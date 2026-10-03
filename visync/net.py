"""Network safety helpers shared by scraping, downloading, and verification."""

import ipaddress
import urllib.error
import urllib.request
from urllib.parse import urlparse

_opener_installed = False

# Names that unambiguously denote the local machine. Anything outside this set
# must parse as an IP literal to earn the loopback exemption, which keeps
# ambiguous spellings such as "127.1", the decimal form "2130706433", or a
# lookalike host from slipping past as if they were loopback.
_LOOPBACK_NAMES = frozenset({"localhost"})


def _is_loopback(host: str | None) -> bool:
    """True only for unambiguous loopback hosts.

    Accepts the exact name "localhost", any "*.localhost" subdomain (RFC 6761
    reserves the whole domain for loopback), and IPv4/IPv6 literals that
    ipaddress classifies as loopback. Non-canonical and integer spellings of
    127.0.0.1 are deliberately *not* treated as loopback: urllib would connect
    to the local machine for them, so allowing them would hand out a cleartext
    exemption for an address that merely looks local.

    IPv4-mapped IPv6 (``::ffff:127.0.0.1``) is also excluded. It resolves to
    loopback, but it is a distinct spelling that no legitimate local mirror
    uses, so rejecting it costs nothing and removes an obfuscation avenue.
    """
    if not host:
        return False
    host = host.strip().strip("[]").lower()
    if not host or host.endswith("."):
        # A trailing dot is the fully-qualified form of the same name, but only
        # for names; it is not valid on an IP literal and is not worth a
        # second code path here.
        host = host.rstrip(".")
    if not host:
        return False
    if host in _LOOPBACK_NAMES or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return False
    return address.is_loopback


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """HTTPRedirectHandler that refuses to follow https -> cleartext redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if (
            urlparse(req.full_url).scheme == "https"
            and urlparse(newurl).scheme != "https"
        ):
            raise urllib.error.URLError(
                f"blocked insecure redirect downgrade: {req.full_url} -> {newurl}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def install_safe_opener() -> None:
    """Install the downgrade-safe opener once for the whole process."""
    global _opener_installed
    if _opener_installed:
        return
    urllib.request.install_opener(urllib.request.build_opener(SafeRedirectHandler()))
    _opener_installed = True


def require_https(url: str, what: str = "URL") -> None:
    """Reject non-HTTPS fetch targets (unambiguous loopback exempt for testing).

    The exemption exists so a local mirror or test server can be used during
    development. It is deliberately narrow: only "localhost", "*.localhost" and
    canonical loopback IP literals qualify.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" and not _is_loopback(parsed.hostname):
        raise ValueError(f"refusing {what} over non-HTTPS: {url}")
