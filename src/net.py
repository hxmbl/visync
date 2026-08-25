"""Network safety helpers shared by scraping, downloading, and verification."""

import urllib.error
import urllib.request
from urllib.parse import urlparse

_opener_installed = False


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    host = host.lower().strip("[]")
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """HTTPRedirectHandler that refuses to follow https -> cleartext redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(req.full_url).scheme == "https" and urlparse(newurl).scheme != "https":
            raise urllib.error.URLError(
                f"blocked insecure redirect downgrade: {req.full_url} -> {newurl}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def install_safe_opener() -> None:
    """Install the downgrade-safe opener once for the whole process."""
    global _opener_installed
    if _opener_installed:
        return
    urllib.request.install_opener(
        urllib.request.build_opener(SafeRedirectHandler())
    )
    _opener_installed = True


def require_https(url: str, what: str = "URL") -> None:
    """Reject non-HTTPS fetch targets (loopback exempt for local testing)."""
    parsed = urlparse(url)
    if parsed.scheme != "https" and not _is_loopback(parsed.hostname):
        raise ValueError(
            f"refusing {what} over non-HTTPS: {url}"
        )
