"""Verify ISO integrity using checksums.

Supports multiple checksum formats:
  - gpg_checksum  : GPG-inline-signed files (Fedora, CentOS, etc.)
  - sha256sums    : Plain hash + filename files (Ubuntu, Arch, Debian)
  - sha1sums      : Same format, SHA1
  - json          : Signed JSON payloads (Tails latest.json)
"""

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from urllib.request import urlopen

from visync.finder import (
    find_installed_isos,
    get_iso_volume_id,
    identify_distro,
    keyword_hit,
    load_all_metadata,
)
from visync.net import install_safe_opener, require_https
from visync.output import warn

install_safe_opener()


# Sentinel result for run_directory_verify / verify_all_isos when checksums
# could not be obtained (distinct from True=verified, False=mismatch, None=no-config)
UNAVAILABLE = "unavailable"


# ── Version comparison utilities ──────────────────────────────────


def parse_version(version_str: str) -> tuple | None:
    """Parse a version string into a comparable tuple.

    Handles semantic versions (e.g. 24.04.1) and date-based versions (e.g. 2026.06.01).
    Returns a tuple of ints for comparison, or None if parsing fails entirely.
    """
    parts = version_str.split(".")
    try:
        parsed = tuple(int(p) for p in parts if p.isdigit())
        return parsed if parsed else None
    except (ValueError, TypeError):
        return None


def compare_versions(remote: str, local: str) -> int:
    """Compare two version strings. Returns 1 if remote is newer, -1 if local is newer, 0 if equal.

    Falls back to string comparison with a warning if structured parsing fails.
    """
    remote_ver = parse_version(remote)
    local_ver = parse_version(local)

    if remote_ver is not None and local_ver is not None:
        if remote_ver > local_ver:
            return 1
        elif remote_ver < local_ver:
            return -1
        return 0

    # Structured parsing failed — fall back to lexicographic string comparison
    warn(
        f"Could not parse version strings for comparison "
        f"(remote='{remote}', local='{local}'). Falling back to string comparison."
    )
    if remote > local:
        return 1
    elif remote < local:
        return -1
    return 0


_ARCH_TOKEN_RE = re.compile(
    r"x86[_-]?64|amd64|aarch64|arm64|armhfp|i[36]86|riscv64|x86", re.IGNORECASE
)
_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+)*")


def extract_version_from_filename(filename: str) -> str:
    """Extract the version portion from an ISO/IMG filename.

    Prefers the first standalone numeric segment after architecture tokens are
    removed, so 'Fedora-Workstation-Live-x86_64-42-1.1.iso' yields '42'
    (the release) rather than '1.1' (the build). Falls back to the first
    dotted numeric run for names like 'nixos-minimal-26.05.1947.a037-x86_64-linux.iso'.
    Returns the raw version substring or empty string if no numeric version found.
    """
    stem = re.sub(r"\.(iso|img)$", "", filename, flags=re.IGNORECASE)
    stem = _ARCH_TOKEN_RE.sub("-", stem)
    for token in re.split(r"[\s_\-]+", stem):
        if _VERSION_TOKEN_RE.fullmatch(token):
            return token
    match = re.search(r"(\d+(?:\.\d+)+)", stem)
    return match.group(1) if match else ""


HASH_ALGOS = {
    "sha256": hashlib.sha256,
    "sha1": hashlib.sha1,
    "sha512": hashlib.sha512,
    "blake2b": hashlib.blake2b,
}


# ── Hash computation ──────────────────────────────────────────────


def compute_iso_hash(iso_path: Path, algo: str = "sha256") -> str:
    """Compute the hex digest of an ISO file using the given hash algorithm."""
    if algo not in HASH_ALGOS:
        raise ValueError(f"Unsupported hash algorithm: {algo}")
    h = HASH_ALGOS[algo]()
    with open(iso_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ── Network ────────────────────────────────────────────────────────


class ChecksumUnavailable(Exception):
    """Raised when the expected checksum cannot be obtained or evaluated.

    Distinct from a hash mismatch: callers must NOT delete downloads when
    this is raised — verification simply could not be performed.
    """


_UA = {"User-Agent": "Mozilla/5.0"}


def _fetch(url: str) -> str:
    require_https(url, "checksum source")
    req = urllib.request.Request(url, headers=_UA)
    # require_https immediately above is the explicit allowlist S310 asks for.
    with urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


# ── GPG verification ──────────────────────────────────────────────


def _import_key_then_verify(
    signed_path: Path, key_url: str, key_fingerprint: str | list[str] = ""
) -> bool:
    if shutil.which("gpg") is None:
        raise ChecksumUnavailable(
            "gpg binary not found — cannot verify the GPG signature "
            "(install GnuPG, or it is not on PATH)"
        )
    wanted = _normalize_fingerprints(key_fingerprint)
    key_file = Path(tempfile.mkdtemp(prefix="visync-gpg")) / "signing.key"
    try:
        try:
            # The key itself must be fetched over HTTPS. _fetch enforces this
            # for checksum content, but the signing key was going out in
            # cleartext, which defeats the fingerprint pinning it exists to
            # support.
            require_https(key_url, "signing key")
            req = urllib.request.Request(key_url, headers=_UA)
            with urlopen(req, timeout=30) as resp:
                key_file.write_bytes(resp.read())
        except ValueError as e:
            # A config-supplied http:// signing key is a misconfiguration, not
            # an outage, so surface it as a refusal rather than "unreachable".
            raise ChecksumUnavailable(str(e)) from e
        except Exception as e:
            raise ChecksumUnavailable(
                f"signing key unreachable ({key_url}): {e}"
            ) from e

        tmpdir = str(key_file.parent)
        import_proc = subprocess.run(
            ["gpg", "--homedir", tmpdir, "--import", str(key_file)],
            capture_output=True,
        )
        if import_proc.returncode != 0:
            return False

        verify_proc = subprocess.run(
            [
                "gpg",
                "--homedir",
                tmpdir,
                "--status-fd",
                "1",
                "--verify",
                str(signed_path),
            ],
            capture_output=True,
            text=True,
        )
        if verify_proc.returncode != 0:
            return False
        if wanted:
            got = set()
            for line in verify_proc.stdout.splitlines():
                parts = line.split()
                if "VALIDSIG" not in parts:
                    continue
                i = parts.index("VALIDSIG")
                fields = parts[i + 1 :]
                if not fields:
                    continue
                # field 1 = fingerprint of the signing key (may be a subkey);
                # last field = fingerprint of the primary key
                got.add(fields[0].lower())
                got.add(fields[-1].lower())
            if not any(w in got for w in wanted):
                return False
        elif verify_proc.stdout:
            warn(
                "GPG signature trusted without fingerprint pinning "
                "(set signing_key_fingerprint in config)"
            )
        return True
    finally:
        shutil.rmtree(key_file.parent, ignore_errors=True)


def _normalize_fingerprints(value: str | list[str]) -> list[str]:
    """Accept one fingerprint or a list; strip spaces/case."""
    items = value if isinstance(value, list) else [value]
    return [v.replace(" ", "").replace(":", "").lower() for v in items if v]


# ── Checksum-file parsers ─────────────────────────────────────────

# Digest length in hex characters. A SUMS file may legitimately list the same
# file under several algorithms (Parrot's signed-hashes.txt has md5, sha256 and
# sha512 sections), so a parser must select by expected length, not by whichever
# line appears first. Without this, Parrot's md5 line was compared against a
# sha256 digest, the comparison always failed, and download_iso deleted a
# perfectly good 2 GiB download as "corrupt".
_ALGO_HEX_LEN = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}

# Case-insensitive algorithm names as they appear in signed content.
_ALGO_LABEL_RE = {
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
    "sha512": "SHA512",
}


def _hex_len_for(algo: str) -> int | None:
    """Expected hex digest length for *algo*, or None if unrecognised."""
    return _ALGO_HEX_LEN.get(algo.strip().lower().replace("-", ""))


def parse_gpg_checksum(content: str, iso_name: str, algo: str = "sha256") -> str | None:
    """Parse a GPG-inline-signed CHECKSUM file (e.g. Fedora).

    Lines look like:  SHA256 (Fedora-Workstation-...iso) = <hex>
    A Fedora CHECKSUM file can carry both SHA256 and SHA512 lines for the same
    ISO, so the labelled algorithm must match *algo* rather than being
    pattern-matched loosely.
    """
    want = _hex_len_for(algo)
    if want is None:
        return None
    label = _ALGO_LABEL_RE.get(algo.strip().lower().replace("-", ""))
    if label is None:
        return None
    pattern = re.compile(
        r"\b"
        + label
        + r"\s*\(([^)]*"
        + re.escape(iso_name)
        + r"[^)]*)\)\s*=\s*([a-fA-F0-9]+)",
        re.IGNORECASE,
    )
    for line in content.splitlines():
        m = pattern.search(line.strip())
        if m and len(m.group(2)) == want:
            return m.group(2).lower()
    return None


def _sums_filename(field: str) -> str:
    """Normalize a SUMS filename field (strip binary-mode '*' prefix)."""
    name = field.strip()
    name = name.removeprefix("*")
    return name


def parse_hashsums(content: str, iso_name: str, algo: str = "sha256") -> str | None:
    """Parse a standard *SUMS file (hash  filename), selecting the *algo* digest.

    Multi-algorithm files (Parrot) put bare section headers such as ``md5`` and
    ``sha256`` above each block, so a matching line is additionally required to
    fall inside the requested algorithm's section when such headers are present.
    Digest length is the final backstop.
    """
    want = _hex_len_for(algo)
    if want is None:
        return None

    section: str | None = None
    sections_present = False
    fallback: str | None = None

    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        bare = line.strip("*").lower()
        if bare in _ALGO_HEX_LEN:
            section = bare
            sections_present = True
            continue
        if line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or _sums_filename(parts[1]) != iso_name:
            continue
        digest = parts[0].strip().lower()
        if len(digest) != want or not re.fullmatch(r"[a-f0-9]+", digest):
            continue
        if sections_present:
            # Headers delimit real sections; only trust a digest in the
            # requested one.
            if section == algo.strip().lower().replace("-", ""):
                return digest
            continue
        # No section headers: a length match is unambiguous.
        return digest

    return fallback


def parse_tails_json(
    content: str, iso_name: str = "", algo: str = "sha256"
) -> str | None:
    """Parse Tails latest.json containing a sha256 field."""
    try:
        data = json.loads(content)
        digest = data.get("sha256", "")
        if not isinstance(digest, str):
            return None
        digest = digest.lower()
        want = _hex_len_for(algo)
        if want is not None and len(digest) != want:
            return None
        return digest or None
    except (json.JSONDecodeError, AttributeError):
        return None


FORMAT_PARSERS = {
    "gpg_checksum": parse_gpg_checksum,
    "sha256sums": parse_hashsums,
    "sha1sums": parse_hashsums,
    "json": parse_tails_json,
}


# ── Top-level verification ────────────────────────────────────────


def verify_iso(
    iso_path: Path,
    checksum_url: str,
    algo: str = "sha256",
    checksum_format: str = "sha256sums",
    signing_key_url: str | None = None,
    signing_key_fingerprint: str = "",
    precomputed_hash: str = "",
) -> bool:
    """Fetch a checksum, optionally verify its GPG signature, then compare.

    Returns True if the local ISO hash matches the published checksum.
    Returns False ONLY on a genuine mismatch (or bad signature) — the caller
    may safely delete the file. Raises ChecksumUnavailable when the expected
    hash cannot be obtained or evaluated (network failure, 404, ISO absent
    from the sums file, unknown format); callers must keep the file then.
    If *precomputed_hash* is supplied and the requested algo is sha256, it is
    compared directly instead of re-reading the ISO from disk — avoids the
    duplicate full-file hash right after a download.
    """
    iso_name = iso_path.name

    try:
        content = _fetch(checksum_url)
    except Exception as e:
        raise ChecksumUnavailable(f"{checksum_url}: {e}") from e

    # GPG verification of the fetched content. This is deliberately independent
    # of checksum_format: signature authenticity and digest *parsing* are
    # separate concerns. Parrot's signed-hashes.txt is clearsigned but uses a
    # plain `hash  filename` layout with md5/sha256/sha512 sections, so gating
    # the signature check on "gpg_checksum" left it entirely unauthenticated.
    if signing_key_url:
        with tempfile.TemporaryDirectory() as tmpdir:
            signed = Path(tmpdir) / "CHECKSUM.asc"
            signed.write_text(content)
            if not _import_key_then_verify(
                signed, signing_key_url, signing_key_fingerprint
            ):
                return False

    parser = FORMAT_PARSERS.get(checksum_format)
    if not parser:
        raise ChecksumUnavailable(
            f"unknown checksum_format '{checksum_format}' for {iso_name}"
        )

    expected = parser(content, iso_name, algo)
    if not expected:
        raise ChecksumUnavailable(
            f"no {algo} digest for {iso_name} in {checksum_url} — "
            f"cannot determine expected hash"
        )

    if precomputed_hash and algo == "sha256":
        local = precomputed_hash
    else:
        local = compute_iso_hash(iso_path, algo)
    return local == expected


def extract_iso_metadata(iso_name: str) -> dict[str, str]:
    """Pull version/arch/path tokens from common ISO filenames."""
    meta: dict[str, str] = {
        "version": "",
        "arch": "",
        "variant_dir": "",
        "checksum_stem": "",
        # Full YY.MM channel ("26.05") and full release id
        # ("26.05.11045.774debe7a0d1"). NixOS checksum URLs need both, and
        # extract_version_from_filename only recovers "26.05.11045".
        "channel": "",
        "release": "",
    }

    fedora = re.match(
        r"^(?P<prefix>Fedora(?:-[A-Za-z]+)+-Live)"
        r"(?:-(?P<infix>x86_64|aarch64|i686|armhfp))?"
        r"-(?P<major>\d+)-(?P<minor>[\d\.]+)"
        r"(?:\.(?:iso)|\.(?P<ext>x86_64|aarch64|i686|armhfp)\.iso)$",
        iso_name,
        re.IGNORECASE,
    )
    if fedora:
        prefix = fedora.group("prefix")
        infix = fedora.group("infix")
        ext = fedora.group("ext")
        major = fedora.group("major")
        minor = fedora.group("minor")
        arch = infix or ext or "x86_64"
        mid = prefix[len("Fedora") : -len("-Live")].lstrip("-")
        if mid.lower().endswith("-desktop"):
            mid = mid[: -len("-Desktop")]
        meta["version"] = major
        meta["arch"] = arch
        meta["variant_dir"] = mid
        if infix:
            meta["checksum_stem"] = f"{prefix}-{infix}-{major}-{minor}"
        else:
            # dl.fedoraproject.org convention, e.g.
            # Fedora-Workstation-43-1.6-x86_64-CHECKSUM
            meta["checksum_stem"] = f"Fedora-{mid}-{major}-{minor}-{arch}"
        return meta

    ubuntu = re.match(
        r"^ubuntu-(\d+\.\d+(?:\.\d+)?)-live-server-amd64\.iso$", iso_name, re.IGNORECASE
    )
    if ubuntu:
        meta["version"] = ubuntu.group(1)
        return meta

    arch = re.match(r"^archlinux-(\d+\.\d+\.\d+)-x86_64\.iso$", iso_name, re.IGNORECASE)
    if arch:
        meta["version"] = arch.group(1)
        return meta

    nixos = re.match(
        r"^nixos-(?:minimal|graphical)-(\d+\.\d+)\.(\d+)\.([a-f0-9]+)"
        r"(?:-[a-z0-9_]+)*\.iso$",
        iso_name,
        re.IGNORECASE,
    )
    if nixos:
        channel = f"{nixos.group(1)}"
        meta["version"] = channel
        meta["channel"] = channel
        meta["release"] = f"{channel}.{nixos.group(2)}.{nixos.group(3)}"
        return meta

    generic = re.search(r"(\d+\.\d+(?:\.\d+)?)", iso_name)
    if generic:
        meta["version"] = generic.group(1)
    return meta


def expand_url(
    template: str, iso_name: str, base_url: str = "", release_base_url: str = ""
) -> str:
    base = base_url.rstrip("/")
    meta = extract_iso_metadata(iso_name)
    expanded = template.replace("{iso_name}", iso_name)
    expanded = expanded.replace("{base_url}/", base + "/")
    expanded = expanded.replace("{base_url}", base + "/")
    if "{release_base_url}" in template:
        # Explicit, so a checksum can live on a different host than base_url
        # (NixOS publishes ISOs under releases.nixos.org while the channel page
        # is on channels.nixos.org).
        release_base = str(release_base_url or base).rstrip("/")
        expanded = expanded.replace("{release_base_url}/", release_base + "/")
        expanded = expanded.replace("{release_base_url}", release_base + "/")
    expanded = expanded.replace("{version}", meta["version"])
    expanded = expanded.replace("{arch}", meta["arch"])
    expanded = expanded.replace("{variant_dir}", meta["variant_dir"])
    expanded = expanded.replace("{checksum_stem}", meta["checksum_stem"])
    expanded = expanded.replace("{channel}", meta["channel"])
    expanded = expanded.replace("{release}", meta["release"])
    return expanded


def index_distro_configs(config: dict) -> dict[str, dict]:
    """Map clean_name → distro settings from [distros.*] tables."""
    indexed: dict[str, dict] = {}
    for _key, settings in config.get("distros", {}).items():
        name = settings.get("clean_name") or _key
        indexed[name] = settings
    return indexed


def resolve_distro_settings(
    detected_name: str,
    iso_name: str,
    distro_configs: dict[str, dict],
) -> dict:
    """Match detected distro to config by name, then filename keyword."""
    if detected_name in distro_configs:
        return distro_configs[detected_name]
    iso_lower = iso_name.lower()
    for settings in distro_configs.values():
        keyword = settings.get("keyword", "")
        if keyword and keyword_hit(keyword, iso_lower):
            return settings
    return {}


def build_iso_distro_map(iso_dir: Path) -> dict[str, tuple[Path, str]]:
    """Map ISO path string → (path, detected distro name)."""
    distro_map: dict[str, tuple[Path, str]] = {}
    for iso_path in find_installed_isos(iso_dir):
        volume_id = get_iso_volume_id(iso_path)
        distro_name = identify_distro(volume_id, iso_path.name)
        distro_map[str(iso_path)] = (iso_path, distro_name)
    return distro_map


def _cached_hash_for(iso_path: Path, cached: dict[str, dict]) -> str:
    """Return the metadata SHA-256 for an ISO only if the on-disk size matches.

    Lets `visync verify` skip re-reading large ISOs from slow drives while still
    catching files that were replaced or truncated after download. Old metadata
    without a recorded size (or a size mismatch) falls back to hashing the file.
    """
    meta = cached.get(iso_path.name)
    if not meta:
        return ""
    sha = meta.get("sha256", "")
    if not sha:
        return ""
    try:
        if meta.get("size") == iso_path.stat().st_size:
            return sha
    except OSError:
        pass
    return ""


def run_directory_verify(
    iso_dir: Path, config: dict
) -> list[tuple[Path, str, bool | None | str]]:
    """Identify ISOs under *iso_dir* and verify each against config.

    Third element is True (verified), False (mismatch), UNAVAILABLE
    (checksum could not be fetched/parsed), or None (no checksum config).
    """
    distro_map = build_iso_distro_map(iso_dir)
    distro_configs = index_distro_configs(config)
    checksums_config = config.get("checksums", {})
    cached = load_all_metadata(iso_dir)
    results: list[tuple[Path, str, bool | None | str]] = []
    for iso_path, distro_name in distro_map.values():
        settings = resolve_distro_settings(distro_name, iso_path.name, distro_configs)
        try:
            result = verify_from_config(
                iso_path,
                distro_name,
                settings,
                checksums_config,
                precomputed_hash=_cached_hash_for(iso_path, cached),
            )
        except ChecksumUnavailable as e:
            warn(f"{iso_path.name} — {e}")
            result = UNAVAILABLE
        results.append((iso_path, distro_name, result))
    return results


def verify_from_config(
    iso_path: Path,
    distro_name: str,
    distro_config: dict,
    checksums_config: dict,
    precomputed_hash: str = "",
) -> bool | None:
    """Verify a single ISO using its distro's checksum configuration.

    Returns True/False on success, None if no checksum config is available.
    If *precomputed_hash* is provided, skip re-hashing the file.
    """
    if not checksums_config.get("enabled", True):
        return None

    # Fast path: if the scraper already resolved a checksum (e.g. NixOS channel
    # page embeds hashes inline), compare directly without fetching a URL.
    resolved = distro_config.get("resolved_checksum")
    if resolved:
        algo = distro_config.get("checksum_algo", "sha256")
        local = precomputed_hash or compute_iso_hash(iso_path, algo)
        return local == resolved

    checksum_url = distro_config.get("checksum_url")
    if not checksum_url:
        return None

    iso_name = iso_path.name
    base_url = distro_config.get("base_url", "")
    checksum_url = expand_url(
        checksum_url,
        iso_name,
        base_url,
        str(distro_config.get("releases_base_url") or ""),
    )

    algo = distro_config.get("checksum_algo", "sha256")
    fmt = distro_config.get("checksum_format", "sha256sums")
    key_url = distro_config.get("signing_key_url")
    key_fingerprint = distro_config.get("signing_key_fingerprint", "")

    return verify_iso(
        iso_path=iso_path,
        checksum_url=checksum_url,
        algo=algo,
        checksum_format=fmt,
        signing_key_url=key_url,
        signing_key_fingerprint=key_fingerprint,
        precomputed_hash=precomputed_hash,
    )


def verify_all_isos(
    distro_map: dict[str, tuple[Path, str]],
    distro_configs: dict[str, dict],
    checksums_config: dict,
) -> list[tuple[Path, str, bool | None | str]]:
    """Verify all ISOs in a directory against their distro's checksums.

    *distro_map* maps ISO path string → (iso_path, distro_name).
    Returns list of (iso_path, distro_name, result).
    """
    results: list[tuple[Path, str, bool | None | str]] = []
    for iso_path, distro_name in distro_map.values():
        settings = resolve_distro_settings(distro_name, iso_path.name, distro_configs)
        try:
            result = verify_from_config(
                iso_path, distro_name, settings, checksums_config
            )
        except ChecksumUnavailable as e:
            warn(f"{iso_path.name} — {e}")
            result = UNAVAILABLE
        results.append((iso_path, distro_name, result))
    return results
