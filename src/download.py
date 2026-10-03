"""Scrape and synchronize distributions configured in config.toml."""

import concurrent.futures
import hashlib
import os
import re
import shutil
import socket
import sys
import time
import urllib.error
import urllib.request
from enum import StrEnum
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlparse

from rich.markup import escape as _esc

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.finder import (
    find_installed_isos,
    find_ventoy_drives,
    get_iso_volume_id,
    identify_distro,
    load_config,
    remove_iso_metadata,
    visync_watchdog,
    write_iso_metadata,
)
from src.net import install_safe_opener, require_https

install_safe_opener()
from src.output import (
    console,
    error,
    header,
    info,
    make_download_progress,
    removed,
    spin_start,
    spin_stop,
    spin_update,
    success,
    warn,
)
from src.verify import compare_versions, extract_version_from_filename, parse_version

DEBUG = os.environ.get("VISYNC_DEBUG", "0") == "1"


def _debug(msg: str) -> None:
    """Print a debug message when VISYNC_DEBUG=1."""
    if DEBUG:
        print(f"  [debug] {msg}", file=sys.stderr)


MIRROR_CONNECT_TIMEOUT = 5
MIRROR_HTTP_TIMEOUT = 10
SCRAPE_DEADLINE = 120
DEFAULT_STAGING_DIR = Path.home() / ".cache" / "visync" / "staging"


class SyncStatus(StrEnum):
    """Outcome of checking one distro against its upstream mirror.

    UNREACHABLE is deliberately distinct from CURRENT: "the mirror is down or
    its page shape changed" must never be reported as "nothing to do", or a
    broken scraper silently stops updating forever.
    """

    CURRENT = "current"
    STALE = "stale"
    UNREACHABLE = "unreachable"


class DistroCheck(NamedTuple):
    """Result of scraping and version-comparing one configured distro."""

    entry_id: str
    clean_name: str
    latest_filename: str
    status: SyncStatus
    download_url: str | None
    reason: str = ""


def _unreachable(entry_id: str, clean_name: str, reason: str) -> DistroCheck:
    """Build an UNREACHABLE result carrying an actionable reason."""
    return DistroCheck(
        entry_id,
        clean_name,
        "",
        SyncStatus.UNREACHABLE,
        None,
        reason.strip() or "could not resolve an ISO from the mirror",
    )


def ping_mirror(url: str) -> bool:
    """Pre-flight TCP connectivity check. Returns True if host is reachable."""
    _debug(f"Pinging {url}")
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=MIRROR_CONNECT_TIMEOUT):
            _debug(f"Ping OK: {host}:{port}")
            return True
    except (TimeoutError, OSError) as e:
        _debug(f"Ping failed: {e}")
        return False


def fetch_html(url: str) -> str:
    """Download HTML source from a mirror index page."""
    require_https(url, "mirror index")
    _debug(f"Fetching {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=MIRROR_HTTP_TIMEOUT) as response:
            html = response.read().decode("utf-8", errors="ignore")
            # Detect bot-protected pages (e.g. Anubis proof-of-work)
            if "Anubis" in html[:1000]:
                warn(
                    "Mirror protected by bot challenge (Anubis). Cannot scrape automatically."
                )
                warn("Visit the URL in a browser, complete the challenge, then re-run.")
                return ""
            return html
    except urllib.error.URLError as e:
        err_str = str(e).lower()
        if "ssl" in err_str or "certificate" in err_str or "cert" in err_str:
            error(f"SSL certificate verification failed for {url}")
            info(f"Details: {e}")
            return ""
        error(f"Network error: {url}: {e}")
        return ""
    except Exception as e:
        error(f"Network error: {url}: {e}")
        return ""


def _safe_filename(name: str) -> str:
    """Normalize an API-provided filename to a bare, traversal-safe segment."""
    name = name.split("?", 1)[0].split("#", 1)[0]
    name = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if name in ("", ".", ".."):
        return ""
    return name


NIXOS_RELEASES_S3 = "https://nix-releases.s3.amazonaws.com/"
# nixos/<YY.MM>/ are numbered stable releases. Suffixes mark non-stable or
# non-default trees: -small is the minimal installer, -aarch64 the ARM build.
# "unstable" is not a YY.MM channel and is deliberately excluded by this pattern.
_NIXOS_CHANNEL_RE = re.compile(r"nixos/(\d{2}\.\d{2})/")

# Plausibility ceiling for a NixOS channel year. NixOS releases twice a year and
# 26.05 was newest when this was written, so anything past year 49 is a parsing
# artefact or a hostile listing rather than a real channel. Guards against
# pointing a download at an attacker-chosen path.
_NIXOS_CHANNEL_MAX_YEAR = 49


def _nixos_stable_channel(settings: dict) -> tuple[str, str]:
    """Resolve the current stable NixOS release, e.g. ``("26.05", "26.05")``.

    NixOS publishes no ``nixos-stable`` alias (404), so the current stable is
    derived from the release bucket: the highest ``nixos/<YY.MM>/`` prefix,
    excluding ``-small`` and ``-aarch64`` trees. An in-progress next release has
    no YY.MM channel directory yet, so the newest one is always the current
    stable — this tracks 26.11, 27.05 and later without a config edit.

    Returns ``(channel, reason)``; *reason* is non-empty on failure.
    """
    listing_url = str(settings.get("releases_index_url") or NIXOS_RELEASES_S3)
    prefix = str(settings.get("releases_index_prefix") or "nixos/")
    if not prefix.endswith("/"):
        prefix += "/"

    listing = fetch_html(f"{listing_url}?delimiter=/&prefix={prefix}")
    if not listing:
        return "", f"could not fetch NixOS release listing {listing_url}"

    channels = {m.group(1) for m in _NIXOS_CHANNEL_RE.finditer(listing)}
    if not channels:
        return "", f"no nixos/<YY.MM>/ channels found in the {listing_url} listing"

    def _key(channel: str) -> tuple[int, int]:
        major, _, minor = channel.partition(".")
        return int(major), int(minor)

    newest = max(channels, key=_key)
    if _key(newest)[0] > _NIXOS_CHANNEL_MAX_YEAR:
        return "", (
            f"NixOS listing contains an implausible channel ({newest}); "
            "refusing to guess"
        )

    # Prefer an explicit channel pin when it is still a real channel, so a
    # deliberate config choice is respected until upstream supersedes it.
    pinned = str(settings.get("channel") or "")
    if pinned and pinned in channels:
        return pinned, ""

    return max(channels, key=_key), ""


def process_scraping_strategy(name: str, settings: dict) -> tuple[str, str]:
    """Resolve specific folder parsing pipelines based on the configured strategy.

    On failure returns ``("", "")`` and records an actionable, one-line reason in
    ``settings["resolve_error"]``. Callers surface that reason to the user instead
    of a generic "unable to reach mirror", so an upstream page-shape change is
    distinguishable from a transient network fault.
    """
    strategy = settings.get("strategy")
    base_url = str(settings.get("base_url") or "")
    iso_regex = str(settings.get("iso_regex") or "")
    version_regex = str(settings.get("version_regex") or "")
    settings["resolve_error"] = ""

    def fail(reason: str) -> tuple[str, str]:
        settings["resolve_error"] = reason
        return "", ""

    # Pre-flight connectivity check — skip dead mirrors instantly
    if base_url and not ping_mirror(base_url):
        warn(f"Mirror unreachable (ping failed): {base_url}")
        return fail(f"no route to mirror {base_url}")

    # Strategy A: Direct Index File Tracking (e.g. Arch Linux)
    if strategy == "direct_match":
        if not base_url or not iso_regex:
            warn(f"{name} — direct_match requires base_url and iso_regex")
            return fail("config incomplete: needs base_url + iso_regex")
        html = fetch_html(base_url)
        if not html:
            return fail(f"could not fetch index page {base_url}")
        match = re.search(iso_regex, html)
        if match:
            filename = _safe_filename(match.group(1))
            if not filename:
                return fail(f"index page {base_url} matched an unsafe filename")
            return filename, f"{base_url.rstrip('/')}/{filename}"
        return fail(f"iso_regex matched nothing on {base_url}")

    # Strategy B: Two-Tier Version Directory Traversal for Fedora
    elif strategy == "fedora_nested":
        if not base_url or not iso_regex or not version_regex:
            warn(f"{name} — fedora_nested requires base_url, iso_regex, version_regex")
            return fail("config incomplete: needs base_url + iso_regex + version_regex")
        root_html = fetch_html(base_url)
        if not root_html:
            return fail(f"could not fetch releases index {base_url}")
        versions = [
            v.strip().rstrip("/")
            for v in re.findall(version_regex, root_html)
            if v.strip().rstrip("/")
        ]
        if not versions:
            return fail(f"no version directories matched at {base_url}")

        versions.sort(key=lambda x: parse_version(x) or ())
        latest_version = versions[-1].rstrip("/")

        variant_path = str(settings.get("variant_path") or "Workstation/x86_64/iso")
        iso_dir_url = f"{base_url}{latest_version}/{variant_path}/"
        iso_html = fetch_html(iso_dir_url)
        if not iso_html:
            return fail(f"could not fetch ISO directory {iso_dir_url}")

        match = re.search(iso_regex, iso_html)
        if match:
            return match.group(1), f"{iso_dir_url}{match.group(1)}"
        return fail(f"iso_regex matched nothing in {iso_dir_url}")

    # Strategy C: Directory Sub-paths for Ubuntu Ecosystem Releases
    elif strategy == "ubuntu_nested":
        if not base_url or not iso_regex or not version_regex:
            warn(f"{name} — ubuntu_nested requires base_url, iso_regex, version_regex")
            return fail("config incomplete: needs base_url + iso_regex + version_regex")
        root_html = fetch_html(base_url)
        if not root_html:
            return fail(f"could not fetch releases index {base_url}")
        versions = [
            v.strip().rstrip("/")
            for v in re.findall(version_regex, root_html)
            if v.strip().rstrip("/")
        ]
        if not versions:
            return fail(f"no version directories matched at {base_url}")

        # Optional release-family filter, applied before sorting so we pick the
        # newest *matching* release rather than the newest overall.
        filter_regex = str(settings.get("version_filter") or "")
        if filter_regex:
            versions = [v for v in versions if re.fullmatch(filter_regex, v)]
            if not versions:
                return fail(
                    f"no version directories matched version_filter "
                    f"{filter_regex!r} at {base_url}"
                )

        versions.sort(key=lambda x: parse_version(x) or ())
        latest_version = versions[-1].rstrip("/")

        iso_dir_url = f"{base_url}{latest_version}/"
        iso_html = fetch_html(iso_dir_url)
        if not iso_html:
            return fail(f"could not fetch release directory {iso_dir_url}")

        match = re.search(iso_regex, iso_html)
        if match:
            return match.group(1), f"{iso_dir_url}{match.group(1)}"
        return fail(f"iso_regex matched nothing in {iso_dir_url} (upstream layout?)")

    # Strategy D: NixOS channel page — parse version, construct ISO URL
    elif strategy == "nixos_channel":
        # NixOS publishes no nixos-stable alias, so derive the current stable
        # channel from the release bucket before touching the channel page.
        channel, channel_err = _nixos_stable_channel(settings)
        if channel_err:
            return fail(channel_err)
        channel_url = f"{base_url.rstrip('/')}-{channel}" if base_url else ""
        if not channel_url:
            return fail("config incomplete: needs base_url")
        html = fetch_html(channel_url)
        if not html:
            return fail(f"could not fetch channel page {channel_url}")

        # The channel page contains text like "nixos-26.05 release nixos-26.05.1947.a0374025a863"
        version_match = re.search(
            r"nixos-[\d\.]+\s+release\s+(nixos-[\d\.]+\.[a-f0-9]+)", html
        )
        if not version_match:
            warn(f"{name} — could not parse NixOS version from channel page")
            return fail(f"could not parse release id from channel page {channel_url}")

        full_version = version_match.group(1)  # e.g. "nixos-26.05.1947.a0374025a863"
        # Strip the "nixos-" prefix for constructing URLs
        version_id = full_version.replace(
            "nixos-", "", 1
        )  # e.g. "26.05.1947.a0374025a863"
        # Extract the short version (e.g. "26.05") from the full version
        short_version_match = re.search(r"nixos-([\d]+\.[\d]+)", full_version)
        if not short_version_match:
            return fail(f"could not parse short version from {full_version!r}")
        short_version = short_version_match.group(1)  # e.g. "26.05"
        if short_version != channel:
            return fail(
                f"channel {channel} resolved to release {short_version} — "
                "mismatch, refusing to guess"
            )

        variant = settings.get("variant", "minimal")  # "minimal" or "graphical"
        iso_filename = f"nixos-{variant}-{version_id}-x86_64-linux.iso"
        releases_base = str(
            settings.get("releases_base_url") or "https://releases.nixos.org"
        )
        iso_url = f"{releases_base.rstrip('/')}/nixos/{short_version}/{full_version}/{iso_filename}"

        # Parse SHA-256 checksum from the channel page HTML table.
        # The page has rows: <td><a href='...'>FILENAME</a></td><td>SIZE</td><td><tt>HASH</tt></td>
        checksum_match = re.search(
            r"href=['\"][^'\"]*"
            + re.escape(iso_filename)
            + r"['\"]>"
            + re.escape(iso_filename)
            + r"</a></td><td[^>]*>\d+</td><td><tt>([a-f0-9]{64})</tt>",
            html,
        )
        if checksum_match:
            settings["resolved_checksum"] = checksum_match.group(1)

        # Verify the URL is reachable
        try:
            require_https(iso_url, "ISO download")
            req = urllib.request.Request(
                iso_url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=MIRROR_HTTP_TIMEOUT) as resp:
                if resp.status == 200:
                    return iso_filename, iso_url
            return fail(f"HEAD probe returned HTTP {resp.status} for {iso_url}")
        except ValueError as e:
            return fail(str(e))
        except Exception as e:
            return fail(f"HEAD probe failed for {iso_url}: {e}")

    # Strategy E: Pop!_OS JSON API — fetch latest build info
    elif strategy == "popos_api":
        import json as _json

        api_url = settings.get("api_url", "https://api.pop-os.org/builds")
        variant = settings.get("variant", "generic")
        release = settings.get("release", "24.04")

        url = f"{api_url}/{release}/{variant}"
        html = fetch_html(url)
        if not html:
            return fail(f"could not fetch {url}")

        try:
            data = _json.loads(html)
        except _json.JSONDecodeError:
            warn(f"{name} — could not parse Pop!_OS API response")
            return fail(f"{url} did not return JSON")

        iso_url = data.get("url", "") if isinstance(data, dict) else ""
        if not iso_url:
            return fail(f"{url} returned no ISO url")
        iso_filename = _safe_filename(iso_url.rsplit("/", 1)[-1])
        if not iso_filename:
            warn(f"{name} — API returned unsafe filename")
            return fail(f"{url} returned an unusable filename")
        # Pop!_OS publishes the digest as "sha_sum"; older docs said "sha256".
        checksum = ""
        if isinstance(data, dict):
            for key in ("sha256", "sha_sum"):
                value = data.get(key, "")
                if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value):
                    checksum = value.lower()
                    break
        if checksum:
            settings["resolved_checksum"] = checksum
        return iso_filename, iso_url

    # Strategy F: Tails JSON API — fetch latest version from releases.json
    elif strategy == "tails_api":
        import json as _json

        api_url = settings.get(
            "api_url", "https://tails.net/install/v2/Tails/amd64/stable/latest.json"
        )
        file_type = settings.get("file_type", "img")  # "iso" or "img"

        html = fetch_html(api_url)
        if not html:
            return fail(f"could not fetch {api_url}")

        try:
            data = _json.loads(html)
            installations = data.get("installations", [])
        except (_json.JSONDecodeError, AttributeError):
            warn(f"{name} — could not parse Tails API response")
            return fail(f"{api_url} did not return the expected JSON")
        if not installations:
            return fail(f"{api_url} listed no installations")

        latest = installations[0]
        for installation in installations:
            if installation.get("version", "") > latest.get("version", ""):
                latest = installation

        for path in latest.get("installation-paths", []):
            if path.get("type") != file_type:
                continue
            for target in path.get("target-files", []):
                url = target.get("url", "")
                if not url:
                    continue
                iso_filename = _safe_filename(url.rsplit("/", 1)[-1])
                if not iso_filename:
                    warn(f"{name} — API returned unsafe filename")
                    return fail(f"{api_url} returned an unusable filename")
                checksum = target.get("sha256", "")
                if isinstance(checksum, str) and re.fullmatch(
                    r"[a-fA-F0-9]{64}", checksum
                ):
                    settings["resolved_checksum"] = checksum.lower()
                return iso_filename, url
        return fail(f"{api_url} has no {file_type} artifact for the latest release")

    return fail(f"unknown or unhandled strategy {strategy!r}")


MIN_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB minimum per chunk
MAX_DOWNLOAD_THREADS = 16


def _download_threads() -> int:
    """Thread count from VISYNC_DOWNLOAD_THREADS; invalid values fall back to 4."""
    raw = os.environ.get("VISYNC_DOWNLOAD_THREADS", "4")
    try:
        n = int(raw)
    except ValueError:
        _debug(f"Invalid VISYNC_DOWNLOAD_THREADS={raw!r}, using 4")
        return 4
    return max(1, min(n, MAX_DOWNLOAD_THREADS))


def _download_chunked(
    url: str,
    part_path: Path,
    total: int,
    num_threads: int,
    filename: str,
) -> bool:
    """Download a file using HTTP Range requests in parallel threads.

    Writes directly to part_path at the correct offsets, using os.pwrite where
    available and per-thread lseek/write on platforms that lack it (Windows).
    Returns True on success, False on failure.
    """
    import threading

    require_https(url, "ISO download")

    pwrite_available = callable(getattr(os, "pwrite", None))

    chunk_size = max(MIN_CHUNK_SIZE, total // num_threads)
    # Build (start, end) ranges
    ranges: list[tuple[int, int]] = []
    start = 0
    while start < total:
        end = min(start + chunk_size - 1, total - 1)
        ranges.append((start, end))
        start = end + 1

    actual_threads = len(ranges)
    _debug(
        f"Chunked download: {total} bytes in {actual_threads} chunks of ~{chunk_size} bytes"
    )

    # Pre-allocate the file. O_BINARY is required on Windows — without it the
    # CRT opens in text mode and os.write() inflates every 0x0A into 0x0D 0x0A,
    # silently corrupting ISO bytes. It is a no-op constant on POSIX.
    _BINARY = getattr(os, "O_BINARY", 0)
    fd = os.open(str(part_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _BINARY)
    try:
        os.ftruncate(fd, total)
    except OSError:
        os.close(fd)
        return False

    downloaded = [0] * actual_threads
    lock = threading.Lock()
    errors: list[str] = []

    def _download_chunk(idx: int, chunk_start: int, chunk_end: int) -> None:
        nonlocal downloaded
        range_header = f"bytes={chunk_start}-{chunk_end}"
        thread_fd = None
        if not pwrite_available:
            thread_fd = os.open(str(part_path), os.O_WRONLY | _BINARY)
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0", "Range": range_header},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                status = getattr(resp, "status", 206)
                if status != 206:
                    with lock:
                        errors.append(
                            f"Chunk {idx}: server ignored Range request "
                            f"(HTTP {status}, expected 206)"
                        )
                    return
                offset = chunk_start
                while True:
                    try:
                        data = resp.read(128000)
                    except TimeoutError:
                        with lock:
                            errors.append(f"Chunk {idx} stalled")
                        return
                    if not data:
                        break
                    room = chunk_end - offset + 1
                    if len(data) > room:
                        with lock:
                            errors.append(
                                f"Chunk {idx}: response exceeds requested range "
                                f"by {len(data) - room} bytes"
                            )
                        return
                    if pwrite_available:
                        written = os.pwrite(fd, data, offset)
                    else:
                        assert thread_fd is not None
                        os.lseek(thread_fd, offset, os.SEEK_SET)
                        written = os.write(thread_fd, data)
                    offset += written
                    with lock:
                        downloaded[idx] = offset - chunk_start
                    if written < len(data):
                        with lock:
                            errors.append(
                                f"Chunk {idx}: short write ({written} of {len(data)})"
                            )
                        return
        except Exception as e:
            with lock:
                errors.append(f"Chunk {idx}: {e}")
        finally:
            if thread_fd is not None:
                os.close(thread_fd)

    try:
        with make_download_progress() as progress:
            task = progress.add_task(
                "download", filename=_esc(filename), total=total or None
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=actual_threads
            ) as pool:
                futures = [
                    pool.submit(_download_chunk, i, s, e)
                    for i, (s, e) in enumerate(ranges)
                ]
                while not all(f.done() for f in futures):
                    time.sleep(0.25)
                    with lock:
                        total_done = sum(downloaded)
                    progress.update(task, completed=total_done)
                concurrent.futures.wait(futures)

        expected_sizes = [e - s + 1 for s, e in ranges]
        with lock:
            short = [
                f"Chunk {i}: got {downloaded[i]} of {expected_sizes[i]} bytes"
                for i in range(actual_threads)
                if downloaded[i] != expected_sizes[i]
            ]
        if short:
            errors.extend(short)

        if errors:
            error(f"Chunked download failed: {'; '.join(errors[:3])}")
            return False

        return True
    finally:
        os.close(fd)


def _download_single_stream(
    url: str,
    part_path: Path,
    total: int,
    filename: str,
) -> bool:
    """Download a file in a single stream with progress reporting."""
    require_https(url, "ISO download")
    CHUNK_SIZE = 128000
    READ_TIMEOUT = 30

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            downloaded = 0
            with make_download_progress() as progress:
                task = progress.add_task(
                    "download",
                    filename=_esc(filename),
                    total=total or None,
                )
                with open(part_path, "wb", buffering=1048576) as f:
                    while True:
                        try:
                            chunk = resp.read(CHUNK_SIZE)
                        except TimeoutError:
                            error(f"Download stalled — no data for {READ_TIMEOUT}s")
                            part_path.unlink(missing_ok=True)
                            return False
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        progress.update(task, completed=downloaded)
    except OSError as e:
        error(f"Write/disk error during download: {e}")
        part_path.unlink(missing_ok=True)
        return False
    except Exception as e:
        error(f"Network error during download: {e}")
        part_path.unlink(missing_ok=True)
        return False

    return True


def download_iso(
    url: str,
    dest_path: Path,
    drive_root: Path | None = None,
    distro_config: dict | None = None,
    checksums_config: dict | None = None,
    no_verify: bool = False,
) -> bool:
    """Download an ISO file with streaming progress and optional metadata persistence.

    Returns True on success, False on failure.
    """
    _debug(f"Starting download: {url} -> {dest_path}")
    if drive_root and dest_path.parent != drive_root:
        console.print(
            f"  [cyan]↓[/cyan] Downloading to staging: [bold]{_esc(dest_path.name)}[/bold]"
        )
    else:
        console.print(
            f"  [cyan]↓[/cyan] Downloading: [bold]{_esc(dest_path.name)}[/bold]"
        )

    require_https(url, "ISO download")

    # HEAD request: get size, check range support
    expected = 0
    ranges_supported = False
    try:
        req = urllib.request.Request(
            url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            expected = int(resp.headers.get("Content-Length", 0))
            accept_ranges = resp.headers.get("Accept-Ranges", "")
            ranges_supported = accept_ranges == "bytes"
    except Exception:
        pass

    # Disk space check
    try:
        usage = shutil.disk_usage(dest_path.parent)
        available = usage.free
        if expected > 0:
            needed = int(expected * 1.05)
            info(
                f"Expected: {expected / (1024**3):.2f} GiB | Available: {available / (1024**3):.2f} GiB"
            )
            if available < needed:
                error(
                    f"Insufficient disk space — need {needed / (1024**3):.2f} GiB, "
                    f"have {available / (1024**3):.2f} GiB"
                )
                return False
        else:
            info(f"Available disk space: {available / (1024**3):.2f} GiB")
            warn("Content-Length unknown — disk space cannot be verified.")
    except Exception:
        pass

    part_path = dest_path.with_suffix(dest_path.suffix + ".part")

    # Choose chunked or single-stream
    _threads = _download_threads()
    if ranges_supported and expected > MIN_CHUNK_SIZE * _threads:
        _debug(f"Using chunked download ({_threads} threads)")
        ok = _download_chunked(url, part_path, expected, _threads, dest_path.name)
        if not ok:
            part_path.unlink(missing_ok=True)
            return False
    else:
        if not ranges_supported:
            _debug("Server does not support Range requests — using single stream")
        else:
            _debug("File too small for chunked download — using single stream")
        ok = _download_single_stream(url, part_path, expected, dest_path.name)
        if not ok:
            return False

    # Verify file is not empty or obviously truncated
    if part_path.stat().st_size == 0:
        error(f"Download produced empty file: {dest_path.name}")
        part_path.unlink(missing_ok=True)
        return False

    if expected > 0 and part_path.stat().st_size < expected:
        error(
            f"Download truncated — got {part_path.stat().st_size / (1024**3):.2f} GiB "
            f"of expected {expected / (1024**3):.2f} GiB"
        )
        part_path.unlink(missing_ok=True)
        return False

    part_path.replace(dest_path)
    if drive_root and dest_path.parent != drive_root:
        success(f"Downloaded to staging: {dest_path.name}")
    else:
        success(f"Downloaded: {dest_path.name}")

    # Compute SHA-256 once — used for both verification and metadata
    sha256_hex = ""
    spin_start(f"Hashing {dest_path.name}...")
    try:
        try:
            h = hashlib.sha256()
            with open(dest_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            sha256_hex = h.hexdigest()
        except OSError:
            pass

        # Auto-verify checksum if config is available
        if not no_verify and distro_config and checksums_config is not None:
            from src.verify import ChecksumUnavailable, verify_from_config

            spin_update(f"Verifying checksum for {dest_path.name}...")
            try:
                result = verify_from_config(
                    dest_path,
                    "",
                    distro_config,
                    checksums_config,
                    precomputed_hash=sha256_hex,
                )
            except ChecksumUnavailable as e:
                warn(f"Could not verify {dest_path.name} — {e}")
                warn("Keeping downloaded file UNVERIFIED.")
                result = None
            if result is False:
                error(f"Checksum verification failed for {dest_path.name} — deleting")
                dest_path.unlink(missing_ok=True)
                return False
            elif result is True:
                success(f"Checksum verified: {dest_path.name}")
            else:
                warn(f"No checksum config for {dest_path.name} — installed UNVERIFIED")
    finally:
        spin_stop()

    _cleanup_old_versions(dest_path, drive_root)

    if drive_root and sha256_hex:
        volume_id = get_iso_volume_id(dest_path)
        version = ""
        if volume_id:
            version = extract_version_from_filename(dest_path.name)
        variant_stem = _variant_stem(volume_id) if volume_id else ""
        try:
            iso_size = dest_path.stat().st_size
        except OSError:
            iso_size = 0
        write_iso_metadata(
            drive_root=drive_root,
            filename=dest_path.name,
            variant_stem=variant_stem,
            version=version,
            sha256=sha256_hex,
            size=iso_size,
        )
        _debug(f"Metadata written for {dest_path.name}")

    return True


def _cleanup_old_versions(new_iso: Path, drive_root: Path | None = None) -> None:
    """Scan the target directory and delete older ISOs of the same distribution variant.

    Uses volume ID for the new file only, then uses filename-based matching
    to find candidates. Only reads volume IDs for filename-matched candidates
    to confirm they are the same distro+variant before deletion.
    """
    _debug(f"Cleanup check for {new_iso.name}")
    try:
        new_vid = get_iso_volume_id(new_iso)
        if new_vid:
            new_distro = identify_distro(new_vid, new_iso.name)
            new_stem = _variant_stem(new_vid)
        else:
            new_distro = identify_distro("", new_iso.name)
            new_stem = _filename_variant_key(new_iso.name)

        if new_distro in ("Unknown OS", ""):
            return

        target_dir = new_iso.parent

        for iso_path in find_installed_isos(target_dir):
            if iso_path == new_iso:
                continue

            try:
                # Cheap pre-filter on the filename key, so we only pay for a
                # volume-ID read on plausible candidates.
                if not same_variant_prefix(
                    new_stem, _filename_variant_key(iso_path.name)
                ):
                    continue

                # Confirm match by reading volume ID only for candidates
                old_vid = get_iso_volume_id(iso_path)
                if old_vid:
                    old_distro = identify_distro(old_vid, iso_path.name)
                    old_stem = _variant_stem(old_vid)
                else:
                    old_distro = identify_distro("", iso_path.name)
                    old_stem = _filename_variant_key(iso_path.name)

                if old_distro == new_distro and old_stem == new_stem:
                    removed(f"Removing deprecated image: {iso_path.name}")
                    iso_path.unlink(missing_ok=True)
                    if drive_root:
                        remove_iso_metadata(drive_root, iso_path.name)
            except OSError:
                warn(f"Could not remove stale file: {iso_path.name}")
            except Exception:
                pass
    except Exception:
        pass


def _sweep_old_versions(drive_root: Path, clean: bool = False) -> None:
    """Scan all ISOs on the drive and remove older versions of the same distro+variant.

    Groups ISOs by (distro, variant_stem), sorts each group by version, and
    removes all but the newest in each group.
    With clean=False (default), only reports what would be deleted.
    """
    from collections import defaultdict

    _debug("Running sweep for stale ISOs")
    all_isos = find_installed_isos(drive_root)
    groups: dict[tuple[str, str], list[tuple[str, Path]]] = defaultdict(list)

    for iso_path in all_isos:
        vid = get_iso_volume_id(iso_path)
        if vid:
            distro = identify_distro(vid, iso_path.name)
            stem = _variant_stem(vid)
        else:
            distro = identify_distro("", iso_path.name)
            stem = _filename_variant_key(iso_path.name)
        version = extract_version_from_filename(iso_path.name) or "0"
        if distro and distro != "Unknown OS":
            groups[(distro, stem)].append((version, iso_path))

    for (distro, _stem), versions in groups.items():
        if len(versions) <= 1:
            continue
        versions.sort(key=lambda x: parse_version(x[0]) or ())
        _newest_version, _newest_path = versions[-1]
        for version, iso_path in versions[:-1]:
            if clean:
                try:
                    removed(f"Removing old {distro} {version}: {iso_path.name}")
                    iso_path.unlink(missing_ok=True)
                    remove_iso_metadata(drive_root, iso_path.name)
                except OSError as e:
                    warn(f"Could not remove {iso_path.name}: {e}")
            else:
                info(f"Would remove old {distro} {version}: {iso_path.name}")


# Tokens that identify the architecture rather than the distro variant. They are
# dropped from variant keys so a rebuild for a different arch is treated as the
# same variant. Mirrors _ARCH_TOKEN_RE in verify.py.
#
# The arch name is bracketed by separator classes rather than \b because
# filenames glue it to underscores ("pop-os_24.04_amd64_generic_24.iso"), where a
# trailing underscore counts as a word character and \bamd64\b would not match.
_ARCH_IN_KEY_RE = re.compile(
    r"(?:(?<=^)|(?<=[\s_\-.]))(?:x86[_-]?64|amd64|aarch64|arm64|armhfp"
    r"|i[36]86|riscv64|x86)(?=[\s_\-.]|$)",
    re.IGNORECASE,
)
# Version tokens: pure numbers, optionally dotted, tolerating a trailing
# separator left behind by a stripped arch token ("live-1.7.").
_VERSION_IN_KEY_RE = re.compile(r"^\d+(?:\.\d+)*\.?$")
# Release-type words that appear in volume IDs but never distinguish a variant.
_RELEASE_WORD_RE = re.compile(
    r"^(?:lts|esd|point|pre|rc|beta|alpha|rc\d*)$", re.IGNORECASE
)


def variant_key(text: str) -> str:
    """Derive a stable distro-variant identity from arbitrary identifying text.

    Accepts either an ISO filename or an ISO 9660 volume ID and reduces both to
    the same distro+variant key, so two versions of one variant match while
    distinct variants (desktop vs server, KDE vs Workstation) never do.

    Architecture tokens, version tokens, and release-type words are removed, and
    all separator styles collapse to single hyphens. Unifying the two former
    implementations mattered because they disagreed: the volume-ID path kept
    ``amd64`` (its "protect the underscore" step is a no-op for every arch
    except x86_64) while the filename path stripped it, producing keys such as
    ``pop_os-amd64`` versus ``pop-os-generic``. That mismatch made the
    cleanup's filename prefix filter reject every Pop!_OS candidate, so old
    builds were never removed.

    Examples:
        'Pop_OS 24.04 amd64'                 -> 'pop-os'
        'pop-os_24.04_amd64_generic_24.iso'  -> 'pop-os-generic'
        'Ubuntu-Server 26.04.1 LTS amd64'    -> 'ubuntu-server'
        'ubuntu-24.04.1-live-server-amd64.iso' -> 'ubuntu-live-server'
    """
    stem = re.sub(r"\.(iso|img)$", "", text, flags=re.IGNORECASE)
    # Remove arch tokens with their surrounding separator so "…-amd64" does not
    # leave a dangling hyphen, then drop standalone version and release words.
    stem = _ARCH_IN_KEY_RE.sub(" ", stem)
    tokens = []
    for token in re.split(r"[\s_\-]+", stem.lower()):
        if not token:
            continue
        if _VERSION_IN_KEY_RE.match(token):
            continue
        if _RELEASE_WORD_RE.fullmatch(token):
            continue
        tokens.append(token)
    return "-".join(tokens)


def _variant_stem(volume_id: str) -> str:
    """Variant key for an ISO 9660 volume ID. Thin alias of variant_key()."""
    return variant_key(volume_id)


def _filename_variant_key(filename: str) -> str:
    """Variant key for a filename. Thin alias of variant_key()."""
    return variant_key(filename)


def same_variant_prefix(key_a: str, key_b: str) -> bool:
    """Cheap pre-filter: could two keys plausibly be the same variant?

    Used to avoid reading a volume ID from every ISO on the drive. Both sides
    are normalised keys, and the check keeps the original "filename starts with
    the first token" semantics: one leading token being a prefix of the other is
    enough to proceed. Exact equality alone would be too strict — the volume ID
    of an Arch ISO is ``ARCH_202610`` (key ``arch``) while its filename key is
    ``archlinux``, and requiring equality would silently stop cleanup.

    Normalising both sides is the fix: the previous raw comparison rejected
    ``pop_os`` versus ``pop-os`` because of the separator mismatch.
    """
    if not key_a or not key_b:
        return True
    first_a = key_a.split("-", 1)[0]
    first_b = key_b.split("-", 1)[0]
    return first_a.startswith(first_b) or first_b.startswith(first_a)


def _check_distro(
    entry_id: str, settings: dict, ventoy_root: Path, force: bool = False
) -> DistroCheck:
    """Scrape and version-check a single distro. Returns metadata for download decisions.

    A mirror we could not read yields UNREACHABLE (never CURRENT), so callers can
    report it and exit non-zero rather than pretending the distro is up to date.
    """
    clean_name = settings.get("clean_name", entry_id)
    _debug(f"Checking {clean_name} (force={force})")
    spin_update(clean_name)

    latest_filename, download_url = process_scraping_strategy(clean_name, settings)
    if not latest_filename:
        # Terse here; the full reason is collected and tabulated by the caller.
        warn(f"{clean_name} — unreachable (details below)")
        return _unreachable(
            entry_id, clean_name, str(settings.get("resolve_error") or "")
        )

    local_ventoy_files = find_installed_isos(ventoy_root)

    # Exact filename match — already up to date (skip check if --force).
    # Case-insensitive: Ventoy drives are typically FAT/exFAT (case-insensitive),
    # so 'Arch' and 'arch' are the same file there.
    if not force and any(
        f.name.lower() == latest_filename.lower() for f in local_ventoy_files
    ):
        success(f"{clean_name} is up to date")
        return DistroCheck(
            entry_id, clean_name, latest_filename, SyncStatus.CURRENT, None
        )

    # Version-based comparison: find best local candidate and compare
    remote_version = extract_version_from_filename(latest_filename)
    if not remote_version:
        reason = f"no version in upstream filename {latest_filename!r}"
        warn(f"{clean_name} — {reason}")
        return _unreachable(entry_id, clean_name, reason)

    if not force:
        remote_key = _filename_variant_key(latest_filename)
        same_distro = [
            f
            for f in local_ventoy_files
            if extract_version_from_filename(f.name)
            and _filename_variant_key(f.name) == remote_key
        ]
        if same_distro:
            best_local = max(
                same_distro,
                key=lambda f: (
                    parse_version(extract_version_from_filename(f.name)) or (0,)
                ),
            )
            local_version = extract_version_from_filename(best_local.name)
            comparison = compare_versions(remote_version, local_version)
            if comparison <= 0:
                success(
                    f"{clean_name} is up to date (local {local_version}, upstream {remote_version})"
                )
                return DistroCheck(
                    entry_id, clean_name, latest_filename, SyncStatus.CURRENT, None
                )

    if force:
        warn(f"{clean_name} — force re-download")

    return DistroCheck(
        entry_id, clean_name, latest_filename, SyncStatus.STALE, download_url
    )


def _copy_with_progress(src: Path, dst: Path, filename: str) -> None:
    """Copy a file with a live progress bar.

    Used when moving an ISO from the staging buffer onto the Ventoy drive
    (different filesystems), where shutil.move would silently copy the whole
    file and look like a hard freeze.
    """
    total = src.stat().st_size
    with make_download_progress() as progress:
        task = progress.add_task(
            "copy to drive", filename=_esc(filename), total=total or None
        )
        copied = 0
        with open(src, "rb") as rf, open(dst, "wb") as wf:
            while True:
                chunk = rf.read(1024 * 1024)
                if not chunk:
                    break
                wf.write(chunk)
                copied += len(chunk)
                progress.update(task, completed=copied)


def _cleanup_part_files(*directories: Path) -> None:
    """Delete any leftover .part files from the given directories."""
    for directory in directories:
        if not directory.is_dir():
            continue
        for part_file in directory.rglob("*.part"):
            # Only remove files this tool creates (<name>.iso.part / .img.part)
            if part_file.suffixes[-2:] not in ([".iso", ".part"], [".img", ".part"]):
                continue
            part_file.unlink(missing_ok=True)


def sync_all_configured_distros(
    dry_run: bool = False,
    force: bool = False,
    clean: bool = False,
    config_path: Path | None = None,
    only: list[str] | None = None,
    drive_override: Path | None = None,
    use_buffer: bool = True,
    no_verify: bool = False,
    reset_visync: bool = False,
) -> tuple[Path | None, list[str], list[tuple[str, str]]]:
    """Iterate through user-defined scrapers to pull updates down safely.

    If *only* is provided, only sync those entry_ids.
    If *drive_override* is provided, use that as the Ventoy root.
    Set *use_buffer* to False to download directly to the Ventoy drive.
    Set *reset_visync* to allow the watchdog to wipe an over-budget .visync/;
    without it the watchdog only deep-cleans. The watchdog never runs on a
    dry run, which must not modify the drive at all.

    Returns ``(download_dir, downloaded_filenames, unreachable)`` where
    *unreachable* is a list of ``(clean_name, reason)`` for every distro whose
    upstream could not be read. This function never raises for a failed scrape;
    the caller decides whether to exit non-zero.
    """
    _debug(
        f"sync_all_configured_distros(dry_run={dry_run}, force={force}, clean={clean}, only={only})"
    )
    config = load_config(config_path)
    distro_scrapers = config.get("distros", {})
    iso_settings = config.get("iso", {})
    unreachable: list[tuple[str, str]] = []

    if not distro_scrapers:
        error("No distribution definitions configured inside [distros] block.")
        return None, [], [("config.toml", "no [distros] block is defined")]

    if drive_override:
        ventoy_root = drive_override
    else:
        drives = find_ventoy_drives()
        if not drives:
            error("No Ventoy drives found.")
            return None, [], [("(drive)", "no Ventoy drives found")]
        ventoy_root = drives[0]

    # The watchdog deep-cleans and can wipe .visync/, so it must never run on a
    # dry run — that command promises to leave the drive untouched.
    if not dry_run:
        visync_watchdog(ventoy_root, allow_wipe=reset_visync)
    _sweep_old_versions(ventoy_root, clean=clean and not dry_run)

    config_download_dir = iso_settings.get("download_dir", "").strip()
    if use_buffer:
        download_target_dir = (
            Path(config_download_dir) if config_download_dir else DEFAULT_STAGING_DIR
        )
        if not dry_run:
            download_target_dir.mkdir(parents=True, exist_ok=True)
        info(f"Buffer staging → {download_target_dir}")
    else:
        download_target_dir = ventoy_root
        info(f"Direct volume mode → {download_target_dir}")

    pending_downloads: list[tuple[str, str, str]] = []

    if only:
        configured = set(distro_scrapers)
        unknown = sorted(set(only) - configured)
        distro_scrapers = {k: v for k, v in distro_scrapers.items() if k in only}
        if unknown:
            # Usually an entry_id left in installed.json by a removed distro.
            warn(
                "Installed but no longer configured: "
                f"{', '.join(unknown)} — run 'visync search' for the current list"
            )
            unreachable.extend(
                (eid, "no longer configured in config.toml") for eid in unknown
            )
        if not distro_scrapers:
            if not unreachable:
                warn("None of the specified distros are configured.")
                unreachable.append(("(none)", "no requested distros are configured"))
            return None, [], unreachable

    spin_start("Syncing ISOs...")
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(distro_scrapers))
    try:
        future_map = {
            executor.submit(
                _check_distro, entry_id, settings, ventoy_root, force
            ): entry_id
            for entry_id, settings in distro_scrapers.items()
        }
        deadline = time.monotonic() + SCRAPE_DEADLINE
        pending = set(future_map)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                for f in pending:
                    f.cancel()
                    timed_out_id = future_map[f]
                    error(f"{timed_out_id} timed out")
                    unreachable.append(
                        (timed_out_id, f"scrape exceeded {SCRAPE_DEADLINE}s deadline")
                    )
                break
            done, pending = concurrent.futures.wait(
                pending, timeout=min(remaining, 0.5)
            )
            for future in done:
                try:
                    check = future.result()
                except (TimeoutError, ConnectionResetError, OSError) as e:
                    failed_id = future_map[future]
                    error(f"{failed_id}: {e}")
                    unreachable.append((failed_id, str(e)))
                    continue
                except Exception as e:
                    failed_id = future_map[future]
                    error(f"{failed_id}: {e}")
                    unreachable.append((failed_id, f"{type(e).__name__}: {e}"))
                    continue
                if check.status is SyncStatus.UNREACHABLE:
                    unreachable.append((check.clean_name, check.reason))
                    continue
                if check.status is not SyncStatus.STALE or not check.download_url:
                    continue
                pending_downloads.append(
                    (check.download_url, check.latest_filename, check.entry_id)
                )
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        spin_stop()

    checksums_config = config.get("checksums", {})

    downloaded: list[str] = []

    if dry_run:
        if pending_downloads:
            console.print()
            info(f"Would download {len(pending_downloads)} file(s):")
            for _url, filename, _ in pending_downloads:
                console.print(f"    [cyan]→[/cyan] {_esc(filename)}")
        elif unreachable:
            info("Nothing to download — but some distros could not be checked.")
        else:
            info("All ISOs are current — nothing to download.")
    else:
        for download_url, latest_filename, entry_id in pending_downloads:
            dest = download_target_dir / latest_filename
            part_file = dest.with_suffix(dest.suffix + ".part")
            distro_cfg = distro_scrapers.get(entry_id, {})
            try:
                ok = download_iso(
                    download_url,
                    dest,
                    drive_root=ventoy_root,
                    distro_config=distro_cfg,
                    checksums_config=checksums_config,
                    no_verify=no_verify,
                )
            except ValueError as e:
                error(f"Skipping {latest_filename}: {e}")
                part_file.unlink(missing_ok=True)
                unreachable.append((latest_filename, f"rejected: {e}"))
                continue
            except (TimeoutError, ConnectionResetError, OSError) as e:
                error(f"Failed syncing {latest_filename}: {e}")
                part_file.unlink(missing_ok=True)
                unreachable.append((latest_filename, f"download failed: {e}"))
                continue
            if not ok:
                part_file.unlink(missing_ok=True)
                unreachable.append((latest_filename, "download or verification failed"))
                continue
            downloaded.append(latest_filename)
            if dest.parent != ventoy_root:
                drive_dest = ventoy_root / latest_filename
                try:
                    try:
                        dest.rename(drive_dest)
                        success(f"Moved to Ventoy drive: {latest_filename}")
                    except OSError:
                        info(f"Copying to Ventoy drive: {latest_filename}")
                        _copy_with_progress(dest, drive_dest, latest_filename)
                        if drive_dest.stat().st_size != dest.stat().st_size:
                            error(
                                f"Copy verification failed for {latest_filename} — "
                                f"source {dest.stat().st_size}, dest {drive_dest.stat().st_size}"
                            )
                            drive_dest.unlink(missing_ok=True)
                            unreachable.append(
                                (latest_filename, "copy to drive failed size check")
                            )
                            continue
                        success(f"Copied to Ventoy drive: {latest_filename}")
                except OSError as e:
                    error(f"Failed placing {latest_filename} on drive: {e}")
                    try:
                        drive_dest.unlink(missing_ok=True)
                    except OSError as unlink_err:
                        if unlink_err.errno == 30:
                            warn(
                                f"Drive became read-only (unplugged?), skipping cleanup of {drive_dest}"
                            )
                        else:
                            warn(
                                f"Could not remove partial file {drive_dest}: {unlink_err}"
                            )
                    unreachable.append(
                        (latest_filename, f"could not place on drive: {e}")
                    )
                    continue
                try:
                    dest.unlink(missing_ok=True)
                except OSError as e:
                    warn(f"Could not remove staging copy {dest.name}: {e}")
                _cleanup_old_versions(drive_dest, ventoy_root)

    return download_target_dir, downloaded, unreachable


if __name__ == "__main__":
    header("VISYNC PROTOCOL LOGISTICAL EXTENSION ENGINE")
    try:
        sync_all_configured_distros()
    except KeyboardInterrupt:
        console.print(
            "\n[red]✕ Sync canceled by user. Cleaning up partial downloads...[/red]"
        )
        _config = load_config()
        _iso_settings = _config.get("iso", {})
        _cleanup_targets: list[Path] = []
        _download_dir = _iso_settings.get("download_dir", "").strip()
        if _download_dir:
            _cleanup_targets.append(Path(_download_dir))
        else:
            _cleanup_targets.append(DEFAULT_STAGING_DIR)
        _drives = find_ventoy_drives()
        if _drives:
            _cleanup_targets.append(_drives[0])
        _cleanup_part_files(*_cleanup_targets)
        raise SystemExit(130)
