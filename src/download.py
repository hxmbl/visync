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
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.finder import (
    find_installed_isos,
    find_ventoy_drives,
    get_iso_volume_id,
    identify_distro,
    load_config,
    write_iso_metadata,
    remove_iso_metadata,
    visync_watchdog,
)
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
PER_DISTRO_TIMEOUT = 30
SCRAPE_DEADLINE = 120
DEFAULT_STAGING_DIR = Path.home() / ".cache" / "visync" / "staging"


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
    except (socket.timeout, OSError) as e:
        _debug(f"Ping failed: {e}")
        return False


def fetch_html(url: str, allow_insecure: bool = False) -> str:
    """Download HTML source from a mirror index page."""
    _debug(f"Fetching {url} (insecure={allow_insecure})")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        ctx = None
        if allow_insecure:
            import ssl

            ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=MIRROR_HTTP_TIMEOUT, context=ctx) as response:
            html = response.read().decode("utf-8", errors="ignore")
            # Detect bot-protected pages (e.g. Anubis proof-of-work)
            if "Anubis" in html[:1000]:
                warn("Mirror protected by bot challenge (Anubis). Cannot scrape automatically.")
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


def process_scraping_strategy(name: str, settings: dict) -> tuple[str, str]:
    """Resolve specific folder parsing pipelines based on the configured strategy."""
    strategy = settings.get("strategy")
    base_url = settings.get("base_url")
    iso_regex = settings.get("iso_regex")

    # Pre-flight connectivity check — skip dead mirrors instantly
    if base_url and not ping_mirror(base_url):
        warn(f"Mirror unreachable (ping failed): {base_url}")
        return "", ""

    # Strategy A: Direct Index File Tracking (e.g. Arch Linux)
    if strategy == "direct_match":
        html = fetch_html(base_url)
        if not html:
            return "", ""
        match = re.search(iso_regex, html)
        if match:
            return match.group(1), f"{base_url}{match.group(1)}"

    # Strategy B: Two-Tier Version Directory Traversal for Fedora
    elif strategy == "fedora_nested":
        root_html = fetch_html(base_url)
        if not root_html:
            return "", ""
        versions = re.findall(settings.get("version_regex"), root_html)
        if not versions:
            return "", ""

        versions.sort(key=lambda x: [int(d) for d in x.split(".") if d.isdigit()])
        latest_version = versions[-1]

        variant_path = settings.get("variant_path", "Workstation/x86_64/iso")
        iso_dir_url = f"{base_url}{latest_version}/{variant_path}/"
        iso_html = fetch_html(iso_dir_url)
        if not iso_html:
            return "", ""

        match = re.search(iso_regex, iso_html)
        if match:
            return match.group(1), f"{iso_dir_url}{match.group(1)}"

    # Strategy C: Directory Sub-paths for Ubuntu Ecosystem Releases
    elif strategy == "ubuntu_nested":
        root_html = fetch_html(base_url)
        if not root_html:
            return "", ""
        versions = re.findall(settings.get("version_regex"), root_html)
        if not versions:
            return "", ""

        versions.sort(key=lambda x: [int(d) for d in x.split(".") if d.isdigit()])
        latest_version = versions[-1]

        iso_dir_url = f"{base_url}{latest_version}/"
        iso_html = fetch_html(iso_dir_url)
        if not iso_html:
            return "", ""

        match = re.search(iso_regex, iso_html)
        if match:
            return match.group(1), f"{iso_dir_url}{match.group(1)}"

    # Strategy D: NixOS channel page — parse version, construct ISO URL
    elif strategy == "nixos_channel":
        html = fetch_html(base_url)
        if not html:
            return "", ""

        # The channel page contains text like "nixos-26.05 release nixos-26.05.1947.a0374025a863"
        version_match = re.search(r"nixos-[\d\.]+\s+release\s+(nixos-[\d\.]+\.[a-f0-9]+)", html)
        if not version_match:
            warn(f"{name} — could not parse NixOS version from channel page")
            return "", ""

        full_version = version_match.group(1)  # e.g. "nixos-26.05.1947.a0374025a863"
        # Strip the "nixos-" prefix for constructing URLs
        version_id = full_version.replace("nixos-", "", 1)  # e.g. "26.05.1947.a0374025a863"
        # Extract the short version (e.g. "26.05") from the full version
        short_version_match = re.search(r"nixos-([\d]+\.[\d]+)", full_version)
        if not short_version_match:
            return "", ""
        short_version = short_version_match.group(1)  # e.g. "26.05"

        variant = settings.get("variant", "minimal")  # "minimal" or "graphical"
        iso_filename = f"nixos-{variant}-{version_id}-x86_64-linux.iso"
        iso_url = f"https://releases.nixos.org/nixos/{short_version}/{full_version}/{iso_filename}"

        # Parse SHA-256 checksum from the channel page HTML table.
        # The page has rows: <td><a href='...'>FILENAME</a></td><td>SIZE</td><td><tt>HASH</tt></td>
        checksum_match = re.search(
            r"href=['\"][^'\"]*" + re.escape(iso_filename) + r"['\"]>"
            + re.escape(iso_filename)
            + r"</a></td><td[^>]*>\d+</td><td><tt>([a-f0-9]{64})</tt>",
            html,
        )
        if checksum_match:
            settings["resolved_checksum"] = checksum_match.group(1)

        # Verify the URL is reachable
        try:
            req = urllib.request.Request(iso_url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=MIRROR_HTTP_TIMEOUT) as resp:
                if resp.status == 200:
                    return iso_filename, iso_url
        except Exception:
            pass

        return "", ""

    # Strategy E: Pop!_OS JSON API — fetch latest build info
    elif strategy == "popos_api":
        import json as _json

        api_url = settings.get("api_url", "https://api.pop-os.org/builds")
        variant = settings.get("variant", "generic")
        release = settings.get("release", "24.04")

        url = f"{api_url}/{release}/{variant}"
        html = fetch_html(url)
        if not html:
            return "", ""

        try:
            data = _json.loads(html)
            iso_url = data.get("url", "")
            if iso_url:
                iso_filename = iso_url.rsplit("/", 1)[-1]
                return iso_filename, iso_url
        except (_json.JSONDecodeError, KeyError):
            warn(f"{name} — could not parse Pop!_OS API response")

        return "", ""

    # Strategy F: Tails JSON API — fetch latest version from releases.json
    elif strategy == "tails_api":
        import json as _json

        api_url = settings.get("api_url", "https://tails.net/install/v2/Tails/amd64/stable/latest.json")
        file_type = settings.get("file_type", "img")  # "iso" or "img"

        html = fetch_html(api_url)
        if not html:
            return "", ""

        try:
            data = _json.loads(html)
            installations = data.get("installations", [])
            if not installations:
                return "", ""

            latest = installations[0]
            for installation in installations:
                if installation.get("version", "") > latest.get("version", ""):
                    latest = installation

            for path in latest.get("installation-paths", []):
                if path.get("type") == file_type:
                    for target in path.get("target-files", []):
                        url = target.get("url", "")
                        if url:
                            iso_filename = url.rsplit("/", 1)[-1]
                            return iso_filename, url
        except (_json.JSONDecodeError, KeyError, IndexError):
            warn(f"{name} — could not parse Tails API response")

        return "", ""

    return "", ""


DOWNLOAD_THREADS = int(os.environ.get("VISYNC_DOWNLOAD_THREADS", "4"))
MIN_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB minimum per chunk


def _download_chunked(
    url: str,
    part_path: Path,
    total: int,
    num_threads: int,
    filename: str,
) -> bool:
    """Download a file using HTTP Range requests in parallel threads.

    Writes directly to part_path at the correct offsets using os.pwrite.
    Returns True on success, False on failure.
    """
    import threading

    chunk_size = max(MIN_CHUNK_SIZE, total // num_threads)
    # Build (start, end) ranges
    ranges: list[tuple[int, int]] = []
    start = 0
    while start < total:
        end = min(start + chunk_size - 1, total - 1)
        ranges.append((start, end))
        start = end + 1

    actual_threads = len(ranges)
    _debug(f"Chunked download: {total} bytes in {actual_threads} chunks of ~{chunk_size} bytes")

    # Pre-allocate the file
    fd = os.open(str(part_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
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
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0", "Range": range_header},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                offset = chunk_start
                while True:
                    try:
                        data = resp.read(128000)
                    except socket.timeout:
                        with lock:
                            errors.append(f"Chunk {idx} stalled")
                        return
                    if not data:
                        break
                    os.pwrite(fd, data, offset)
                    offset += len(data)
                    with lock:
                        downloaded[idx] = offset - chunk_start
        except Exception as e:
            with lock:
                errors.append(f"Chunk {idx}: {e}")

    with make_download_progress() as progress:
        task = progress.add_task("download", filename=filename, total=total or None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=actual_threads) as pool:
            futures = [
                pool.submit(_download_chunk, i, s, e)
                for i, (s, e) in enumerate(ranges)
            ]
            # Poll progress while futures run
            while not all(f.done() for f in futures):
                time.sleep(0.25)
                with lock:
                    total_done = sum(downloaded)
                progress.update(task, completed=total_done)
            # Final update
            concurrent.futures.wait(futures)
            with lock:
                total_done = sum(downloaded)
            progress.update(task, completed=total_done)

    os.close(fd)

    if errors:
        error(f"Chunked download failed: {'; '.join(errors[:3])}")
        return False

    return True


def _download_single_stream(
    url: str,
    part_path: Path,
    total: int,
    filename: str,
) -> bool:
    """Download a file in a single stream with progress reporting."""
    CHUNK_SIZE = 128000
    READ_TIMEOUT = 30

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            downloaded = 0
            with make_download_progress() as progress:
                task = progress.add_task(
                    "download",
                    filename=filename,
                    total=total or None,
                )
                with open(part_path, "wb", buffering=1048576) as f:
                    while True:
                        try:
                            chunk = resp.read(CHUNK_SIZE)
                        except socket.timeout:
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
    console.print(f"  [cyan]↓[/cyan] Downloading [bold]{dest_path.name}[/bold]")

    # HEAD request: get size, check range support
    expected = 0
    ranges_supported = False
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
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
            info(f"Expected: {expected / (1024**3):.2f} GiB | Available: {available / (1024**3):.2f} GiB")
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
    if ranges_supported and expected > MIN_CHUNK_SIZE * DOWNLOAD_THREADS:
        _debug(f"Using chunked download ({DOWNLOAD_THREADS} threads)")
        ok = _download_chunked(url, part_path, expected, DOWNLOAD_THREADS, dest_path.name)
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

    part_path.rename(dest_path)
    success(f"Downloaded {dest_path.name}")

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
            from src.verify import verify_from_config
            spin_update(f"Verifying checksum for {dest_path.name}...")
            result = verify_from_config(
                dest_path, "", distro_config, checksums_config,
                precomputed_hash=sha256_hex,
            )
            if result is False:
                error(f"Checksum verification failed for {dest_path.name} — deleting")
                dest_path.unlink(missing_ok=True)
                return False
            elif result is True:
                success(f"Checksum verified: {dest_path.name}")
            else:
                warn(f"No checksum config for {dest_path.name} — skipping verification")
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
            new_stem = new_iso.name.rsplit("-", 1)[0].lower() if "-" in new_iso.name else ""

        if new_distro in ("Unknown OS", ""):
            return

        target_dir = new_iso.parent
        new_stem_lower = new_stem.lower()

        for iso_path in find_installed_isos(target_dir):
            if iso_path == new_iso:
                continue

            try:
                # Quick filename-based filter: same distro prefix
                old_name_lower = iso_path.name.lower()
                # Check if filename starts with the same stem prefix
                if new_stem_lower and not old_name_lower.startswith(new_stem_lower.split("-")[0]):
                    continue

                # Confirm match by reading volume ID only for candidates
                old_vid = get_iso_volume_id(iso_path)
                if old_vid:
                    old_distro = identify_distro(old_vid, iso_path.name)
                    old_stem = _variant_stem(old_vid)
                else:
                    old_distro = identify_distro("", iso_path.name)
                    old_stem = iso_path.name.rsplit("-", 1)[0].lower() if "-" in iso_path.name else ""

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
            stem = iso_path.name.rsplit("-", 1)[0].lower() if "-" in iso_path.name else ""
        version = extract_version_from_filename(iso_path.name) or "0"
        if distro and distro != "Unknown OS":
            groups[(distro, stem)].append((version, iso_path))

    for (distro, _stem), versions in groups.items():
        if len(versions) <= 1:
            continue
        versions.sort(key=lambda x: [int(d) for d in x[0].split(".") if d.isdigit()])
        newest_version, newest_path = versions[-1]
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


def _variant_stem(volume_id: str) -> str:
    """Extract a stable variant stem from a volume ID by removing version-like tokens.

    Version tokens are segments that start with a digit (e.g. '44', '24.04.4').
    Architecture tokens like 'x86_64' and 'amd64' are preserved because they start
    with a letter, even though they contain digits. Consecutive separators
    (from removed version tokens) are collapsed into a single hyphen.

    Examples:
        'Fedora-E-dvd-x86_64-44'         → 'fedora-e-dvd-x86_64'
        'Fedora-KDE-Live-44'             → 'fedora-kde-live'
        'Ubuntu-Server 24.04.4 LTS amd64' → 'ubuntu-server-amd64'
    """
    import re as _re

    # Temporarily protect architecture names that contain underscores
    # (e.g. x86_64) by replacing the underscore with a placeholder
    protected = volume_id
    arch_patterns = _re.findall(r"\b(x86_\d+|amd\d+|i\d86|arm\w*)\b", volume_id, _re.I)
    for arch in arch_patterns:
        safe_arch = arch.replace("_", "§")
        protected = protected.replace(arch, safe_arch, 1)

    tokens = _re.split(r"([\s\-_]+)", protected)
    cleaned = []
    for token in tokens:
        if _re.match(r"^[\s\-_]+$", token):
            cleaned.append(token)
            continue
        # Remove tokens that start with a digit (version numbers)
        if token and token[0].isdigit():
            continue
        cleaned.append(token)

    stem = "".join(cleaned)
    stem = stem.replace("§", "_")
    stem = _re.sub(r"\b(lts|esd|point)\b", "", stem, flags=_re.I)
    stem = _re.sub(r"[\s\-]+", "-", stem).strip(" -_")
    return stem.lower()


def _check_distro(entry_id: str, settings: dict, ventoy_root: Path, force: bool = False) -> tuple[str, str, str, bool, str | None]:
    """Scrape and version-check a single distro. Returns metadata for download decisions."""
    clean_name = settings.get("clean_name", entry_id)
    _debug(f"Checking {clean_name} (force={force})")
    spin_update(clean_name)

    latest_filename, download_url = process_scraping_strategy(clean_name, settings)
    if not latest_filename:
        warn(f"{clean_name} — unable to reach mirror")
        return entry_id, clean_name, "", False, None

    local_ventoy_files = find_installed_isos(ventoy_root)

    # Exact filename match — already up to date (skip check if --force)
    if not force and any(f.name == latest_filename for f in local_ventoy_files):
        success(f"{clean_name} is up to date")
        return entry_id, clean_name, latest_filename, True, None

    # Version-based comparison: find best local candidate and compare
    remote_version = extract_version_from_filename(latest_filename)
    if not remote_version:
        warn(f"{clean_name} — could not parse version from '{latest_filename}'")
        return entry_id, clean_name, "", False, None

    if not force:
        remote_stem = latest_filename.split("-")[0].lower()
        same_distro = [
            f for f in local_ventoy_files
            if f.name.lower().startswith(remote_stem)
            and extract_version_from_filename(f.name)
        ]
        if same_distro:
            best_local = max(
                same_distro,
                key=lambda f: parse_version(extract_version_from_filename(f.name)) or (0,),
            )
            local_version = extract_version_from_filename(best_local.name)
            comparison = compare_versions(remote_version, local_version)
            if comparison <= 0:
                success(
                    f"{clean_name} is up to date (local {local_version}, upstream {remote_version})"
                )
                return entry_id, clean_name, latest_filename, True, None

    if force:
        warn(f"{clean_name} — force re-download")

    return entry_id, clean_name, latest_filename, False, download_url


def _copy_with_progress(src: Path, dst: Path, filename: str) -> None:
    """Copy a file with a live progress bar.

    Used when moving an ISO from the staging buffer onto the Ventoy drive
    (different filesystems), where shutil.move would silently copy the whole
    file and look like a hard freeze.
    """
    total = src.stat().st_size
    with make_download_progress() as progress:
        task = progress.add_task("copy", filename=filename, total=total or None)
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
) -> tuple[Path | None, list[str]]:
    """Iterate through user-defined scrapers to pull updates down safely.

    If *only* is provided, only sync those entry_ids.
    If *drive_override* is provided, use that as the Ventoy root.
    Set *use_buffer* to False to download directly to the Ventoy drive.
    """
    _debug(f"sync_all_configured_distros(dry_run={dry_run}, force={force}, clean={clean}, only={only})")
    config = load_config(config_path)
    distro_scrapers = config.get("distros", {})
    iso_settings = config.get("iso", {})

    if not distro_scrapers:
        error("No distribution definitions configured inside [distros] block.")
        return

    if drive_override:
        ventoy_root = drive_override
    else:
        drives = find_ventoy_drives()
        if not drives:
            error("No Ventoy drives found.")
            return
        ventoy_root = drives[0]

    visync_watchdog(ventoy_root)
    _sweep_old_versions(ventoy_root, clean=clean)

    config_download_dir = iso_settings.get("download_dir", "").strip()
    if use_buffer:
        download_target_dir = Path(config_download_dir) if config_download_dir else DEFAULT_STAGING_DIR
        download_target_dir.mkdir(parents=True, exist_ok=True)
        info(f"Buffer staging → {download_target_dir}")
    else:
        download_target_dir = ventoy_root
        info(f"Direct volume mode → {download_target_dir}")

    pending_downloads: list[tuple[str, str, str]] = []
    scrape_start = __import__("time").monotonic()

    if only:
        distro_scrapers = {k: v for k, v in distro_scrapers.items() if k in only}
        if not distro_scrapers:
            warn("None of the specified distros are configured.")
            return

    spin_start("Syncing ISOs...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(distro_scrapers)) as executor:
        future_map = {
            executor.submit(_check_distro, entry_id, settings, ventoy_root, force): entry_id
            for entry_id, settings in distro_scrapers.items()
        }
        for future in concurrent.futures.as_completed(future_map, timeout=SCRAPE_DEADLINE):
            elapsed = __import__("time").monotonic() - scrape_start
            if elapsed > SCRAPE_DEADLINE:
                break
            try:
                entry_id, clean_name, latest_filename, up_to_date, download_url = future.result(timeout=PER_DISTRO_TIMEOUT)
            except concurrent.futures.TimeoutError:
                error(f"{future_map[future]} timed out")
                continue
            except (TimeoutError, ConnectionResetError, OSError) as e:
                error(f"{future_map[future]}: {e}")
                continue
            if up_to_date or not download_url:
                continue
            pending_downloads.append((download_url, latest_filename, entry_id))
        executor.shutdown(wait=False, cancel_futures=True)
    spin_stop()

    checksums_config = config.get("checksums", {})

    downloaded: list[str] = []

    if dry_run:
        if not pending_downloads:
            info("All ISOs are current — nothing to download.")
        else:
            console.print()
            info(f"Would download {len(pending_downloads)} file(s):")
            for url, filename, _ in pending_downloads:
                console.print(f"    [cyan]→[/cyan] {filename}")
    else:
        for download_url, latest_filename, entry_id in pending_downloads:
            dest = download_target_dir / latest_filename
            part_file = dest.with_suffix(dest.suffix + ".part")
            distro_cfg = distro_scrapers.get(entry_id, {})
            try:
                ok = download_iso(
                    download_url, dest,
                    drive_root=ventoy_root,
                    distro_config=distro_cfg,
                    checksums_config=checksums_config,
                    no_verify=no_verify,
                )
            except (TimeoutError, ConnectionResetError, OSError) as e:
                error(f"Failed syncing {latest_filename}: {e}")
                part_file.unlink(missing_ok=True)
                continue
            if not ok:
                part_file.unlink(missing_ok=True)
                continue
            downloaded.append(latest_filename)
            if dest.parent != ventoy_root:
                drive_dest = ventoy_root / latest_filename
                try:
                    try:
                        dest.rename(drive_dest)
                        success(f"Moved {latest_filename} to Ventoy drive")
                    except OSError:
                        _copy_with_progress(dest, drive_dest, latest_filename)
                        if drive_dest.stat().st_size != dest.stat().st_size:
                            error(
                                f"Copy verification failed for {latest_filename} — "
                                f"source {dest.stat().st_size}, dest {drive_dest.stat().st_size}"
                            )
                            drive_dest.unlink(missing_ok=True)
                            continue
                        dest.unlink(missing_ok=True)
                        success(f"Copied {latest_filename} to Ventoy drive")
                    _cleanup_old_versions(drive_dest, ventoy_root)
                except OSError as e:
                    error(f"Failed placing {latest_filename} on drive: {e}")
                    drive_dest.unlink(missing_ok=True)
                    continue

    return download_target_dir, downloaded


if __name__ == "__main__":
    header("VISYNC PROTOCOL LOGISTICAL EXTENSION ENGINE")
    try:
        sync_all_configured_distros()
    except KeyboardInterrupt:
        console.print("\n[red]✕ Sync canceled by user. Cleaning up partial downloads...[/red]")
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
