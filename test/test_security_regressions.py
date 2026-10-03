"""Regression tests for security/correctness fixes from the audit.

Each test maps to an audit finding ID (C1..C3, H1..H4, M1..M6, L1..L13).
"""

import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from visync import download as dl
from visync.download import (
    DistroCheck,
    SyncStatus,
    _download_chunked,
    _download_threads,
    _safe_filename,
    _sweep_old_versions,
    sync_all_configured_distros,
)
from visync.finder import _dir_size, keyword_hit, load_config
from visync.output import console, error, info, removed, success, warn
from visync.pm import load_installed
from visync.verify import ChecksumUnavailable, expand_url, extract_iso_metadata

ISO_VID_OFFSET = 32808


def _iso_with_vid(path: Path, volume_id: str, size: int = 40000) -> None:
    """Create a fake ISO with an ISO9660 primary volume descriptor label."""
    buf = bytearray(size)
    label = volume_id.encode("ascii")[:32]
    buf[ISO_VID_OFFSET : ISO_VID_OFFSET + len(label)] = label
    path.write_bytes(bytes(buf))


# ── C1: dry-run must gate destructive clean sweeps ───────────────────────────


class TestDryRunGatesClean(unittest.TestCase):
    def _make_drive(self, tmpdir: str) -> Path:
        drive = Path(tmpdir)
        _iso_with_vid(
            drive / "archlinux-2025.01.01-x86_64.iso", "ARCH LINUX 2025.01.01 x86_64"
        )
        _iso_with_vid(
            drive / "archlinux-2026.08.01-x86_64.iso", "ARCH LINUX 2026.08.01 x86_64"
        )
        return drive

    def _config(self):
        return {
            "iso": {},
            "checksums": {"enabled": False},
            "distros": {"ArchLinux": {"clean_name": "Arch Linux"}},
        }

    def _current(self, filename: str) -> DistroCheck:
        return DistroCheck(
            "ArchLinux", "Arch Linux", filename, SyncStatus.CURRENT, None
        )

    @patch("visync.download.visync_watchdog")
    @patch("visync.download._check_distro")
    def test_sync_clean_dry_run_deletes_nothing(self, mock_check, _wd):
        """--clean --dry-run reports but keeps both ISOs on disk."""
        mock_check.return_value = self._current("archlinux-2026.08.01-x86_64.iso")
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._make_drive(tmpdir)
            with patch("visync.download.load_config", return_value=self._config()):
                sync_all_configured_distros(
                    dry_run=True,
                    clean=True,
                    only=["ArchLinux"],
                    drive_override=drive,
                    use_buffer=False,
                )
            self.assertTrue((drive / "archlinux-2025.01.01-x86_64.iso").exists())
            self.assertTrue((drive / "archlinux-2026.08.01-x86_64.iso").exists())

    @patch("visync.download.visync_watchdog")
    @patch("visync.download._check_distro")
    def test_sync_clean_without_dry_run_removes_old(self, mock_check, _wd):
        """--clean (no dry-run) removes only the older version."""
        mock_check.return_value = self._current("archlinux-2026.08.01-x86_64.iso")
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._make_drive(tmpdir)
            with patch("visync.download.load_config", return_value=self._config()):
                sync_all_configured_distros(
                    dry_run=False,
                    clean=True,
                    only=["ArchLinux"],
                    drive_override=drive,
                    use_buffer=False,
                )
            self.assertFalse((drive / "archlinux-2025.01.01-x86_64.iso").exists())
            self.assertTrue((drive / "archlinux-2026.08.01-x86_64.iso").exists())

    def test_sweep_keeps_higher_release_not_higher_build(self):
        """Fedora 43 build 1.0 must outrank Fedora 42 build 1.6 (M6 sort)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = Path(tmpdir)
            f42 = drive / "Fedora-Workstation-Live-x86_64-42-1.6.iso"
            f43 = drive / "Fedora-Workstation-Live-x86_64-43-1.0.iso"
            _iso_with_vid(f42, "Fedora-Workstation-Live-x86_64-42-1.6")
            _iso_with_vid(f43, "Fedora-Workstation-Live-x86_64-43-1.0")
            _sweep_old_versions(drive, clean=True)
            self.assertTrue(f43.exists(), "newer release must survive")
            self.assertFalse(f42.exists())

    @patch("visync.download.visync_watchdog")
    @patch("visync.download._check_distro")
    def test_sync_dry_run_creates_no_staging_dir(self, mock_check, _wd):
        """--dry-run must not create the staging cache directory."""
        mock_check.return_value = DistroCheck(
            "ArchLinux",
            "Arch Linux",
            "archlinux-2026.08.01-x86_64.iso",
            SyncStatus.STALE,
            "https://m/x.iso",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            staging = Path(tmpdir) / "staging"
            cfg = {
                "iso": {},
                "checksums": {"enabled": False},
                "distros": {"ArchLinux": {"clean_name": "Arch Linux"}},
            }
            with (
                patch("visync.download.load_config", return_value=cfg),
                patch.object(dl, "DEFAULT_STAGING_DIR", staging),
            ):
                sync_all_configured_distros(
                    dry_run=True,
                    only=["ArchLinux"],
                    drive_override=Path(tmpdir),
                    use_buffer=True,
                )
            self.assertFalse(
                staging.exists(), "dry-run must not create the staging dir"
            )


# ── C2: chunked downloader rejects truncated / range-ignoring servers ────────


class _RangeServer(BaseHTTPRequestHandler):
    """Minimal byte-range server. Emits Content-Range so the client's range
    validation can be exercised, and lets subclasses lie about it."""

    data = b""
    truncate_at = None  # bytes to serve for the SECOND range before clean EOF

    # Set on subclasses to make the server misreport the range it served.
    # content_range_fn receives (start, end) and returns the Content-Range to
    # emit; the sentinel below omits the header entirely.
    content_range_fn = None
    OMIT = object()

    def _serve(self, start, end, chunk):
        self.send_response(206)
        self.send_header("Content-Length", str(len(chunk)))
        override = type(self).content_range_fn
        value = (
            f"bytes {start}-{end - 1}/{len(self.data)}"
            if override is None
            else override(start, end)
        )
        if value is not type(self).OMIT:
            self.send_header("Content-Range", value)
        self.end_headers()
        try:
            self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            # The client rejects a bad range and hangs up; that is the point.
            self.close_connection = True

    def do_GET(self):
        spec = self.headers.get("Range", "")[6:]
        start_s, end_s = spec.split("-")
        start, end = int(start_s), int(end_s) + 1
        chunk = self.data[start:end]
        if type(self).truncate_at is not None and start == type(self).truncate_at[0]:
            self._serve(start, end, chunk[: type(self).truncate_at[1]])
            self.close_connection = True
            return
        self._serve(start, end, chunk)

    def log_message(self, *a):
        pass


class TestChunkedIntegrity(unittest.TestCase):
    def _serve(self, handler_cls):
        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        t = threading.Thread(target=server.serve_forever, daemon=True)

        def _stop():
            server.shutdown()
            t.join()

        self.addCleanup(_stop)
        t.start()
        return f"http://127.0.0.1:{server.server_address[1]}/x.iso"

    def test_short_read_detected(self):
        """A cleanly-truncated range must fail the download, not leave holes."""
        data = os.urandom(12 * 1024 * 1024)
        handler = type(
            "TruncServer",
            (_RangeServer,),
            {
                "data": data,
                "truncate_at": (4 * 1024 * 1024, 1024 * 1024),
            },
        )
        url = self._serve(handler)
        with tempfile.TemporaryDirectory() as tmpdir:
            part = Path(tmpdir) / "x.iso.part"
            ok = _download_chunked(url, part, len(data), 3, "x.iso")
            self.assertFalse(ok, "truncated chunk must fail the download")

    def test_range_ignored_detected(self):
        """A server answering 200 to Range requests must fail the download."""
        payload = os.urandom(12 * 1024 * 1024)

        class NoRange(_RangeServer):
            data = payload
            status_code = 200

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        url = self._serve(NoRange)
        with tempfile.TemporaryDirectory() as tmpdir:
            part = Path(tmpdir) / "x.iso.part"
            ok = _download_chunked(url, part, len(payload), 3, "x.iso")
            self.assertFalse(ok, "non-206 response must fail the download")


class TestChunkedWindowsFallback(unittest.TestCase):
    """Chunked downloader must work on Windows where os.pwrite does not exist."""

    def _serve(self, handler_cls):
        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        t = threading.Thread(target=server.serve_forever, daemon=True)

        def _stop():
            server.shutdown()
            t.join()

        self.addCleanup(_stop)
        t.start()
        return f"http://127.0.0.1:{server.server_address[1]}/x.iso"

    def test_falls_back_to_lseek_write_when_pwrite_absent(self):
        """Removing os.pwrite (Windows) must still download via per-thread writes."""
        data = os.urandom(12 * 1024 * 1024)
        handler = type("OkServer", (_RangeServer,), {"data": data})
        url = self._serve(handler)
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.object(dl.os, "pwrite", None, create=True),
        ):
            part = Path(tmpdir) / "x.iso.part"
            ok = _download_chunked(url, part, len(data), 3, "x.iso")
            self.assertTrue(ok, "download must succeed without os.pwrite")
            self.assertEqual(part.read_bytes(), data, "bytes must match exactly")


# ── Windows: missing gpg binary must surface as ChecksumUnavailable ──────────


class TestMissingGpgBinary(unittest.TestCase):
    """gpg is not installed by default on Windows. verify_iso must report the
    checksum as UNAVAILABLE (keep the file) instead of crashing with an
    unhandled FileNotFoundError from subprocess.run / subprocess.Popen."""

    @patch("visync.verify.shutil.which", return_value=None)
    def test_import_key_then_verify_raises_checksum_unavailable(self, _mock_which):
        from visync.verify import ChecksumUnavailable, _import_key_then_verify

        with self.assertRaises(ChecksumUnavailable):
            _import_key_then_verify(
                Path("/tmp/CHECKSUM"),
                "https://fedoraproject.org/fedora.gpg",
                "DEADBEEF00000000000000000000000000000000",
            )

    @patch("visync.verify._fetch")
    @patch("visync.verify.shutil.which", return_value=None)
    def test_verify_iso_keeps_file_when_gpg_missing(self, _mock_which, _mock_fetch):
        """verify_iso must not raise FileNotFoundError when gpg is missing —
        it should raise ChecksumUnavailable so callers keep the ISO."""
        from visync.verify import ChecksumUnavailable, verify_iso

        _mock_fetch.return_value = "\n".join(
            [
                "-----BEGIN PGP SIGNED MESSAGE-----",
                "Hash: SHA256",
                "",
                "SHA256 (Fedora.iso) = " + "0" * 64,
                "-----BEGIN PGP SIGNATURE-----",
                "sig",
                "-----END PGP SIGNATURE-----",
            ]
        )
        with self.assertRaises(ChecksumUnavailable):
            verify_iso(
                Path("/tmp/Fedora.iso"),
                "https://mirror.example/CHECKSUM",
                algo="sha256",
                checksum_format="gpg_checksum",
                signing_key_url="https://fedoraproject.org/fedora.gpg",
            )


# ── C2: signature authenticity must not depend on the digest layout ───────────


class TestSignatureCheckedForPlainSumsFormat(unittest.TestCase):
    """Parrot's signed-hashes.txt is clearsigned but parsed as plain
    `hash  filename`. verify_iso used to run the GPG check only when
    checksum_format == "gpg_checksum", so Parrot's digests were never
    authenticated at all."""

    @patch("visync.verify._import_key_then_verify")
    @patch("visync.verify._fetch")
    def test_valid_signature_verifies_plain_sums_format(self, mock_fetch, mock_import):
        from visync.verify import verify_iso

        mock_fetch.return_value = "0" * 64 + "  Parrot-security-7.4_amd64.iso\n"
        mock_import.return_value = True

        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "Parrot-security-7.4_amd64.iso"
            iso.write_bytes(b"x" * 64)
            with patch("visync.verify.compute_iso_hash", return_value="0" * 64):
                result = verify_iso(
                    iso,
                    "https://deb.parrotsec.org/parrot/iso/7.4/signed-hashes.txt",
                    algo="sha256",
                    checksum_format="sha256sums",
                    signing_key_url="https://deb.parrot.sh/parrot/misc/archive.gpg",
                    signing_key_fingerprint="B711822346552E4D92DA02DF7A8286AF0E81EE4A",
                )

        mock_import.assert_called_once()
        self.assertTrue(result, "valid signature + matching digest must verify")

    @patch("visync.verify._import_key_then_verify")
    @patch("visync.verify._fetch")
    def test_bad_signature_fails_plain_sums_format(self, mock_fetch, mock_import):
        from visync.verify import verify_iso

        mock_fetch.return_value = "0" * 64 + "  Parrot-security-7.4_amd64.iso\n"
        mock_import.return_value = False

        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "Parrot-security-7.4_amd64.iso"
            iso.write_bytes(b"x" * 64)
            result = verify_iso(
                iso,
                "https://deb.parrotsec.org/parrot/iso/7.4/signed-hashes.txt",
                checksum_format="sha256sums",
                signing_key_url="https://deb.parrot.sh/parrot/misc/archive.gpg",
            )

        self.assertFalse(result, "a rejected signature must not verify")

    @patch("visync.verify._fetch")
    def test_no_signing_key_skips_gpg_entirely(self, mock_fetch):
        """Distros without a signing_key_url must not require gpg at all."""
        from visync.verify import verify_iso

        mock_fetch.return_value = "0" * 64 + "  arch.iso\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "arch.iso"
            iso.write_bytes(b"x" * 64)
            with (
                patch("visync.verify.shutil.which", return_value=None),
                patch("visync.verify.compute_iso_hash", return_value="0" * 64),
            ):
                result = verify_iso(
                    iso,
                    "https://mirror.example/SHA256SUMS",
                    checksum_format="sha256sums",
                    signing_key_url=None,
                )
        self.assertTrue(result, "unsigned sums files still verify without gpg")


# ── C2b: chunked writer must request binary mode on Windows ───────────────────


class TestWindowsTextModeCorruption(unittest.TestCase):
    """os.open() on Windows defaults to TEXT mode unless O_BINARY is passed.

    Writing ISO bytes through a text-mode CRT fd translates every 0x0A into
    0x0D 0x0A — silently corrupting every downloaded distro. The chunked
    writer must OR in O_BINARY (a no-op constant on POSIX).
    """

    def _serve(self, handler_cls):
        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        t = threading.Thread(target=server.serve_forever, daemon=True)

        def _stop():
            server.shutdown()
            t.join()

        self.addCleanup(_stop)
        t.start()
        return f"http://127.0.0.1:{server.server_address[1]}/x.iso"

    def test_chunk_fds_are_binary_not_text(self):
        """Per-thread write fds must be opened with O_BINARY (Windows)."""
        payload = bytearray(os.urandom(12 * 1024 * 1024))
        payload[::4096] = b"\n" * (len(payload) // 4096)  # force 0x0A bytes
        payload = bytes(payload)
        handler = type("OkServer", (_RangeServer,), {"data": payload})
        url = self._serve(handler)

        real_open = dl.os.open
        real_write = dl.os.write
        fake_binary = 0x8000  # Windows _O_BINARY
        text_fds = set()

        def win_open(path, flags, *a, **k):
            fd = real_open(path, flags, *a, **k)
            if not (flags & fake_binary):
                text_fds.add(fd)  # CRT text-mode fd -> newline translation
            return fd

        def win_write(fd, b):
            if fd in text_fds:
                b = b.replace(b"\n", b"\r\n")  # text-mode write inflation
            return real_write(fd, b)

        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.object(dl.os, "O_BINARY", fake_binary, create=True),
            patch.object(dl.os, "pwrite", None, create=True),
            patch.object(dl.os, "open", win_open),
            patch.object(dl.os, "write", win_write),
        ):
            part = Path(tmpdir) / "x.iso.part"
            ok = _download_chunked(url, part, len(payload), 3, "x.iso")
            self.assertTrue(ok, "download must succeed on Windows")
            self.assertEqual(
                part.read_bytes(),
                payload,
                "ISO bytes must survive: text-mode fds would inflate 0x0A -> 0x0D 0x0A",
            )


# ── H1: verification unavailability must not delete downloads ────────────────


class TestDownloadKeepsFileWhenChecksumUnavailable(unittest.TestCase):
    @patch("visync.verify.verify_from_config")
    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_fetch_failure_keeps_download(self, _req, mock_urlopen, mock_verify):
        head = MagicMock()
        head.headers = {"Content-Length": "500"}
        head.__enter__ = lambda s: s
        head.__exit__ = MagicMock(return_value=False)
        body = MagicMock()
        body.headers = {"Content-Length": "500"}
        body.read.side_effect = [b"x" * 500, b""]
        body.__enter__ = lambda s: s
        body.__exit__ = MagicMock(return_value=False)
        mock_urlopen.side_effect = [head, body]
        mock_verify.side_effect = ChecksumUnavailable("mirror unreachable")

        from visync.download import download_iso

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.iso"
            result = download_iso(
                "https://example.com/test.iso",
                dest,
                distro_config={"checksum_url": "https://example.com/SUMS"},
                checksums_config={"enabled": True},
            )
            self.assertTrue(result, "download itself succeeded; unavailable ≠ mismatch")
            self.assertTrue(
                dest.exists(), "file must be kept when checksum unavailable"
            )


class TestDownloadOverwritesExistingDestination(unittest.TestCase):
    """Re-download over an existing ISO must overwrite (Windows-safe atomic move)."""

    @patch("visync.download.urllib.request.urlopen")
    def test_existing_destination_is_overwritten(self, mock_urlopen):
        """PosixPath.rename raises FileExistsError on Windows; replace must be used."""
        head = MagicMock()
        head.headers = {"Content-Length": "500"}
        head.__enter__ = lambda s: s
        head.__exit__ = MagicMock(return_value=False)
        body = MagicMock()
        body.headers = {"Content-Length": "500"}
        body.read.side_effect = [b"x" * 500, b""]
        body.__enter__ = lambda s: s
        body.__exit__ = MagicMock(return_value=False)
        mock_urlopen.side_effect = [head, body]

        from visync.download import download_iso

        real_rename = dl.Path.rename

        def windows_rename(self, target):
            if Path(target).exists():
                raise FileExistsError(17, "File exists", str(target))
            return real_rename(self, target)

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.iso"
            dest.write_bytes(b"stale previous download")
            with patch.object(dl.Path, "rename", windows_rename):
                result = download_iso(
                    "https://example.com/test.iso",
                    dest,
                    distro_config=None,
                    checksums_config=None,
                )
            self.assertTrue(result)
            self.assertEqual(
                dest.read_bytes(),
                b"x" * 500,
                "destination must be replaced, not left stale",
            )


# ── H2: API strategies stash resolved checksums ──────────────────────────────


class TestApiResolvedChecksums(unittest.TestCase):
    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_popos_stashes_sha256(self, mock_fetch, _ping):
        mock_fetch.return_value = json.dumps(
            {
                "url": "https://isos.pop-os.org/pop-os.iso",
                "sha256": "ab" * 32,
            }
        )
        settings = {"strategy": "popos_api"}
        name, _url = dl.process_scraping_strategy("Pop!_OS", settings)
        self.assertEqual(name, "pop-os.iso")
        self.assertEqual(settings.get("resolved_checksum"), "ab" * 32)

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_tails_stashes_target_sha256(self, mock_fetch, _ping):
        mock_fetch.return_value = json.dumps(
            {
                "installations": [
                    {
                        "version": "6.91",
                        "installation-paths": [
                            {
                                "type": "img",
                                "target-files": [
                                    {
                                        "url": "https://tails.net/tails-amd64-6.91.img",
                                        "sha256": "cd" * 32,
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        settings = {"strategy": "tails_api", "api_url": "https://x/latest.json"}
        name, _url = dl.process_scraping_strategy("Tails", settings)
        self.assertEqual(name, "tails-amd64-6.91.img")
        self.assertEqual(settings.get("resolved_checksum"), "cd" * 32)


# ── L2: API filenames are traversal-safe ────────────────────────────────────


class TestSafeFilename(unittest.TestCase):
    def test_backslash_traversal_flattened(self):
        evil = r"..\\..\\Users\\victim\\Startup\\pwned.iso"
        safe = _safe_filename(evil)
        self.assertEqual(safe, "pwned.iso")
        self.assertNotIn("..", safe)
        self.assertNotIn("\\", safe)

    def test_query_and_fragment_stripped(self):
        self.assertEqual(_safe_filename("x.iso?token=abc#frag"), "x.iso")

    def test_dotdot_only_rejected(self):
        self.assertEqual(_safe_filename(".."), "")


class TestScrapeFilenamesAreSanitised(unittest.TestCase):
    """Every strategy that scrapes a filename must run it through _safe_filename.

    direct_match, popos_api and tails_api were checked; the two nested
    directory-walking strategies returned the regex capture verbatim, so a
    listing containing a traversal sequence produced a local path outside the
    download directory — and a name that cleanup later unlinks.

    _safe_filename's policy is to flatten rather than reject, so these assert
    the property that matters: the name stays a single harmless segment.
    """

    def _nested(self, strategy, iso_html, root_html="", **extra):
        settings = {
            "strategy": strategy,
            "base_url": "https://example.com/",
            "iso_regex": 'href="([^"]+)"',
            "version_regex": 'href="([^"]+)/"',
            **extra,
        }
        pages = iter([p for p in (root_html, iso_html) if p] or [iso_html])
        with (
            patch.object(dl, "ping_mirror", return_value=True),
            patch.object(dl, "fetch_html", side_effect=lambda *a, **k: next(pages)),
        ):
            return dl.process_scraping_strategy("X", settings)

    def _assert_single_segment(self, filename, url):
        self.assertNotIn("/", filename)
        self.assertNotIn("\\", filename)
        self.assertNotIn("..", filename)
        # The local destination is download_dir / filename, so a single segment
        # is what keeps the write inside the download directory.
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(Path(tmp, filename).parent, Path(tmp))
        self.assertNotIn("..", url)

    def test_fedora_nested_flattens_traversal_filename(self):
        filename, url = self._nested(
            "fedora_nested",
            '<a href="../../../../etc/cron.d/x.iso">x</a>',
            root_html='<a href="44/">44</a>',
        )
        self.assertEqual(filename, "x.iso")
        self._assert_single_segment(filename, url)

    def test_ubuntu_nested_flattens_traversal_filename(self):
        filename, url = self._nested(
            "ubuntu_nested",
            '<a href="../../../pool/evil.iso">x</a>',
            root_html='<a href="26.04/">26.04</a>',
        )
        self.assertEqual(filename, "evil.iso")
        self._assert_single_segment(filename, url)

    def test_nested_strategies_accept_ordinary_names(self):
        filename, url = self._nested(
            "ubuntu_nested",
            '<a href="ubuntu-26.04.1-desktop-amd64.iso">x</a>',
            root_html='<a href="26.04.1/">26.04.1</a>',
        )
        self.assertEqual(filename, "ubuntu-26.04.1-desktop-amd64.iso")
        self.assertTrue(url.endswith("ubuntu-26.04.1-desktop-amd64.iso"))


class TestSafeVersionSegment(unittest.TestCase):
    """Scraped release directories must stay a single URL segment."""

    def test_plain_version_kept(self):
        self.assertEqual(dl._safe_version_segment("26.04.1"), "26.04.1")
        self.assertEqual(dl._safe_version_segment("44/"), "44")
        self.assertEqual(dl._safe_version_segment("  26.05  "), "26.05")

    def test_traversal_and_separators_rejected(self):
        for bad in (
            "../../pool",
            "26.04/../../pool",
            "26.04\\x",
            "..",
            ".",
            "",
            "26.04?a=b",
            "26.04#frag",
            ".hidden",
        ):
            with self.subTest(bad=bad):
                self.assertEqual(dl._safe_version_segment(bad), "")

    def test_traversing_version_is_not_used_for_the_iso_url(self):
        settings = {
            "strategy": "ubuntu_nested",
            "base_url": "https://example.com/",
            "iso_regex": 'href="([^"]+)"',
            "version_regex": 'href="([^"]+)/"',
        }
        pages = iter(
            [
                '<a href="../../evil/">x</a><a href="26.04/">26.04</a>',
                '<a href="ubuntu.iso">x</a>',
            ]
        )
        with (
            patch.object(dl, "ping_mirror", return_value=True),
            patch.object(dl, "fetch_html", side_effect=lambda *a, **k: next(pages)),
        ):
            filename, url = dl.process_scraping_strategy("X", settings)
        self.assertEqual(filename, "ubuntu.iso")
        self.assertEqual(url, "https://example.com/26.04/ubuntu.iso")


# ── M1: hung mirrors cannot freeze or crash the scrape phase ────────────────


class TestScrapeDeadline(unittest.TestCase):
    def test_deadline_returns_without_joining_hung_workers(self):
        release = threading.Event()

        def hung_check(*a, **k):
            release.wait(10)
            return DistroCheck("X", "X", "", SyncStatus.CURRENT, None)

        config = {"iso": {}, "distros": {"X": {"clean_name": "X"}}}
        orig_deadline = dl.SCRAPE_DEADLINE
        dl.SCRAPE_DEADLINE = 1
        try:
            with (
                patch.object(dl, "_check_distro", side_effect=hung_check),
                patch.object(dl, "visync_watchdog"),
                patch.object(dl, "_sweep_old_versions"),
                patch.object(dl, "load_config", return_value=config),
            ):
                t0 = time.monotonic()
                sync_all_configured_distros(
                    dry_run=True,
                    drive_override=Path(tempfile.gettempdir()),
                    use_buffer=False,
                )
                elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 5, "deadline must not be blocked by hung workers")
        finally:
            dl.SCRAPE_DEADLINE = orig_deadline
            release.set()


# ── M2: remote-controlled text cannot inject rich markup ────────────────────


class TestMarkupEscaping(unittest.TestCase):
    def _capture(self, fn, msg, terminal=False):
        buf = __import__("io").StringIO()
        cap = type(console)(file=buf, force_terminal=terminal, width=200)
        with patch.object(sys.modules["visync.output"], "console", cap):
            fn(msg)
        return buf.getvalue()

    def test_filename_markup_neutralized(self):
        evil = "arch [/bold][red]FAKE ERROR[/red] x.iso"
        for fn in (success, warn, error, info, removed):
            out = self._capture(fn, evil)
            self.assertIn(
                "[red]", out, f"{fn.__name__} must render tags as literal text"
            )

    def test_osc_link_not_emitted_from_filename(self):
        evil = "a.iso [link=https://evil.example]click[/link]"
        raw = self._capture(success, evil, terminal=True)
        self.assertNotIn("\x1b]8;", raw)

    def test_helpers_still_render_own_markup(self):
        raw = self._capture(success, "all good", terminal=True)
        self.assertIn("\x1b[32m", raw, "helper's own green style must survive")


# ── M5: whole-token keyword matching ────────────────────────────────────────


class TestKeywordHit(unittest.TestCase):
    def test_positive_matches(self):
        self.assertTrue(keyword_hit("pop", "pop-os_24.04.iso"))
        self.assertTrue(keyword_hit("pop", "POP OS"))
        self.assertTrue(keyword_hit("nixos-minimal", "nixos minimal stuff"))
        self.assertTrue(keyword_hit("arch", "ARCH LINUX 2026"))

    def test_substring_false_positives_rejected(self):
        self.assertFalse(keyword_hit("pop", "popcorn-time.iso"))
        self.assertFalse(keyword_hit("arch", "patriarch-backup.iso"))
        self.assertFalse(keyword_hit("nixos", "nixosophile.iso"))


# ── L1: thread-count env robustness ─────────────────────────────────────────


class TestThreadCountEnv(unittest.TestCase):
    def test_garbage_falls_back(self):
        with patch.dict(os.environ, {"VISYNC_DOWNLOAD_THREADS": "abc"}):
            self.assertEqual(_download_threads(), 4)

    def test_zero_clamped_to_one(self):
        with patch.dict(os.environ, {"VISYNC_DOWNLOAD_THREADS": "0"}):
            self.assertEqual(_download_threads(), 1)

    def test_huge_clamped_to_max(self):
        with patch.dict(os.environ, {"VISYNC_DOWNLOAD_THREADS": "100000"}):
            self.assertLessEqual(_download_threads(), 16)


# ── L5: hostile installed.json shapes degrade safely; writes are atomic ─────


class TestStateRobustness(unittest.TestCase):
    def test_list_shaped_state_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            drive = Path(tmp)
            (drive / ".visync").mkdir()
            (drive / ".visync" / "installed.json").write_text('["not","a","dict"]')
            self.assertEqual(load_installed(drive), {})

    def test_save_is_atomic_no_tmp_leftovers(self):
        from visync.pm import save_installed

        with tempfile.TemporaryDirectory() as tmp:
            drive = Path(tmp)
            save_installed(drive, {"A": {"version": "1"}})
            leftovers = list((drive / ".visync").glob("*.tmp"))
            self.assertEqual(leftovers, [])
            self.assertEqual(load_installed(drive), {"A": {"version": "1"}})


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ── M4/Fedora: GPG fingerprint pinning accepts lists and enforces VALIDSIG ───


class TestGpgFingerprintPinning(unittest.TestCase):
    def _run_verify(self, pins, validsig):
        """Drive _import_key_then_verify with mocked gpg + key fetch."""
        from visync.verify import _import_key_then_verify

        def fake_run(cmd, **kw):
            r = MagicMock()
            r.returncode = 0
            if "--verify" in cmd:
                r.stdout = f"[GNUPG:] VALIDSIG {validsig} 0 0 1 1 1 sha256\n"
            return r

        with (
            patch("visync.verify.subprocess.run", side_effect=fake_run),
            patch("visync.verify.urlopen") as mu,
            patch("visync.verify.shutil.which", return_value="/usr/bin/gpg"),
        ):
            resp = MagicMock()
            resp.read.return_value = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            mu.return_value = resp
            return _import_key_then_verify(
                Path("/tmp/CHECKSUM"), "https://fedoraproject.org/fedora.gpg", pins
            )

    def test_list_pin_matching(self):
        self.assertTrue(
            self._run_verify(
                [
                    "C6E7F081CF80E13146676E88829B606631645531",
                    "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6",
                ],
                "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6",
            )
        )

    def test_single_string_pin(self):
        self.assertTrue(
            self._run_verify(
                "4F50A6114CD5C6976A7F1179655A4B02F577861E",
                "4f50a6114cd5c6976a7f1179655a4b02f577861e",
            )
        )

    def test_unknown_key_rejected(self):
        self.assertFalse(
            self._run_verify(
                ["C6E7F081CF80E13146676E88829B606631645531"],
                "DEADBEEF00000000000000000000000000000000",
            )
        )

    def test_config_fingerprints_flow_through_config(self):
        from visync.finder import load_config

        cfg = load_config()
        for entry in ("Fedora", "FedoraKDE", "FedoraARM"):
            s = cfg["distros"][entry]
            pins = s.get("signing_key_fingerprint")
            self.assertIsInstance(pins, list) and None
            self.assertGreaterEqual(
                len(pins), 4, f"{entry} should pin the release keys"
            )
            self.assertEqual(s["checksum_format"], "gpg_checksum")
            self.assertIn("signing_key_url", s)


# ── Fedora: version sort survives capture groups that include the slash ──────


class TestNestedVersionSort(unittest.TestCase):
    def _strategy(self, iso_name):
        return {
            "strategy": "fedora_nested",
            "base_url": "https://m/fedora/releases/",
            "version_regex": 'href="([0-9]+\\s*/)"',
            "variant_path": "Workstation/x86_64/iso",
            "iso_regex": 'href="(Fedora-Workstation-Live-(?:x86_64-[0-9][0-9.\\-]*\\.iso|[0-9][0-9.\\-]*\\.x86_64\\.iso))"',
        }

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_trailing_slash_capture_still_picks_max(self, mock_fetch, _ping):
        """Apache lists 7,8,9 after 44 alphabetically; numeric max must win."""
        mock_fetch.side_effect = [
            '<a href="43/"></a><a href="44/"></a><a href="7/"></a><a href="9/">',
            '<a href="Fedora-Workstation-Live-44-1.7.x86_64.iso">x</a>',
        ]
        name, url = dl.process_scraping_strategy("Fedora", self._strategy(None))
        self.assertEqual(name, "Fedora-Workstation-Live-44-1.7.x86_64.iso")
        self.assertIn("/44/", url)


# ── P2: chunked writer enforces range bounds and honest byte accounting ──────


class TestChunkOverflow(unittest.TestCase):
    def test_oversized_range_response_detected(self):
        """Server answering a range with MORE bytes than requested must fail."""
        payload = os.urandom(12 * 1024 * 1024)

        class Greedy(_RangeServer):
            data = payload

            def do_GET(self):
                spec = self.headers.get("Range", "")[6:]
                s, e = spec.split("-")
                s, e = int(s), int(e) + 1
                chunk = payload[s : min(e + 4096, len(payload))]  # 4 KiB extra
                self.send_response(206)
                self.send_header("Content-Length", str(len(chunk)))
                self.end_headers()
                self.wfile.write(chunk)

        server = HTTPServer(("127.0.0.1", 0), Greedy)
        t = threading.Thread(target=server.serve_forever, daemon=True)

        def _stop():
            server.shutdown()
            t.join()

        self.addCleanup(_stop)
        t.start()
        url = f"http://127.0.0.1:{server.server_address[1]}/x.iso"
        with tempfile.TemporaryDirectory() as tmpdir:
            part = Path(tmpdir) / "x.iso.part"
            ok = _download_chunked(url, part, len(payload), 3, "x.iso")
            self.assertFalse(ok, "oversized response must fail the download")
            if part.exists():
                self.assertLessEqual(part.stat().st_size, len(payload))


class TestContentRangeValidation(unittest.TestCase):
    """A 206 status alone does not prove the body is the requested range.

    A server that answers every Range with the same 206 slice would otherwise
    assemble a full-size file from duplicated chunks and satisfy every
    byte-count check — silent corruption wherever no checksum is configured.
    """

    def _serve(self, handler_cls):
        server = HTTPServer(("127.0.0.1", 0), handler_cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)

        def _stop():
            server.shutdown()
            thread.join()

        self.addCleanup(_stop)
        thread.start()
        return f"http://127.0.0.1:{server.server_address[1]}/x.iso"

    def test_wrong_content_range_fails(self):
        payload = os.urandom(12 * 1024 * 1024)
        handler = type(
            "WrongRange",
            (_RangeServer,),
            {
                "data": payload,
                # Every chunk claims to be the first one.
                "content_range_fn": lambda s, e: "bytes 0-4194303/12582912",
            },
        )
        url = self._serve(handler)
        with tempfile.TemporaryDirectory() as tmpdir:
            part = Path(tmpdir) / "x.iso.part"
            ok = _download_chunked(url, part, len(payload), 3, "x.iso")
            self.assertFalse(ok, "a mismatched Content-Range must fail the download")

    def test_missing_content_range_fails(self):
        payload = os.urandom(12 * 1024 * 1024)
        handler = type(
            "NoRange",
            (_RangeServer,),
            {"data": payload, "content_range_fn": lambda s, e: _RangeServer.OMIT},
        )
        url = self._serve(handler)
        with tempfile.TemporaryDirectory() as tmpdir:
            part = Path(tmpdir) / "x.iso.part"
            ok = _download_chunked(url, part, len(payload), 3, "x.iso")
            self.assertFalse(ok, "a 206 with no Content-Range must fail the download")

    def test_malformed_content_range_fails(self):
        payload = os.urandom(12 * 1024 * 1024)
        handler = type(
            "JunkRange",
            (_RangeServer,),
            {"data": payload, "content_range_fn": lambda s, e: "bytes all of it"},
        )
        url = self._serve(handler)
        with tempfile.TemporaryDirectory() as tmpdir:
            part = Path(tmpdir) / "x.iso.part"
            ok = _download_chunked(url, part, len(payload), 3, "x.iso")
            self.assertFalse(ok, "an unparsable Content-Range must fail")

    def test_correct_content_range_still_succeeds(self):
        """The new check must not break well-behaved servers."""
        payload = os.urandom(12 * 1024 * 1024)
        handler = type("GoodRange", (_RangeServer,), {"data": payload})
        url = self._serve(handler)
        with tempfile.TemporaryDirectory() as tmpdir:
            part = Path(tmpdir) / "x.iso.part"
            ok = _download_chunked(url, part, len(payload), 3, "x.iso")
            self.assertTrue(ok, "an honest range server must still succeed")
            self.assertEqual(part.read_bytes(), payload, "bytes must match exactly")


# ── P1: non-HTTPS download URL fails that distro, not the whole run ─────────


class TestInsecureUrlGracefulSkip(unittest.TestCase):
    def test_http_url_skips_without_crashing(self):
        config = {
            "iso": {},
            "distros": {
                "X": {
                    "strategy": "direct_match",
                    "base_url": "http://insecure.example/",
                }
            },
        }
        with (
            patch.object(dl, "load_config", return_value=config),
            patch.object(dl, "visync_watchdog"),
            patch.object(dl, "_sweep_old_versions"),
            patch.object(dl, "ping_mirror", return_value=True),
            patch.object(dl, "fetch_html", return_value='<a href="evil.iso">x</a>'),
        ):
            # Must not raise; the http:// URL is rejected per-distro
            result = sync_all_configured_distros(
                dry_run=False,
                drive_override=Path(tempfile.gettempdir()),
                use_buffer=False,
            )
        self.assertIsNotNone(result)


# ── P4: VALIDSIG accepts primary-key fingerprint (subkey signers) ────────────


class TestValidSigPrimaryField(unittest.TestCase):
    def _run(self, stdout):
        from visync.verify import _import_key_then_verify

        def fake_run(cmd, **kw):
            r = MagicMock()
            r.returncode = 0
            if "--verify" in cmd:
                r.stdout = stdout
            return r

        with (
            patch("visync.verify.subprocess.run", side_effect=fake_run),
            patch("visync.verify.urlopen") as mu,
            patch("visync.verify.shutil.which", return_value="/usr/bin/gpg"),
        ):
            resp = MagicMock()
            resp.read.return_value = b"key"
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            mu.return_value = resp
            return _import_key_then_verify(
                Path("/tmp/CHECKSUM"),
                "https://fedoraproject.org/fedora.gpg",
                ["C6E7F081CF80E13146676E88829B606631645531"],
            )

    def test_subkey_sig_accepted_via_primary_field(self):
        stdout = (
            "[GNUPG:] NEWSIG\n"
            "[GNUPG:] KEY_CONSIDERED C6E7F081CF80E13146676E88829B606631645531 0\n"
            "[GNUPG:] VALIDSIG AABB00000000000000000000000000000000CCDD "
            "2026-01-01 0 pi 1 1 1 01 "
            "C6E7F081CF80E13146676E88829B606631645531\n"
        )
        self.assertTrue(
            self._run(stdout), "subkey signer must be accepted via primary-fpr field"
        )

    def test_wrong_primary_rejected(self):
        stdout = (
            "[GNUPG:] VALIDSIG AABB00000000000000000000000000000000CCDD "
            "2026-01-01 0 pi 1 1 1 01 "
            "DEAD00000000000000000000000000000000BEEF\n"
        )
        self.assertFalse(self._run(stdout))


# ── S1: scalar metadata JSON must degrade, not crash metadata consumers ──────


class TestHostileMetadataShapes(unittest.TestCase):
    def test_scalar_metadata_ignored(self):
        from visync.finder import load_all_metadata

        with tempfile.TemporaryDirectory() as tmp:
            drive = Path(tmp)
            meta = drive / ".visync" / "metadata"
            meta.mkdir(parents=True)
            (meta / "weird.iso.json").write_text("5")
            (meta / "bool.iso.json").write_text("true")
            (meta / "good.iso.json").write_text('{"variant_stem": "x", "version": "1"}')
            result = load_all_metadata(drive)
        self.assertEqual(list(result.keys()), ["good.iso"])


# ── S2: watchdog deep-clean skips non-json instead of aborting the sync ──────


class TestWatchdogSkipsNonJson(unittest.TestCase):
    def test_deep_clean_survives_stray_iso_in_metadata(self):
        from visync.finder import _deep_clean_metadata

        with tempfile.TemporaryDirectory() as tmp:
            drive = Path(tmp)
            meta = drive / ".visync" / "metadata"
            meta.mkdir(parents=True)
            stray = meta / "planted.iso"
            stray.write_bytes(b"\x00" * 64)
            orphan = meta / "gone.iso.json"
            orphan.write_text('{"variant_stem": "x", "version": "1"}')

            _deep_clean_metadata(drive)

            self.assertFalse(orphan.exists(), "orphaned json should be cleaned")
            self.assertTrue(stray.exists(), "non-json must never be deleted")

    def _over_budget_drive(self, tmp: str) -> tuple[Path, Path]:
        """Build a drive whose .visync/ exceeds the ceiling via un-wipeable ballast.

        A non-.json ballast file is used deliberately: it survives stage 1's deep
        clean, which is what forces the stage-2 decision.
        """
        from visync.finder import VISYNC_SIZE_LIMIT

        drive = Path(tmp)
        visync_dir = drive / ".visync"
        (visync_dir / "metadata").mkdir(parents=True)
        (visync_dir / "metadata" / "gone.iso.json").write_text("{}")
        (visync_dir / "ballast.bin").write_bytes(b"\0" * (VISYNC_SIZE_LIMIT + 1))
        keeper = drive / "archlinux-2026.iso"
        keeper.write_bytes(b"\x00" * 64)
        return drive, keeper

    def test_watchdog_default_does_not_wipe(self):
        """Over budget without --reset-visync must NOT destroy .visync/ (C4)."""
        from visync.finder import visync_watchdog

        with tempfile.TemporaryDirectory() as tmp:
            drive, keeper = self._over_budget_drive(tmp)
            visync_dir = drive / ".visync"

            visync_watchdog(drive)

            self.assertTrue(visync_dir.exists(), "wipe must be opt-in")
            self.assertTrue(keeper.exists(), "drive content outside .visync untouched")

    def test_watchdog_wipes_only_when_opted_in(self):
        """allow_wipe=True removes .visync contents but nothing outside it."""
        from visync.finder import visync_watchdog

        with tempfile.TemporaryDirectory() as tmp:
            drive, keeper = self._over_budget_drive(tmp)
            visync_dir = drive / ".visync"

            visync_watchdog(drive, allow_wipe=True)

            self.assertFalse(visync_dir.exists(), "opted-in wipe must remove .visync")
            self.assertTrue(keeper.exists(), "drive content outside .visync untouched")

    def test_dry_run_sync_never_runs_the_watchdog(self):
        """--dry-run must leave .visync/ (and installed.json) byte-for-byte intact."""
        from visync.download import sync_all_configured_distros
        from visync.finder import VISYNC_SIZE_LIMIT

        with tempfile.TemporaryDirectory() as tmp:
            drive, _keeper = self._over_budget_drive(tmp)
            visync_dir = drive / ".visync"
            installed = visync_dir / "installed.json"
            installed.write_text('{"ArchLinux": {"version": "2026.01.01"}}')
            cfg = {
                "iso": {},
                "checksums": {"enabled": False},
                "distros": {"ArchLinux": {"clean_name": "Arch Linux"}},
            }

            with (
                patch("visync.download.load_config", return_value=cfg),
                patch("visync.download._sweep_old_versions"),
                patch("visync.download._check_distro") as check,
            ):
                check.return_value = DistroCheck(
                    "ArchLinux", "Arch Linux", "a.iso", SyncStatus.CURRENT, None
                )
                sync_all_configured_distros(
                    dry_run=True,
                    only=["ArchLinux"],
                    drive_override=drive,
                    use_buffer=False,
                    reset_visync=True,  # even asked for, dry-run must not wipe
                )

            self.assertTrue(visync_dir.exists(), "dry-run must not delete .visync")
            self.assertTrue(
                installed.exists(), "dry-run must not delete installed.json"
            )
            self.assertEqual(
                (visync_dir / "metadata" / "gone.iso.json").exists(),
                True,
                "dry-run must not even deep-clean orphaned metadata",
            )
            self.assertTrue(
                (visync_dir / "ballast.bin").stat().st_size > VISYNC_SIZE_LIMIT,
                "ballast must be untouched",
            )

    def test_watchdog_deep_cleans_orphans_without_opting_in(self):
        """Stage 1 still runs unattended and reclaims orphaned metadata."""
        from visync.finder import VISYNC_SIZE_LIMIT, visync_watchdog

        with tempfile.TemporaryDirectory() as tmp:
            drive = Path(tmp)
            visync_dir = drive / ".visync"
            (visync_dir / "metadata").mkdir(parents=True)
            orphan = visync_dir / "metadata" / "gone.iso.json"
            orphan.write_text('{"variant_stem": "x", "version": "1"}')
            # Padding that pushes us over the ceiling but is itself removable.
            for i in range(12):
                (visync_dir / f"pad{i}.json").write_text(
                    '{"variant_stem": "x", "version": "1"}'
                )
            assert _dir_size(visync_dir) < VISYNC_SIZE_LIMIT

            with patch("visync.finder.VISYNC_SIZE_LIMIT", 1):
                visync_watchdog(drive)

            self.assertFalse(orphan.exists(), "orphaned metadata must be deep-cleaned")
            self.assertTrue(visync_dir.exists(), "deep clean must not wipe the dir")


# ── Upstream selection: LTS filter + dynamic NixOS stable channel ─────────────


class TestUbuntuLtsVersionFilter(unittest.TestCase):
    """releases.ubuntu.com lists interim releases too, and during a beta cycle
    the newest directory contains only `-beta-` ISOs, so the regex matched
    nothing and Ubuntu Server/Desktop silently stopped updating."""

    INDEX = (
        '<a href="14.04/">x</a><a href="14.04.6/">x</a><a href="16.04/">x</a>'
        '<a href="18.04/">x</a><a href="20.04/">x</a><a href="20.04.6/">x</a>'
        '<a href="22.04/">x</a><a href="22.04.5/">x</a><a href="24.04/">x</a>'
        '<a href="24.04.5/">x</a><a href="25.10/">x</a><a href="26.04/">x</a>'
        '<a href="26.04.1/">x</a><a href="26.10/">x</a>'
    )

    def _strategy(self, iso_regex, filter_regex):
        return {
            "strategy": "ubuntu_nested",
            "base_url": "https://releases.ubuntu.com/",
            "version_regex": r'href="([0-9\.]+)/"',
            "version_filter": filter_regex,
            "iso_regex": iso_regex,
        }

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_picks_newest_lts_not_newest_release(self, mock_fetch, _ping):
        mock_fetch.side_effect = [
            self.INDEX,
            '<a href="ubuntu-26.04.1-desktop-amd64.iso">x</a>',
        ]
        name, url = dl.process_scraping_strategy(
            "Ubuntu Desktop",
            self._strategy(
                r'href="(ubuntu-[0-9\.-]+desktop-amd64\.iso)"',
                r"\d*[02468]\.04(\.\d+)*",
            ),
        )
        self.assertEqual(name, "ubuntu-26.04.1-desktop-amd64.iso")
        self.assertIn("/26.04.1/", url)
        print("interim 25.10/26.10 skipped, newest LTS 26.04.1 chosen")

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_lts_filter_rejects_interim_only_release(self, mock_fetch, _ping):
        """A filter matching nothing must fail closed, not fall back."""
        mock_fetch.return_value = self.INDEX
        settings = self._strategy(
            r'href="(ubuntu-[0-9\.-]+desktop-amd64\.iso)"', r"99\.99"
        )
        dl.process_scraping_strategy("Ubuntu Desktop", settings)
        self.assertIn("version_filter", settings.get("resolve_error", ""))
        print("empty filter result reported, no fallback to 26.10")

    def test_shipped_ubuntu_filter_is_lts_only(self):
        """Guard the real config: both Ubuntu entries must be LTS-pinned."""
        cfg = load_config()
        for key in ("UbuntuDesktop", "UbuntuServer"):
            with self.subTest(entry=key):
                entry = cfg["distros"][key]
                self.assertIn("version_filter", entry)
                pattern = entry["version_filter"]
                for version, expect in [
                    ("26.04.1", True),
                    ("24.04", True),
                    ("26.10", False),
                    ("25.10", False),
                    ("25.04", False),
                    ("26.04.1-beta", False),
                ]:
                    self.assertEqual(
                        bool(re.fullmatch(pattern, version)),
                        expect,
                        f"{key}: {version} should "
                        f"{'match' if expect else 'not match'} {pattern!r}",
                    )
        print("shipped version_filter accepts only even-year .04 LTS series")


class TestNixosStableChannelDiscovery(unittest.TestCase):
    """NixOS publishes no nixos-stable alias, so the current stable channel is
    derived from the release bucket. It must fail closed rather than guess."""

    LISTING = "".join(
        f"<Prefix>nixos/{v}/</Prefix>"
        for v in (
            "20.09",
            "20.09-aarch64",
            "24.11",
            "25.05",
            "25.11",
            "26.05",
            "26.05-aarch64",
            "26.05-small",
        )
    )

    def test_picks_newest_stable_excluding_small_and_aarch64(self):
        with patch.object(dl, "fetch_html", return_value=self.LISTING):
            channel, err = dl._nixos_stable_channel({})
        self.assertEqual(channel, "26.05")
        self.assertEqual(err, "")
        print("-small and -aarch64 trees ignored")

    def test_future_channel_wins_when_newer(self):
        listing = "<Prefix>nixos/26.05/</Prefix><Prefix>nixos/26.11/</Prefix>"
        with patch.object(dl, "fetch_html", return_value=listing):
            channel, _ = dl._nixos_stable_channel({})
        self.assertEqual(channel, "26.11", "must track a new stable automatically")

    def test_channel_pin_wins_while_still_real(self):
        with patch.object(dl, "fetch_html", return_value=self.LISTING):
            channel, _ = dl._nixos_stable_channel({"channel": "25.11"})
        self.assertEqual(channel, "25.11")

    def test_retired_channel_pin_falls_back(self):
        listing = "<Prefix>nixos/26.05/</Prefix>"
        with patch.object(dl, "fetch_html", return_value=listing):
            channel, _ = dl._nixos_stable_channel({"channel": "19.04"})
        self.assertEqual(channel, "26.05")

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html", return_value="")
    def test_unreachable_listing_is_reported(self, _fetch, _ping):
        settings = {
            "strategy": "nixos_channel",
            "base_url": "https://channels.nixos.org/nixos",
        }
        dl.process_scraping_strategy("NixOS", settings)
        self.assertIn("release listing", settings.get("resolve_error", ""))
        print("listing failure surfaces, no channel guessed")

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html", return_value="<html>nothing useful</html>")
    def test_listing_without_channels_is_reported(self, _fetch, _ping):
        settings = {
            "strategy": "nixos_channel",
            "base_url": "https://channels.nixos.org/nixos",
        }
        dl.process_scraping_strategy("NixOS", settings)
        self.assertIn("channels", settings.get("resolve_error", ""))

    @patch("visync.download.ping_mirror", return_value=True)
    @patch(
        "visync.download.fetch_html",
        return_value="<Prefix>nixos/99.99/</Prefix><Prefix>nixos/26.05/</Prefix>",
    )
    def test_implausible_channel_is_refused(self, _fetch, _ping):
        settings = {
            "strategy": "nixos_channel",
            "base_url": "https://channels.nixos.org/nixos",
        }
        dl.process_scraping_strategy("NixOS", settings)
        self.assertIn("implausible", settings.get("resolve_error", ""))
        print("bogus listing cannot redirect the download URL")

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_channel_release_mismatch_is_refused(self, mock_fetch, _ping):
        """If the channel page names a different series, stop."""
        listing = "<Prefix>nixos/26.05/</Prefix>"
        page = "nixos-25.11 release nixos-25.11.12484.b6018f87da91 released 2026-01-01"

        def _fetch(url):
            return listing if "s3.amazonaws" in url else page

        mock_fetch.side_effect = _fetch
        settings = {
            "strategy": "nixos_channel",
            "base_url": "https://channels.nixos.org/nixos",
            "variant": "graphical",
        }
        dl.process_scraping_strategy("NixOS", settings)
        self.assertIn("mismatch", settings.get("resolve_error", ""))


class TestNixosChecksumUrls(unittest.TestCase):
    """The .sha256 sidecars live under releases.nixos.org, not the channel host,
    and need both the channel and the full release id in the path."""

    RELEASE = "26.05.11045.774debe7a0d1"

    def test_expands_to_real_sidecar_path(self):
        iso = f"nixos-graphical-{self.RELEASE}-x86_64-linux.iso"
        url = expand_url(
            "{release_base_url}/nixos/{version}/nixos-{release}/{iso_name}.sha256",
            iso,
            "https://channels.nixos.org/nixos",
            "https://releases.nixos.org",
        )
        self.assertEqual(
            url,
            f"https://releases.nixos.org/nixos/26.05/nixos-{self.RELEASE}/{iso}.sha256",
        )

    def test_metadata_recovers_channel_and_release(self):
        for variant in ("minimal", "graphical"):
            with self.subTest(variant=variant):
                meta = extract_iso_metadata(
                    f"nixos-{variant}-{self.RELEASE}-x86_64-linux.iso"
                )
                self.assertEqual(meta["channel"], "26.05")
                self.assertEqual(meta["release"], self.RELEASE)

    def test_non_nixos_iso_leaves_channel_empty(self):
        meta = extract_iso_metadata("archlinux-2026.10.01-x86_64.iso")
        self.assertEqual(meta["channel"], "")
        self.assertEqual(meta["release"], "")

    def test_shipped_nixos_entries_use_releases_host(self):
        cfg = load_config()
        for key in ("NixOS", "NixOSGraphical"):
            with self.subTest(entry=key):
                entry = cfg["distros"][key]
                self.assertEqual(
                    entry.get("releases_base_url"), "https://releases.nixos.org"
                )
                self.assertIn("{release_base_url}", entry["checksum_url"])
                iso = f"nixos-{entry['variant']}-{self.RELEASE}-x86_64-linux.iso"
                url = expand_url(
                    entry["checksum_url"],
                    iso,
                    entry["base_url"],
                    entry.get("releases_base_url", ""),
                )
                self.assertTrue(url.startswith("https://releases.nixos.org/"))
                self.assertNotIn("{", url, "no placeholder left unexpanded")
        print("NixOS checksums resolve to releases.nixos.org")


class TestRemovedDistros(unittest.TestCase):
    def test_omarchy_absent_from_config(self):
        cfg = load_config()
        self.assertNotIn(
            "Omarchy", cfg.get("distros", {}), "Omarchy entry must be removed"
        )

    def test_omarchy_removal_is_documented_in_place(self):
        """Follows the Arch Linux ARM precedent: a NOTE explaining why."""
        text = (
            Path(__file__).resolve().parent.parent.joinpath("config.toml").read_text()
        )
        self.assertIn("NOTE: Omarchy was removed", text)
        self.assertIn("iso.omarchy.org", text)
        print("removal records the reason and a re-add condition")


# ── Distro identity: variant keys and config/name consistency ────────────────

ISO_VID = 32808


def _make_iso(path: Path, volume_id: str = "", size: int = 4096) -> Path:
    """Write a file carrying an ISO 9660 volume ID at the PVD offset.

    *size* must exceed ISO_VID or the label is written past the buffer end and
    the resulting file reads back as having no volume ID.
    """
    size = max(size, ISO_VID + 64)
    buf = bytearray(size)
    label = volume_id.encode("ascii")[:32]
    if label:
        buf[ISO_VID : ISO_VID + len(label)] = label
    path.write_bytes(bytes(buf))
    return path


class TestVariantKey(unittest.TestCase):
    """_variant_stem and _filename_variant_key disagreed about architecture
    tokens, so a volume-ID key never matched its own filename. That silently
    disabled old-version cleanup for Pop!_OS. Unified into variant_key()."""

    def test_arch_and_version_tokens_are_stripped(self):
        from visync.download import variant_key

        cases = {
            "Pop_OS 24.04 amd64": "pop-os",
            "ARCH_202610": "arch",
            "OMARCHY_202608": "omarchy",
            "Fedora-E-dvd-x86_64-44": "fedora-e-dvd",
            "Fedora-KDE-Live-44": "fedora-kde-live",
            "Ubuntu-Server 26.04.1 LTS amd64": "ubuntu-server",
            "pop-os_24.04_amd64_generic_24.iso": "pop-os-generic",
            "archlinux-2026.10.01-x86_64.iso": "archlinux",
            "tails-amd64-7.14.img": "tails",
            "ipxe.iso": "ipxe",
        }
        for raw, expected in cases.items():
            with self.subTest(text=raw):
                self.assertEqual(variant_key(raw), expected)

    def test_arch_token_after_underscore_is_stripped(self):
        """amd64 glued to underscores must still be recognised."""
        from visync.download import variant_key

        self.assertNotIn("amd64", variant_key("pop-os_24.04_amd64_generic_24.iso"))

    def test_thin_aliases_agree(self):
        from visync.download import _filename_variant_key, _variant_stem, variant_key

        for raw in ("Fedora-KDE-Live-44", "tails-amd64-7.14.img"):
            with self.subTest(text=raw):
                self.assertEqual(_variant_stem(raw), variant_key(raw))
                self.assertEqual(_filename_variant_key(raw), variant_key(raw))

    def test_distinct_variants_stay_distinct(self):
        from visync.download import variant_key

        pairs = [
            ("Ubuntu 26.04.1 LTS amd64", "Ubuntu-Server 26.04.1 LTS amd64"),
            ("Fedora-E-dvd-x86_64-44", "Fedora-KDE-Live-44"),
        ]
        for a, b in pairs:
            with self.subTest(pair=(a, b)):
                self.assertNotEqual(variant_key(a), variant_key(b))

    def test_prefix_filter_matches_pop_os_vid_against_filename(self):
        """The bug this fixes: 'pop_os' vs 'pop-os' rejected every candidate."""
        from visync.download import same_variant_prefix, variant_key

        vid_key = variant_key("Pop_OS 24.04 amd64")
        name_key = variant_key("pop-os_24.03_amd64_generic_23.iso")
        self.assertTrue(same_variant_prefix(vid_key, name_key))

    def test_prefix_filter_still_permissive_for_arch(self):
        """Volume key 'arch' vs filename key 'archlinux' must still proceed."""
        from visync.download import same_variant_prefix, variant_key

        self.assertTrue(
            same_variant_prefix(
                variant_key("ARCH_202610"),
                variant_key("archlinux-2026.09.01-x86_64.iso"),
            )
        )

    def test_prefix_filter_rejects_unrelated(self):
        from visync.download import same_variant_prefix

        self.assertFalse(same_variant_prefix("fedora-kde-live", "archlinux"))

    def test_empty_keys_are_permissive(self):
        from visync.download import same_variant_prefix

        self.assertTrue(same_variant_prefix("", "anything"))


class TestCleanupDeletionSafety(unittest.TestCase):
    """Deletion-focused: cleanup runs unlink(), so these pin the decisions."""

    def _drive(self, tmpdir: str) -> Path:
        return Path(tmpdir)

    def test_cleanup_removes_older_pop_os_build(self):
        """Pop!_OS cleanup was fully broken; this is the regression."""
        from visync.download import _cleanup_old_versions

        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._drive(tmpdir)
            old = _make_iso(
                drive / "pop-os_24.03_amd64_generic_23.iso", "Pop_OS 24.03 amd64"
            )
            new = _make_iso(
                drive / "pop-os_24.04_amd64_generic_24.iso", "Pop_OS 24.04 amd64"
            )

            _cleanup_old_versions(new, drive)

            self.assertFalse(old.exists(), "older Pop!_OS build must be removed")
            self.assertTrue(new.exists(), "newest build must survive")

    def test_cleanup_keeps_different_variants(self):
        """Desktop and server must never be treated as the same variant."""
        from visync.download import _cleanup_old_versions

        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._drive(tmpdir)
            server = _make_iso(
                drive / "ubuntu-26.04.1-live-server-amd64.iso",
                "Ubuntu-Server 26.04.1 LTS amd64",
            )
            desktop = _make_iso(
                drive / "ubuntu-26.04.1-desktop-amd64.iso",
                "Ubuntu 26.04.1 LTS amd64",
            )
            _cleanup_old_versions(desktop, drive)
            self.assertTrue(server.exists(), "live-server ISO must survive")
            self.assertTrue(desktop.exists())

    def test_cleanup_keeps_fedora_netinst_and_kde(self):
        from visync.download import _cleanup_old_versions

        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._drive(tmpdir)
            netinst = _make_iso(
                drive / "Fedora-Everything-netinst-x86_64-44-1.7.iso",
                "Fedora-E-dvd-x86_64-44",
            )
            kde = _make_iso(
                drive / "Fedora-KDE-Desktop-Live-44-1.7.x86_64.iso",
                "Fedora-KDE-Live-44",
            )
            _cleanup_old_versions(kde, drive)
            self.assertTrue(
                netinst.exists(), "netinst must not be swept by KDE cleanup"
            )
            self.assertTrue(kde.exists())

    def test_cleanup_removes_older_build_of_same_variant(self):
        from visync.download import _cleanup_old_versions

        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._drive(tmpdir)
            old = _make_iso(
                drive / "Fedora-KDE-Desktop-Live-43-1.6.x86_64.iso",
                "Fedora-KDE-Live-43",
            )
            new = _make_iso(
                drive / "Fedora-KDE-Desktop-Live-44-1.7.x86_64.iso",
                "Fedora-KDE-Live-44",
            )
            _cleanup_old_versions(new, drive)
            self.assertFalse(old.exists())
            self.assertTrue(new.exists())

    def test_cleanup_never_touches_unidentified_isos(self):
        from visync.download import _cleanup_old_versions

        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._drive(tmpdir)
            keeper = _make_iso(drive / "mystery-boot-2026.iso")
            new = _make_iso(
                drive / "Fedora-KDE-Desktop-Live-44-1.7.x86_64.iso",
                "Fedora-KDE-Live-44",
            )
            _cleanup_old_versions(new, drive)
            self.assertTrue(keeper.exists(), "unidentifiable ISO must survive")

    def test_sweep_groups_by_variant_and_keeps_newest(self):
        from visync.download import _sweep_old_versions

        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._drive(tmpdir)
            f43 = _make_iso(
                drive / "Fedora-Workstation-Live-x86_64-43-1.6.iso",
                "Fedora-E-dvd-x86_64-43",
            )
            f44 = _make_iso(
                drive / "Fedora-Workstation-Live-x86_64-44-1.7.iso",
                "Fedora-E-dvd-x86_64-44",
            )
            kde = _make_iso(
                drive / "Fedora-KDE-Desktop-Live-44-1.7.x86_64.iso",
                "Fedora-KDE-Live-44",
            )
            _sweep_old_versions(drive, clean=True)
            self.assertFalse(f43.exists())
            self.assertTrue(f44.exists())
            self.assertTrue(kde.exists())

    def test_sweep_dry_run_deletes_nothing(self):
        from visync.download import _sweep_old_versions

        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._drive(tmpdir)
            f43 = _make_iso(
                drive / "Fedora-Workstation-Live-x86_64-43-1.6.iso",
                "Fedora-E-dvd-x86_64-43",
            )
            _make_iso(
                drive / "Fedora-Workstation-Live-x86_64-44-1.7.iso",
                "Fedora-E-dvd-x86_64-44",
            )
            _sweep_old_versions(drive, clean=False)
            self.assertTrue(f43.exists())


class TestConfigNameConsistency(unittest.TestCase):
    """install/remove match an identified distro against clean_name, so every
    configured clean_name must be reachable from identify_distro."""

    SAMPLES: ClassVar[dict[str, tuple[str, str]]] = {
        "Fedora": (
            "Fedora-E-dvd-x86_64-44",
            "Fedora-Everything-netinst-x86_64-44-1.7.iso",
        ),
        "FedoraKDE": (
            "Fedora-KDE-Live-44",
            "Fedora-KDE-Desktop-Live-44-1.7.x86_64.iso",
        ),
        "FedoraARM": (
            "Fedora-Workstation-Live-aarch64-44",
            "Fedora-Workstation-Live-44-1.7.aarch64.iso",
        ),
        "ArchLinux": ("ARCH_202610", "archlinux-2026.10.01-x86_64.iso"),
        "UbuntuServer": (
            "Ubuntu-Server 26.04.1 LTS amd64",
            "ubuntu-26.04.1-live-server-amd64.iso",
        ),
        "UbuntuDesktop": (
            "Ubuntu 26.04.1 LTS amd64",
            "ubuntu-26.04.1-desktop-amd64.iso",
        ),
        "ParrotSecurity": ("Parrot", "Parrot-security-7.4_amd64.iso"),
        "NixOS": ("NIXOS_26.05_x86_64", "nixos-minimal-26.05.11045-x86_64-linux.iso"),
        "NixOSGraphical": (
            "NIXOS_26.05_x86_64",
            "nixos-graphical-26.05.11045-x86_64-linux.iso",
        ),
        "PopOS": ("Pop_OS 24.04 amd64", "pop-os_24.04_amd64_generic_24.iso"),
        "Tails": ("", "tails-amd64-7.14.img"),
    }

    def test_every_clean_name_is_identifiable(self):
        from visync.finder import identify_distro

        cfg = load_config()
        for entry_id, settings in sorted(cfg["distros"].items()):
            with self.subTest(entry=entry_id):
                self.assertIn(entry_id, self.SAMPLES, "add a sample for this entry")
                vid, filename = self.SAMPLES[entry_id]
                self.assertEqual(
                    identify_distro(vid, filename),
                    settings["clean_name"],
                    f"{entry_id}: identify_distro must return clean_name "
                    f"{settings['clean_name']!r} or install/remove cannot target it",
                )

    def test_fedora_x86_is_not_labelled_arm(self):
        from visync.finder import identify_distro

        self.assertEqual(
            identify_distro(
                "Fedora-E-dvd-x86_64-44", "Fedora-Everything-netinst-x86_64-44-1.7.iso"
            ),
            "Fedora",
        )
        self.assertEqual(
            identify_distro(
                "Fedora-Workstation-Live-x86_64-44",
                "Fedora-Workstation-Live-44-1.7.x86_64.iso",
            ),
            "Fedora",
        )

    def test_ubuntu_desktop_and_server_are_distinct(self):
        from visync.finder import identify_distro

        self.assertEqual(
            identify_distro(
                "Ubuntu 26.04.1 LTS amd64", "ubuntu-26.04.1-desktop-amd64.iso"
            ),
            "Ubuntu Desktop",
        )
        self.assertEqual(
            identify_distro(
                "Ubuntu-Server 26.04.1 LTS amd64",
                "ubuntu-26.04.1-live-server-amd64.iso",
            ),
            "Ubuntu Server",
        )

    def test_standalone_specificity_does_not_depend_on_toml_order(self):
        """Specificity is decided by keyword length, not config line order."""
        from visync import finder

        cfg = finder.load_config()
        generic = {"nixos", "nixos-minimal", "nixos-graphical"}
        reordered = {k: v for k, v in cfg["standalone_matches"].items() if k in generic}
        reordered = dict(sorted(reordered.items(), key=lambda kv: len(kv[0])))
        reordered.update(
            {k: v for k, v in cfg["standalone_matches"].items() if k not in generic}
        )
        cfg["standalone_matches"] = reordered
        finder._CONFIG_CACHE = cfg
        try:
            self.assertEqual(
                finder.identify_distro(
                    "NIXOS_26.05_x86_64", "nixos-graphical-26.05-x86_64-linux.iso"
                ),
                "NixOS Graphical",
            )
            self.assertEqual(
                finder.identify_distro(
                    "NIXOS_26.05_x86_64", "nixos-minimal-26.05-x86_64-linux.iso"
                ),
                "NixOS Minimal",
            )
        finally:
            finder._CONFIG_CACHE = None


class TestQueryNormalisation(unittest.TestCase):
    def test_separator_styles_resolve_to_one_entry(self):
        from visync.pm import resolve_distro

        cfg = load_config()
        for query in (
            "ubuntu-desktop",
            "ubuntu_desktop",
            "Ubuntu Desktop",
            "UbuntuDesktop",
            "ubuntudesktop",
        ):
            with self.subTest(query=query):
                self.assertEqual(resolve_distro(query, cfg), "UbuntuDesktop")

    def test_ambiguous_queries_are_still_refused(self):
        from visync.pm import matching_distros

        cfg = load_config()
        for query in ("ubuntu", "u"):
            with self.subTest(query=query):
                entry_id, partials = matching_distros(query, cfg)
                self.assertIsNone(entry_id)
                self.assertGreater(len(partials), 1)

    def test_empty_query_returns_nothing(self):
        from visync.pm import matching_distros, resolve_distro

        cfg = load_config()
        for query in ("", "   ", "!!!"):
            with self.subTest(query=query):
                self.assertIsNone(resolve_distro(query, cfg))
                self.assertEqual(matching_distros(query, cfg), (None, []))


# ── Packaging: the installed artifact must be self-contained ─────────────────


class TestPackagedConfig(unittest.TestCase):
    """The wheel used to ship no config.toml, so `pip install visync` produced a
    tool that reported "No distros configured" and exited 0. `visync --help`
    still passed, which is why CI never caught it."""

    def test_packaged_config_is_not_taken_from_the_cwd(self):
        """Discovery must not fall through to a config in the working directory.

        Run from a temp dir that has its own config.toml. Resolution must pick
        the installed one, not ./config.toml — otherwise a planted config in any
        directory could hijack distro identification.
        """
        from visync.finder import _config_candidates, _packaged_config

        installed = _packaged_config()
        self.assertTrue(installed.is_file(), f"resolved config missing: {installed}")

        original = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            planted = Path(tmp) / "config.toml"
            planted.write_text('[distros]\nplanted = { clean_name = "Planted" }\n')
            try:
                os.chdir(tmp)
                self.assertEqual(
                    _packaged_config().resolve(),
                    installed.resolve(),
                    "packaged config must not be cwd-relative",
                )
                # The cwd is the last-resort candidate by design, so what matters
                # is that it is last and never outranks the installed config.
                # macOS reports /var and /private/var differently, so compare
                # resolved paths rather than the raw strings.
                candidates = [c.resolve() for c in _config_candidates()]
                self.assertEqual(
                    candidates[-1],
                    planted.resolve(),
                    "the cwd config must remain the final fallback",
                )
                self.assertIn(installed.resolve(), candidates)
                self.assertLess(
                    candidates.index(installed.resolve()),
                    len(candidates) - 1,
                    "the installed config must be preferred over the cwd",
                )
            finally:
                os.chdir(original)

    def test_wheel_layout_puts_config_beside_the_modules(self):
        """The built wheel ships visync/config.toml.

        Checked against the packaging config rather than a built artefact, so it
        runs in CI before the build job.
        """
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        text = pyproject.read_text()
        self.assertIn('packages = ["visync"]', text)
        self.assertIn('"config.toml" = "visync/config.toml"', text)

    def test_packaged_config_parses_and_has_distros(self):
        from visync.finder import reset_config_cache

        reset_config_cache()
        cfg = load_config()
        self.assertIn("distros", cfg)
        self.assertGreater(len(cfg["distros"]), 5)
        reset_config_cache()

    def test_load_config_reports_a_missing_file_clearly(self):
        """A missing config used to print 'Failed to parse config.toml'."""
        from visync.finder import load_config, reset_config_cache

        reset_config_cache()
        self.assertEqual(load_config(Path("/nonexistent/visync.toml")), {})
        reset_config_cache()

    def test_module_is_importable_under_its_own_name(self):
        """The package must not be a top-level module called `src`."""
        import visync
        import visync.main

        self.assertTrue(hasattr(visync, "__version__"))
        self.assertTrue(hasattr(visync.main, "app"))
        with self.assertRaises(ModuleNotFoundError):
            __import__("src")

    def test_no_sys_path_mutation_on_import(self):
        """download.py used to prepend the repo root to sys.path at import.

        Compared against a snapshot taken before the import, so an editable
        install (where the repo root is already present via the .pth file) is
        not mistaken for the bug.
        """
        import sys

        before = list(sys.path)
        import visync.download  # noqa: F401

        self.assertEqual(
            [p for p in sys.path if p not in before],
            [],
            "importing visync must not add anything to sys.path",
        )

    def test_editable_layout_resolves_to_repo_root_config(self):
        """With config.toml at the repo root (editable install / checkout),
        discovery must find it rather than falling through to the cwd."""
        from visync.finder import _packaged_config

        path = _packaged_config()
        self.assertTrue(path.is_file(), f"resolved config missing: {path}")
        self.assertEqual(path.name, "config.toml")


# ── Cleartext exemption: only genuinely unambiguous loopback ─────────────────


class TestLoopbackExemption(unittest.TestCase):
    """require_https lets http:// through for a local mirror used in testing.

    The exemption used to be a string set, so any spelling of 127.0.0.1 that
    urllib would resolve locally also qualified — including "127.1", the integer
    form "2130706433", and the IPv4-mapped "::ffff:127.0.0.1". That handed a
    cleartext exemption to a string the operator did not intend as loopback.
    """

    def test_intended_loopback_spellings_accepted(self):
        from visync.net import _is_loopback

        for host in (
            "localhost",
            "LOCALHOST",
            "localhost.",  # fully-qualified form of the same name
            "mirror.localhost",  # RFC 6761 reserves the whole domain
            "127.0.0.1",
            "127.0.0.2",  # the whole 127/8 is loopback
            "::1",
            "[::1]",
        ):
            with self.subTest(host=host):
                self.assertTrue(_is_loopback(host))

    def test_ambiguous_spellings_rejected(self):
        from visync.net import _is_loopback

        for host in (
            "127.1",
            "2130706433",
            "0x7f000001",
            "0x7f.0.0.1",
            "0177.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:7f00:1",
            "localhost.evil.com",
            "notlocalhost",
            "evil.com",
            "",
            ".",
            None,
        ):
            with self.subTest(host=host):
                self.assertFalse(_is_loopback(host))

    def test_http_allowed_only_for_loopback(self):
        from visync.net import require_https

        require_https("https://example.com/x")
        require_https("http://localhost:8080/x")
        require_https("http://127.0.0.1/x")
        for url in (
            "http://example.com/x",
            "http://127.1/x",
            "http://2130706433/x",
            "http://[::ffff:127.0.0.1]/x",
            "file:///etc/passwd",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    require_https(url)


class TestSigningKeyMustBeHttps(unittest.TestCase):
    """The GPG key was fetched over plain http:// with no scheme check.

    The point of fingerprint pinning is to defeat a key substituted in
    transit, so fetching that key in cleartext made the pinning decorative for
    any config that spelled the URL with http://.
    """

    def test_http_key_url_is_refused_before_any_fetch(self):
        from visync.verify import _import_key_then_verify

        with patch("visync.verify.urlopen") as mu:
            with self.assertRaises(ChecksumUnavailable) as ctx:
                _import_key_then_verify(
                    Path("/tmp/CHECKSUM"),
                    "http://deb.parrot.sh/parrot/misc/archive.gpg",
                    "B711822346552E4D92DA02DF7A8286AF0E81EE4A",
                )
        mu.assert_not_called()
        self.assertIn("non-HTTPS", str(ctx.exception))

    def test_https_key_url_is_still_fetched(self):
        from visync.verify import _import_key_then_verify

        def fake_run(cmd, **kw):
            r = MagicMock()
            r.returncode = 1  # import/verify failure is not what this test is about
            return r

        with (
            patch("visync.verify.subprocess.run", side_effect=fake_run),
            patch("visync.verify.shutil.which", return_value="/usr/bin/gpg"),
            patch("visync.verify.urlopen") as mu,
        ):
            resp = MagicMock()
            resp.read.return_value = b"key"
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            mu.return_value = resp
            result = _import_key_then_verify(
                Path("/tmp/CHECKSUM"),
                "https://deb.parrot.sh/parrot/misc/archive.gpg",
                "B711822346552E4D92DA02DF7A8286AF0E81EE4A",
            )
        mu.assert_called_once()
        self.assertFalse(result)


# ── Ctrl-C must not orphan partial downloads ─────────────────────────────────


class TestInterruptDiscardsPartial(unittest.TestCase):
    """Cancelling a download left the .part file on disk.

    The handler that was supposed to clean up lived in download.py's
    __main__ block, which the CLI never executes (entry point is
    visync.main:app), so it had been dead code since it was written. Every
    other failure path already unlinked the partial; cancellation was the one
    that did not, and on a Ventoy drive the bytes are wasted space the next ISO
    needs.
    """

    def _run(self, exc):
        config = {
            "iso": {},
            "distros": {"X": {"clean_name": "X", "strategy": "direct_match"}},
        }
        with (
            patch.object(dl, "load_config", return_value=config),
            patch.object(dl, "visync_watchdog"),
            patch.object(dl, "_sweep_old_versions"),
            patch.object(
                dl,
                "_check_distro",
                return_value=DistroCheck(
                    "X", "X", "x.iso", SyncStatus.STALE, "https://example.com/x.iso"
                ),
            ),
            patch.object(dl, "download_iso", side_effect=exc),
        ):
            return dl.sync_all_configured_distros(
                dry_run=False,
                drive_override=Path(tempfile.gettempdir()),
                use_buffer=True,
                config_path=None,
            )

    def test_keyboard_interrupt_removes_the_part_file(self):
        with tempfile.TemporaryDirectory() as staging:
            written = {}

            def fake_download(url, dest, **kwargs):
                part = Path(dest).with_suffix(Path(dest).suffix + ".part")
                part.write_bytes(b"\0" * 4096)
                written["part"] = part
                raise KeyboardInterrupt

            with patch("visync.download.DEFAULT_STAGING_DIR", Path(staging)):
                with self.assertRaises(KeyboardInterrupt):
                    self._run(fake_download)
            self.assertTrue(written["part"].name.endswith(".part"))
            self.assertFalse(
                written["part"].exists(), "the interrupted partial must be removed"
            )

    def test_unlink_failure_does_not_mask_the_interrupt(self):
        """A read-only staging dir must not turn Ctrl-C into a crash."""

        def fake_download(url, dest, **kwargs):
            part = Path(dest).with_suffix(Path(dest).suffix + ".part")
            part.write_bytes(b"\0" * 16)
            with patch.object(Path, "unlink", side_effect=OSError("read-only")):
                raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as staging:
            with patch("visync.download.DEFAULT_STAGING_DIR", Path(staging)):
                with self.assertRaises(KeyboardInterrupt):
                    self._run(fake_download)

    def test_cli_exits_130_on_interrupt(self):
        """The CLI turns Ctrl-C into a clean exit(130), not a traceback."""
        from typer.testing import CliRunner

        from visync.main import app

        with (
            patch("visync.download.download_iso", side_effect=KeyboardInterrupt),
            patch("visync.download.DEFAULT_STAGING_DIR", Path(tempfile.gettempdir())),
        ):
            result = CliRunner().invoke(
                app,
                ["--yes", "sync", "--all", "--no-verify", "--no-staging"],
            )
        self.assertEqual(result.exit_code, 130, result.output)
        self.assertNotIn("Traceback", result.output)
