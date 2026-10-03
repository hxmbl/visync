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
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import download as dl
from src.download import (
    DistroCheck,
    SyncStatus,
    _download_chunked,
    _download_threads,
    _safe_filename,
    _sweep_old_versions,
    sync_all_configured_distros,
)
from src.finder import _dir_size, keyword_hit, load_config
from src.output import console, error, info, removed, success, warn
from src.pm import load_installed
from src.verify import ChecksumUnavailable, expand_url, extract_iso_metadata

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

    @patch("src.download.visync_watchdog")
    @patch("src.download._check_distro")
    def test_sync_clean_dry_run_deletes_nothing(self, mock_check, _wd):
        """--clean --dry-run reports but keeps both ISOs on disk."""
        mock_check.return_value = self._current("archlinux-2026.08.01-x86_64.iso")
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._make_drive(tmpdir)
            with patch("src.download.load_config", return_value=self._config()):
                sync_all_configured_distros(
                    dry_run=True,
                    clean=True,
                    only=["ArchLinux"],
                    drive_override=drive,
                    use_buffer=False,
                )
            self.assertTrue((drive / "archlinux-2025.01.01-x86_64.iso").exists())
            self.assertTrue((drive / "archlinux-2026.08.01-x86_64.iso").exists())

    @patch("src.download.visync_watchdog")
    @patch("src.download._check_distro")
    def test_sync_clean_without_dry_run_removes_old(self, mock_check, _wd):
        """--clean (no dry-run) removes only the older version."""
        mock_check.return_value = self._current("archlinux-2026.08.01-x86_64.iso")
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._make_drive(tmpdir)
            with patch("src.download.load_config", return_value=self._config()):
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

    @patch("src.download.visync_watchdog")
    @patch("src.download._check_distro")
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
                patch("src.download.load_config", return_value=cfg),
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
    data = b""
    truncate_at = None  # bytes to serve for the SECOND range before clean EOF

    def do_GET(self):
        spec = self.headers.get("Range", "")[6:]
        start_s, end_s = spec.split("-")
        start, end = int(start_s), int(end_s) + 1
        chunk = self.data[start:end]
        if type(self).truncate_at is not None and start == type(self).truncate_at[0]:
            chunk = chunk[: type(self).truncate_at[1]]
            self.send_response(206)
            self.send_header("Content-Length", str(len(chunk)))
            self.end_headers()
            self.wfile.write(chunk)
            self.close_connection = True
            return
        self.send_response(self.status_code if hasattr(self, "status_code") else 206)
        self.send_header("Content-Length", str(len(chunk)))
        self.end_headers()
        self.wfile.write(chunk)

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

    @patch("src.verify.shutil.which", return_value=None)
    def test_import_key_then_verify_raises_checksum_unavailable(self, _mock_which):
        from src.verify import ChecksumUnavailable, _import_key_then_verify

        with self.assertRaises(ChecksumUnavailable):
            _import_key_then_verify(
                Path("/tmp/CHECKSUM"),
                "https://fedoraproject.org/fedora.gpg",
                "DEADBEEF00000000000000000000000000000000",
            )

    @patch("src.verify._fetch")
    @patch("src.verify.shutil.which", return_value=None)
    def test_verify_iso_keeps_file_when_gpg_missing(self, _mock_which, _mock_fetch):
        """verify_iso must not raise FileNotFoundError when gpg is missing —
        it should raise ChecksumUnavailable so callers keep the ISO."""
        from src.verify import ChecksumUnavailable, verify_iso

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

    @patch("src.verify._import_key_then_verify")
    @patch("src.verify._fetch")
    def test_valid_signature_verifies_plain_sums_format(self, mock_fetch, mock_import):
        from src.verify import verify_iso

        mock_fetch.return_value = "0" * 64 + "  Parrot-security-7.4_amd64.iso\n"
        mock_import.return_value = True

        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "Parrot-security-7.4_amd64.iso"
            iso.write_bytes(b"x" * 64)
            with patch("src.verify.compute_iso_hash", return_value="0" * 64):
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

    @patch("src.verify._import_key_then_verify")
    @patch("src.verify._fetch")
    def test_bad_signature_fails_plain_sums_format(self, mock_fetch, mock_import):
        from src.verify import verify_iso

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

    @patch("src.verify._fetch")
    def test_no_signing_key_skips_gpg_entirely(self, mock_fetch):
        """Distros without a signing_key_url must not require gpg at all."""
        from src.verify import verify_iso

        mock_fetch.return_value = "0" * 64 + "  arch.iso\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "arch.iso"
            iso.write_bytes(b"x" * 64)
            with (
                patch("src.verify.shutil.which", return_value=None),
                patch("src.verify.compute_iso_hash", return_value="0" * 64),
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
    @patch("src.verify.verify_from_config")
    @patch("src.download.urllib.request.urlopen")
    @patch("src.download.urllib.request.Request")
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

        from src.download import download_iso

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

    @patch("src.download.urllib.request.urlopen")
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

        from src.download import download_iso

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
    @patch("src.download.ping_mirror", return_value=True)
    @patch("src.download.fetch_html")
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

    @patch("src.download.ping_mirror", return_value=True)
    @patch("src.download.fetch_html")
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
        with patch.object(sys.modules["src.output"], "console", cap):
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
        from src.pm import save_installed

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
        from src.verify import _import_key_then_verify

        def fake_run(cmd, **kw):
            r = MagicMock()
            r.returncode = 0
            if "--verify" in cmd:
                r.stdout = f"[GNUPG:] VALIDSIG {validsig} 0 0 1 1 1 sha256\n"
            return r

        with (
            patch("src.verify.subprocess.run", side_effect=fake_run),
            patch("src.verify.urlopen") as mu,
            patch("src.verify.shutil.which", return_value="/usr/bin/gpg"),
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
        from src.finder import load_config

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

    @patch("src.download.ping_mirror", return_value=True)
    @patch("src.download.fetch_html")
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
        from src.verify import _import_key_then_verify

        def fake_run(cmd, **kw):
            r = MagicMock()
            r.returncode = 0
            if "--verify" in cmd:
                r.stdout = stdout
            return r

        with (
            patch("src.verify.subprocess.run", side_effect=fake_run),
            patch("src.verify.urlopen") as mu,
            patch("src.verify.shutil.which", return_value="/usr/bin/gpg"),
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
        from src.finder import load_all_metadata

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
        from src.finder import _deep_clean_metadata

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
        from src.finder import VISYNC_SIZE_LIMIT

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
        from src.finder import visync_watchdog

        with tempfile.TemporaryDirectory() as tmp:
            drive, keeper = self._over_budget_drive(tmp)
            visync_dir = drive / ".visync"

            visync_watchdog(drive)

            self.assertTrue(visync_dir.exists(), "wipe must be opt-in")
            self.assertTrue(keeper.exists(), "drive content outside .visync untouched")

    def test_watchdog_wipes_only_when_opted_in(self):
        """allow_wipe=True removes .visync contents but nothing outside it."""
        from src.finder import visync_watchdog

        with tempfile.TemporaryDirectory() as tmp:
            drive, keeper = self._over_budget_drive(tmp)
            visync_dir = drive / ".visync"

            visync_watchdog(drive, allow_wipe=True)

            self.assertFalse(visync_dir.exists(), "opted-in wipe must remove .visync")
            self.assertTrue(keeper.exists(), "drive content outside .visync untouched")

    def test_dry_run_sync_never_runs_the_watchdog(self):
        """--dry-run must leave .visync/ (and installed.json) byte-for-byte intact."""
        from src.download import sync_all_configured_distros
        from src.finder import VISYNC_SIZE_LIMIT

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
                patch("src.download.load_config", return_value=cfg),
                patch("src.download._sweep_old_versions"),
                patch("src.download._check_distro") as check,
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
        from src.finder import VISYNC_SIZE_LIMIT, visync_watchdog

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

            with patch("src.finder.VISYNC_SIZE_LIMIT", 1):
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

    @patch("src.download.ping_mirror", return_value=True)
    @patch("src.download.fetch_html")
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

    @patch("src.download.ping_mirror", return_value=True)
    @patch("src.download.fetch_html")
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

    @patch("src.download.ping_mirror", return_value=True)
    @patch("src.download.fetch_html", return_value="")
    def test_unreachable_listing_is_reported(self, _fetch, _ping):
        settings = {
            "strategy": "nixos_channel",
            "base_url": "https://channels.nixos.org/nixos",
        }
        dl.process_scraping_strategy("NixOS", settings)
        self.assertIn("release listing", settings.get("resolve_error", ""))
        print("listing failure surfaces, no channel guessed")

    @patch("src.download.ping_mirror", return_value=True)
    @patch("src.download.fetch_html", return_value="<html>nothing useful</html>")
    def test_listing_without_channels_is_reported(self, _fetch, _ping):
        settings = {
            "strategy": "nixos_channel",
            "base_url": "https://channels.nixos.org/nixos",
        }
        dl.process_scraping_strategy("NixOS", settings)
        self.assertIn("channels", settings.get("resolve_error", ""))

    @patch("src.download.ping_mirror", return_value=True)
    @patch(
        "src.download.fetch_html",
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

    @patch("src.download.ping_mirror", return_value=True)
    @patch("src.download.fetch_html")
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
