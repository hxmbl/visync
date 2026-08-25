"""Regression tests for security/correctness fixes from the audit.

Each test maps to an audit finding ID (C1..C3, H1..H4, M1..M6, L1..L13).
"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import download as dl
from src.download import (
    _cleanup_old_versions,
    _download_chunked,
    _download_threads,
    _safe_filename,
    _sweep_old_versions,
    sync_all_configured_distros,
)
from src.finder import keyword_hit
from src.output import console, error, info, removed, success, warn
from src.pm import load_installed
from src.verify import ChecksumUnavailable

ISO_VID_OFFSET = 32808


def _iso_with_vid(path: Path, volume_id: str, size: int = 40000) -> None:
    """Create a fake ISO with an ISO9660 primary volume descriptor label."""
    buf = bytearray(size)
    label = volume_id.encode("ascii")[:32]
    buf[ISO_VID_OFFSET:ISO_VID_OFFSET + len(label)] = label
    path.write_bytes(bytes(buf))


# ── C1: dry-run must gate destructive clean sweeps ───────────────────────────


class TestDryRunGatesClean(unittest.TestCase):
    def _make_drive(self, tmpdir: str) -> Path:
        drive = Path(tmpdir)
        _iso_with_vid(drive / "archlinux-2025.01.01-x86_64.iso", "ARCH LINUX 2025.01.01 x86_64")
        _iso_with_vid(drive / "archlinux-2026.08.01-x86_64.iso", "ARCH LINUX 2026.08.01 x86_64")
        return drive

    def _config(self):
        return {
            "iso": {},
            "checksums": {"enabled": False},
            "distros": {"ArchLinux": {"clean_name": "Arch Linux"}},
        }

    @patch("src.download.visync_watchdog")
    @patch("src.download._check_distro")
    def test_sync_clean_dry_run_deletes_nothing(self, mock_check, _wd):
        """--clean --dry-run reports but keeps both ISOs on disk."""
        mock_check.return_value = ("ArchLinux", "Arch Linux",
                                   "archlinux-2026.08.01-x86_64.iso", True, None)
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._make_drive(tmpdir)
            with patch("src.download.load_config", return_value=self._config()):
                sync_all_configured_distros(
                    dry_run=True, clean=True, only=["ArchLinux"], drive_override=drive,
                    use_buffer=False,
                )
            self.assertTrue((drive / "archlinux-2025.01.01-x86_64.iso").exists())
            self.assertTrue((drive / "archlinux-2026.08.01-x86_64.iso").exists())

    @patch("src.download.visync_watchdog")
    @patch("src.download._check_distro")
    def test_sync_clean_without_dry_run_removes_old(self, mock_check, _wd):
        """--clean (no dry-run) removes only the older version."""
        mock_check.return_value = ("ArchLinux", "Arch Linux",
                                   "archlinux-2026.08.01-x86_64.iso", True, None)
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = self._make_drive(tmpdir)
            with patch("src.download.load_config", return_value=self._config()):
                sync_all_configured_distros(
                    dry_run=False, clean=True, only=["ArchLinux"], drive_override=drive,
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
        handler = type("TruncServer", (_RangeServer,), {
            "data": data, "truncate_at": (4 * 1024 * 1024, 1024 * 1024),
        })
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


# ── H1: verification unavailability must not delete downloads ────────────────


class TestDownloadKeepsFileWhenChecksumUnavailable(unittest.TestCase):
    @patch("src.verify.verify_from_config")
    @patch("src.download.urllib.request.urlopen")
    @patch("src.download.urllib.request.Request")
    def test_fetch_failure_keeps_download(
        self, _req, mock_urlopen, mock_verify
    ):
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
                "https://example.com/test.iso", dest,
                distro_config={"checksum_url": "https://example.com/SUMS"},
                checksums_config={"enabled": True},
            )
            self.assertTrue(result, "download itself succeeded; unavailable ≠ mismatch")
            self.assertTrue(dest.exists(), "file must be kept when checksum unavailable")


# ── H2: API strategies stash resolved checksums ──────────────────────────────


class TestApiResolvedChecksums(unittest.TestCase):
    @patch("src.download.ping_mirror", return_value=True)
    @patch("src.download.fetch_html")
    def test_popos_stashes_sha256(self, mock_fetch, _ping):
        mock_fetch.return_value = json.dumps({
            "url": "https://isos.pop-os.org/pop-os.iso",
            "sha256": "ab" * 32,
        })
        settings = {"strategy": "popos_api"}
        name, url = dl.process_scraping_strategy("Pop!_OS", settings)
        self.assertEqual(name, "pop-os.iso")
        self.assertEqual(settings.get("resolved_checksum"), "ab" * 32)

    @patch("src.download.ping_mirror", return_value=True)
    @patch("src.download.fetch_html")
    def test_tails_stashes_target_sha256(self, mock_fetch, _ping):
        mock_fetch.return_value = json.dumps({
            "installations": [{
                "version": "6.91",
                "installation-paths": [{
                    "type": "img",
                    "target-files": [{
                        "url": "https://tails.net/tails-amd64-6.91.img",
                        "sha256": "cd" * 32,
                    }],
                }],
            }],
        })
        settings = {"strategy": "tails_api", "api_url": "https://x/latest.json"}
        name, url = dl.process_scraping_strategy("Tails", settings)
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
            return ("X", "X", "", True, None)

        config = {"iso": {}, "distros": {"X": {"clean_name": "X"}}}
        orig_deadline = dl.SCRAPE_DEADLINE
        dl.SCRAPE_DEADLINE = 1
        try:
            with patch.object(dl, "_check_distro", side_effect=hung_check), \
                 patch.object(dl, "visync_watchdog"), \
                 patch.object(dl, "_sweep_old_versions"), \
                 patch.object(dl, "load_config", return_value=config):
                t0 = time.monotonic()
                sync_all_configured_distros(
                    dry_run=True, drive_override=Path(tempfile.gettempdir()),
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
            self.assertIn("[red]", out, f"{fn.__name__} must render tags as literal text")

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

        with patch("src.verify.subprocess.run", side_effect=fake_run), \
             patch("src.verify.urlopen") as mu:
            resp = MagicMock()
            resp.read.return_value = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            mu.return_value = resp
            return _import_key_then_verify(Path("/tmp/CHECKSUM"), "https://fedoraproject.org/fedora.gpg", pins)

    def test_list_pin_matching(self):
        self.assertTrue(self._run_verify(
            ["C6E7F081CF80E13146676E88829B606631645531",
             "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6"],
            "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6"))

    def test_single_string_pin(self):
        self.assertTrue(self._run_verify(
            "4F50A6114CD5C6976A7F1179655A4B02F577861E",
            "4f50a6114cd5c6976a7f1179655a4b02f577861e"))

    def test_unknown_key_rejected(self):
        self.assertFalse(self._run_verify(
            ["C6E7F081CF80E13146676E88829B606631645531"],
            "DEADBEEF00000000000000000000000000000000"))

    def test_config_fingerprints_flow_through_config(self):
        from src.finder import load_config
        cfg = load_config()
        for entry in ("Fedora", "FedoraKDE", "FedoraARM"):
            s = cfg["distros"][entry]
            pins = s.get("signing_key_fingerprint")
            self.assertIsInstance(pins, list) and None
            self.assertGreaterEqual(len(pins), 4, f"{entry} should pin the release keys")
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
                chunk = payload[s:min(e + 4096, len(payload))]  # 4 KiB extra
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
            "distros": {"X": {"strategy": "direct_match",
                              "base_url": "http://insecure.example/"}},
        }
        with patch.object(dl, "load_config", return_value=config), \
             patch.object(dl, "visync_watchdog"), \
             patch.object(dl, "_sweep_old_versions"), \
             patch.object(dl, "ping_mirror", return_value=True), \
             patch.object(dl, "fetch_html",
                          return_value='<a href="evil.iso">x</a>'):
            # Must not raise; the http:// URL is rejected per-distro
            result = sync_all_configured_distros(
                dry_run=False, drive_override=Path(tempfile.gettempdir()),
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

        with patch("src.verify.subprocess.run", side_effect=fake_run), \
             patch("src.verify.urlopen") as mu:
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
        stdout = ("[GNUPG:] NEWSIG\n"
                  "[GNUPG:] KEY_CONSIDERED C6E7F081CF80E13146676E88829B606631645531 0\n"
                  "[GNUPG:] VALIDSIG AABB00000000000000000000000000000000CCDD "
                  "2026-01-01 0 pi 1 1 1 01 "
                  "C6E7F081CF80E13146676E88829B606631645531\n")
        self.assertTrue(self._run(stdout),
                        "subkey signer must be accepted via primary-fpr field")

    def test_wrong_primary_rejected(self):
        stdout = ("[GNUPG:] VALIDSIG AABB00000000000000000000000000000000CCDD "
                  "2026-01-01 0 pi 1 1 1 01 "
                  "DEAD00000000000000000000000000000000BEEF\n")
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

    def test_watchdog_over_limit_wipes_but_only_visync(self):
        """Stage-2 wipe removes .visync contents but nothing outside it."""
        from src.finder import visync_watchdog, VISYNC_SIZE_LIMIT

        with tempfile.TemporaryDirectory() as tmp:
            drive = Path(tmp)
            visync_dir = drive / ".visync"
            (visync_dir / "metadata").mkdir(parents=True)
            (visync_dir / "metadata" / "gone.iso.json").write_text("{}")
            keeper = drive / "archlinux-2026.iso"
            keeper.write_bytes(b"\x00" * 64)
            (visync_dir / "ballast.bin").write_bytes(b"\0" * (VISYNC_SIZE_LIMIT + 1))

            visync_watchdog(drive)

            self.assertFalse(visync_dir.exists(), "over-budget .visync gets wiped")
            self.assertTrue(keeper.exists(), "drive content outside .visync untouched")
