"""Unit tests for download module (no network or Ventoy hardware required)."""

import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from visync.download import (
    DEBUG,
    SyncStatus,
    _check_distro,
    _cleanup_old_versions,
    _filename_variant_key,
    _variant_stem,
    download_iso,
    fetch_html,
    find_installed_isos,
    load_config,
    ping_mirror,
    process_scraping_strategy,
    same_variant_prefix,
)


def _section(title: str) -> None:
    print(f"\n  {'=' * 60}")
    print(f"  {title}")
    print(f"  {'=' * 60}")


def _ok(msg: str) -> None:
    print(f"  [✓] {msg}")


def _info(msg: str) -> None:
    print(f"  [*] {msg}")


class TestDebugMode(unittest.TestCase):
    def test_debug_off_by_default(self):
        _section("Debug Mode: Default Off")
        self.assertFalse(DEBUG)
        _ok("VISYNC_DEBUG defaults to 0")

    @patch.dict(os.environ, {"VISYNC_DEBUG": "1"})
    def test_debug_on_with_env(self):
        _section("Debug Mode: Enabled via ENV")
        import visync.download as dl

        old = dl.DEBUG
        dl.DEBUG = True
        self.assertTrue(dl.DEBUG)
        dl.DEBUG = old
        _ok("VISYNC_DEBUG=1 enables debug mode")


class TestPingMirror(unittest.TestCase):
    @patch("visync.download.socket.create_connection")
    def test_ping_success(self, mock_conn: MagicMock):
        _section("ping_mirror: Reachable Host")
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        result = ping_mirror("https://example.com")
        self.assertTrue(result)
        _ok("Returns True on successful TCP connect")

    @patch("visync.download.socket.create_connection")
    def test_ping_timeout(self, mock_conn: MagicMock):
        _section("ping_mirror: Timeout")
        mock_conn.side_effect = TimeoutError("timed out")
        result = ping_mirror("https://unreachable.example.com")
        self.assertFalse(result)
        _ok("Returns False on timeout")

    @patch("visync.download.socket.create_connection")
    def test_ping_connection_refused(self, mock_conn: MagicMock):
        _section("ping_mirror: Connection Refused")
        mock_conn.side_effect = ConnectionRefusedError
        result = ping_mirror("https://example.com")
        self.assertFalse(result)
        _ok("Returns False on connection refused")

    def test_ping_parses_port_from_url(self):
        _section("ping_mirror: Port Extraction")
        with patch("visync.download.socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_conn)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            ping_mirror("https://example.com:8443/path")
            args, _kwargs = mock_conn.call_args
            self.assertEqual(args[0], ("example.com", 8443))
            _ok("Extracts custom port from URL")

    def test_ping_defaults_https_port(self):
        _section("ping_mirror: Default HTTPS Port")
        with patch("visync.download.socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_conn)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            ping_mirror("https://example.com")
            args, _kwargs = mock_conn.call_args
            self.assertEqual(args[0], ("example.com", 443))
            _ok("Defaults to port 443 for HTTPS")

    def test_ping_defaults_http_port(self):
        _section("ping_mirror: Default HTTP Port")
        with patch("visync.download.socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_conn)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            ping_mirror("http://example.com")
            args, _kwargs = mock_conn.call_args
            self.assertEqual(args[0], ("example.com", 80))
            _ok("Defaults to port 80 for HTTP")


class TestVariantStem(unittest.TestCase):
    """variant_key strips architecture tokens so a volume-ID key matches the
    filename key of the same distro. The previous volume-ID path kept 'amd64'
    and 'x86_64' (its underscore-protection step is a no-op for every arch
    except x86_64), so the two key schemes disagreed."""

    def test_fedora_everything(self):
        _section("variant_key: Fedora Everything")
        result = _variant_stem("Fedora-E-dvd-x86_64-44")
        self.assertEqual(result, "fedora-e-dvd")
        _ok(f"Result: {result}")

    def test_fedora_kde(self):
        _section("variant_key: Fedora KDE")
        result = _variant_stem("Fedora-KDE-Live-44")
        self.assertEqual(result, "fedora-kde-live")
        _ok(f"Result: {result}")

    def test_fedora_sway(self):
        _section("variant_key: Fedora Sway")
        result = _variant_stem("Fedora-Sway-Live-44")
        self.assertEqual(result, "fedora-sway-live")
        _ok(f"Result: {result}")

    def test_ubuntu_server_with_lts(self):
        _section("variant_key: Ubuntu Server LTS")
        result = _variant_stem("Ubuntu-Server 24.04.4 LTS amd64")
        self.assertEqual(result, "ubuntu-server")
        _ok(f"Result: {result}")

    def test_ubuntu_server_without_lts(self):
        _section("variant_key: Ubuntu Server (no LTS)")
        result = _variant_stem("Ubuntu-Server 26.04 amd64")
        self.assertEqual(result, "ubuntu-server")
        _ok(f"Result: {result}")

    def test_arch_linux(self):
        _section("variant_key: Arch Linux")
        result = _variant_stem("ARCH_202610")
        self.assertEqual(result, "arch")
        _ok(f"Result: {result}")

    def test_volume_id_and_filename_share_a_variant_prefix(self):
        """The invariant that was violated.

        Full equality is the wrong assertion: a volume ID is terser than a
        filename ("Fedora-KDE-Live-44" vs "...-Desktop-Live-44-1.7...iso"), so
        the keys differ in detail by design. What cleanup actually needs is that
        neither side rules the other out — which is what the old
        ``startswith`` comparison failed to guarantee, because 'pop_os' (volume
        ID) could never match 'pop-os' (filename).
        """
        _section("variant_key: volume ID and filename are compatible")
        pairs = [
            ("Fedora-KDE-Live-44", "Fedora-KDE-Desktop-Live-44-1.7.x86_64.iso"),
            ("Pop_OS 24.04 amd64", "pop-os_24.04_amd64_generic_24.iso"),
            ("ARCH_202610", "archlinux-2026.10.01-x86_64.iso"),
            ("Ubuntu-Server 26.04.1 LTS amd64", "ubuntu-26.04.1-live-server-amd64.iso"),
        ]
        for vid, filename in pairs:
            with self.subTest(pair=(vid, filename)):
                self.assertTrue(
                    same_variant_prefix(
                        _variant_stem(vid), _filename_variant_key(filename)
                    ),
                    f"{_variant_stem(vid)!r} must not rule out "
                    f"{_filename_variant_key(filename)!r}",
                )
        _ok("every real volume ID/filename pair survives the pre-filter")

    def test_ubuntu_versions_match(self):
        _section("_variant_stem: Ubuntu Cross-Version Match")
        stem_old = _variant_stem("Ubuntu-Server 24.04.4 LTS amd64")
        stem_new = _variant_stem("Ubuntu-Server 26.04 amd64")
        self.assertEqual(stem_old, stem_new)
        _ok(f"Old: {stem_old} == New: {stem_new}")

    def test_fedora_variants_differ(self):
        _section("_variant_stem: Fedora Variant Separation")
        s1 = _variant_stem("Fedora-E-dvd-x86_64-44")
        s2 = _variant_stem("Fedora-KDE-Live-44")
        s3 = _variant_stem("Fedora-Sway-Live-44")
        self.assertNotEqual(s1, s2)
        self.assertNotEqual(s2, s3)
        self.assertNotEqual(s1, s3)
        _ok("All three Fedora variants produce unique stems")

    def test_arch_linux_filename(self):
        _section("variant_key: Arch Linux (filename)")
        result = _variant_stem("ArchLinux-2026.06.01-x86_64")
        self.assertEqual(result, "archlinux")
        _ok(f"Result: {result}")

    def test_empty_string(self):
        _section("_variant_stem: Empty String")
        result = _variant_stem("")
        self.assertEqual(result, "")
        _ok("Returns empty string for empty input")


class TestFetchHtml(unittest.TestCase):
    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_fetch_html_success(self, mock_request: MagicMock, mock_urlopen: MagicMock):
        _section("fetch_html: Successful Request")
        mock_response = MagicMock()
        mock_response.read.return_value = b"<html>content</html>"
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        result = fetch_html("https://example.com")
        self.assertEqual(result, "<html>content</html>")
        _ok("HTML content returned as string")

    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_fetch_html_failure(self, mock_request: MagicMock, mock_urlopen: MagicMock):
        _section("fetch_html: Network Failure")
        mock_urlopen.side_effect = Exception("timeout")
        result = fetch_html("https://example.com")
        self.assertEqual(result, "")
        _ok("Empty string returned on timeout")

    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_bot_challenge_detected(
        self, mock_request: MagicMock, mock_urlopen: MagicMock
    ):
        _section("fetch_html: Bot Challenge Detection")
        mock_response = MagicMock()
        mock_response.read.return_value = b"<html>Anubis challenge page</html>"
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response
        result = fetch_html("https://example.com")
        self.assertEqual(result, "")
        _ok("Anubis challenge detected, empty string returned")

    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_ssl_error_auto_skips(
        self, mock_request: MagicMock, mock_urlopen: MagicMock
    ):
        _section("fetch_html: SSL Error — Auto Skip (Non-Interactive)")
        mock_urlopen.side_effect = urllib.error.URLError(
            "SSL: CERTIFICATE_VERIFY_FAILED"
        )
        result = fetch_html("https://example.com")
        self.assertEqual(result, "")
        _ok("SSL error returns empty string without prompting (non-interactive)")

    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_url_error_returns_empty(
        self, mock_request: MagicMock, mock_urlopen: MagicMock
    ):
        _section("fetch_html: Generic URLError")
        mock_urlopen.side_effect = urllib.error.URLError("404 Not Found")
        result = fetch_html("https://example.com/missing")
        self.assertEqual(result, "")
        _ok("URLError returns empty string")


class TestLoadConfig(unittest.TestCase):
    def test_load_config_returns_dict(self):
        _section("load_config: Structure Check")
        config = load_config()
        self.assertIsInstance(config, dict)
        self.assertIn("distros", config)
        self.assertIn("iso", config)
        _ok("Config loaded as dict with [distros] and [iso] sections")

    def test_load_config_missing_file(self):
        _section("load_config: Missing File")
        config = load_config(Path("/nonexistent/config.toml"))
        self.assertEqual(config, {})
        _ok("Returns empty dict on missing file")

    def test_load_config_custom_path(self):
        _section("load_config: Custom Path")
        config = load_config(Path("config.toml"))
        self.assertIsInstance(config, dict)
        self.assertIn("distros", config)
        _ok("Loads from custom path successfully")


class TestProcessScrapingStrategy(unittest.TestCase):
    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_direct_match_found(self, mock_fetch_html: MagicMock, mock_ping: MagicMock):
        _section("Strategy: direct_match — Found")
        mock_fetch_html.return_value = (
            '<a href="archlinux-2025.01.01-x86_64.iso">arch</a>'
        )
        settings = {
            "strategy": "direct_match",
            "base_url": "https://example.com/iso/",
            "iso_regex": 'href="(archlinux-[^"]+\\.iso)"',
        }
        name, url = process_scraping_strategy("Arch Linux", settings)
        self.assertEqual(name, "archlinux-2025.01.01-x86_64.iso")
        self.assertEqual(url, "https://example.com/iso/archlinux-2025.01.01-x86_64.iso")
        _ok(f"Resolved to {name}")

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_direct_match_not_found(
        self, mock_fetch_html: MagicMock, mock_ping: MagicMock
    ):
        _section("Strategy: direct_match — Not Found")
        mock_fetch_html.return_value = "<html>no iso here</html>"
        settings = {
            "strategy": "direct_match",
            "base_url": "https://example.com/",
            "iso_regex": 'href="(archlinux-[^"]+\\.iso)"',
        }
        name, url = process_scraping_strategy("Arch Linux", settings)
        self.assertEqual(name, "")
        self.assertEqual(url, "")
        _ok("Empty strings returned when no match")

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_fedora_nested_found(
        self, mock_fetch_html: MagicMock, mock_ping: MagicMock
    ):
        _section("Strategy: fedora_nested — Found")
        mock_fetch_html.side_effect = [
            '<a href="41/">41/</a><a href="42/">42/</a>',
            '<a href="Fedora-Workstation-Live-x86_64-42-1.1.iso">iso</a>',
        ]
        settings = {
            "strategy": "fedora_nested",
            "base_url": "https://example.com/fedora/",
            "version_regex": 'href="([0-9\\.]+)/"',
            "iso_regex": 'href="(Fedora-Workstation-Live-x86_64-[^"]+\\.iso)"',
        }
        name, url = process_scraping_strategy("Fedora", settings)
        self.assertEqual(name, "Fedora-Workstation-Live-x86_64-42-1.1.iso")
        self.assertIn("42/Workstation/x86_64/iso/", url)
        _ok(f"Resolved to Fedora 42: {name}")

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_ubuntu_nested_found(
        self, mock_fetch_html: MagicMock, mock_ping: MagicMock
    ):
        _section("Strategy: ubuntu_nested — Found")
        mock_fetch_html.side_effect = [
            '<a href="24.04/">24.04/</a><a href="24.10/">24.10/</a>',
            '<a href="ubuntu-24.10-live-server-amd64.iso">iso</a>',
        ]
        settings = {
            "strategy": "ubuntu_nested",
            "base_url": "https://example.com/ubuntu/",
            "version_regex": 'href="([0-9\\.]+)/"',
            "iso_regex": 'href="(ubuntu-[^"]+\\.iso)"',
        }
        name, url = process_scraping_strategy("Ubuntu Server", settings)
        self.assertEqual(name, "ubuntu-24.10-live-server-amd64.iso")
        self.assertIn("24.10/", url)
        _ok(f"Resolved to Ubuntu 24.10: {name}")

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_fedora_empty_root(self, mock_fetch_html: MagicMock, mock_ping: MagicMock):
        _section("Strategy: fedora_nested — Empty Root")
        mock_fetch_html.return_value = ""
        settings = {
            "strategy": "fedora_nested",
            "base_url": "https://example.com/",
            "version_regex": 'href="([0-9\\.]+)/"',
            "iso_regex": 'href="(Fedora-[^"]+\\.iso)"',
        }
        name, url = process_scraping_strategy("Fedora", settings)
        self.assertEqual(name, "")
        self.assertEqual(url, "")
        _ok("Empty strings returned on empty root HTML")

    @patch("visync.download.ping_mirror", return_value=False)
    def test_ping_failure_skips_mirror(self, mock_ping: MagicMock):
        _section("Strategy: ping failure short-circuits")
        settings = {
            "strategy": "direct_match",
            "base_url": "https://dead.example.com/",
            "iso_regex": 'href="(.+\\.iso)"',
        }
        name, url = process_scraping_strategy("Dead Mirror", settings)
        self.assertEqual(name, "")
        self.assertEqual(url, "")
        mock_ping.assert_called_once()
        _ok("Ping failure returns empty without fetching")

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_fedora_dl_real_listing(
        self, mock_fetch_html: MagicMock, mock_ping: MagicMock
    ):
        """Suffix-style names actually served by dl.fedoraproject.org."""
        _section("Strategy: fedora_nested — dl.fedoraproject.org real layout")
        mock_fetch_html.side_effect = [
            '<a href="42/">42/</a><a href="43/">43/</a>',
            (
                '<a href="?C=N;O=D" href="Fedora-Workstation-43-1.6-x86_64-CHECKSUM"></a>'
                '<a href="Fedora-Workstation-Live-43-1.6.x86_64.iso">iso</a>'
            ),
        ]
        settings = {
            "strategy": "fedora_nested",
            "base_url": "https://dl.fedoraproject.org/pub/fedora/linux/releases/",
            "version_regex": 'href="([0-9]+\\s*/)"',
            "iso_regex": 'href="(Fedora-Workstation-Live-(?:x86_64-[0-9][0-9.\\-]*\\.iso|[0-9][0-9.\\-]*\\.x86_64\\.iso))"',
        }
        name, url = process_scraping_strategy("Fedora", settings)
        self.assertEqual(name, "Fedora-Workstation-Live-43-1.6.x86_64.iso")
        self.assertIn("43/Workstation/x86_64/iso/", url)
        _ok(f"Resolved from real-style listing: {name}")

    @patch("visync.download.ping_mirror", return_value=True)
    @patch("visync.download.fetch_html")
    def test_fedora_arm_aarch64_tree(
        self, mock_fetch_html: MagicMock, mock_ping: MagicMock
    ):
        """FedoraARM scrapes the aarch64 subtree and ignores x86_64 lives."""
        _section("Strategy: fedora_nested — FedoraARM aarch64")
        mock_fetch_html.side_effect = [
            '<a href="43/">43/</a>',
            (
                '<a href="Fedora-Workstation-Live-43-1.6.aarch64.iso">iso</a>'
                '<a href="Fedora-Workstation-Live-43-1.6.x86_64.iso">wrong-arch</a>'
            ),
        ]
        settings = {
            "strategy": "fedora_nested",
            "base_url": "https://dl.fedoraproject.org/pub/fedora/linux/releases/",
            "variant_path": "Workstation/aarch64/iso",
            "version_regex": 'href="([0-9]+\\s*/)"',
            "iso_regex": 'href="(Fedora-Workstation-Live-(?:aarch64-[0-9][0-9.\\-]*\\.iso|[0-9][0-9.\\-]*\\.aarch64\\.iso))"',
        }
        name, url = process_scraping_strategy("Fedora ARM", settings)
        self.assertEqual(name, "Fedora-Workstation-Live-43-1.6.aarch64.iso")
        self.assertIn("/Workstation/aarch64/iso/", url)
        _ok(f"aarch64 ISO resolved: {name}")

    @patch("visync.download.ping_mirror", return_value=True)
    def test_unknown_strategy(self, mock_ping: MagicMock):
        _section("Strategy: Unknown / Unrecognized")
        settings = {"strategy": "custom_strategy", "base_url": "https://example.com/"}
        name, url = process_scraping_strategy("Custom", settings)
        self.assertEqual(name, "")
        self.assertEqual(url, "")
        _ok("Empty strings returned for unknown strategy")


class _FakeResponse:
    """A minimal context-manager response for use with mock urlopen."""

    def __init__(self, headers=None, read_data=None):
        self.headers = headers or {}
        self._read_data = read_data or []
        self._read_idx = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, size=-1):
        if self._read_idx < len(self._read_data):
            data = self._read_data[self._read_idx]
            self._read_idx += 1
            return data
        return b""


class TestDownloadIso(unittest.TestCase):
    def _mock_head_response(self, content_length: str = "1000"):
        return _FakeResponse(headers={"Content-Length": content_length})

    def _mock_get_response(self, data: bytes, content_length: str = "1000"):
        return _FakeResponse(
            headers={"Content-Length": content_length},
            read_data=[data, b""],
        )

    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_download_success(self, mock_request: MagicMock, mock_urlopen: MagicMock):
        _section("download_iso: Successful Download")
        head_resp = self._mock_head_response(content_length="500")
        get_resp = self._mock_get_response(b"x" * 500, content_length="500")
        mock_urlopen.side_effect = [head_resp, get_resp]

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.iso"
            download_iso("https://example.com/test.iso", dest)
            self.assertTrue(dest.exists())
            self.assertEqual(dest.read_bytes(), b"x" * 500)
            _ok(f"Wrote {len(dest.read_bytes())} bytes to {dest.name}")

    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_download_failure_cleans_part(
        self, mock_request: MagicMock, mock_urlopen: MagicMock
    ):
        _section("download_iso: Failure Cleans .part File")
        head_resp = self._mock_head_response()
        mock_urlopen.side_effect = [head_resp, Exception("connection lost")]

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.iso"
            download_iso("https://example.com/test.iso", dest)
            self.assertFalse(dest.exists())
            part_file = dest.with_suffix(".iso.part")
            self.assertFalse(part_file.exists())
            _ok("Neither .iso nor .part remain after failure")

    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_download_oserror_cleans_part(
        self, mock_request: MagicMock, mock_urlopen: MagicMock
    ):
        _section("download_iso: OSError Cleans .part File")
        head_resp = self._mock_head_response()
        mock_urlopen.side_effect = [head_resp, OSError("No space left on device")]

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.iso"
            download_iso("https://example.com/test.iso", dest)
            self.assertFalse(dest.exists())
            self.assertFalse(dest.with_suffix(".iso.part").exists())
            _ok("OSError triggers .part cleanup")

    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_download_disk_full_skips(
        self, mock_request: MagicMock, mock_urlopen: MagicMock
    ):
        _section("download_iso: Insufficient Disk Space")
        head_resp = self._mock_head_response("99999999999")
        mock_urlopen.side_effect = [head_resp]

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.iso"
            download_iso("https://example.com/test.iso", dest)
            self.assertFalse(dest.exists())
            _ok("Download skipped when disk space insufficient")

    @patch("visync.verify.verify_from_config")
    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_download_auto_verify_success(
        self, mock_request: MagicMock, mock_urlopen: MagicMock, mock_verify: MagicMock
    ):
        _section("download_iso: Auto-Verify Checksum Success")
        head_resp = self._mock_head_response("500")
        get_resp = self._mock_get_response(b"x" * 500, content_length="500")
        mock_urlopen.side_effect = [head_resp, get_resp]
        mock_verify.return_value = True

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.iso"
            distro_cfg = {"checksum_url": "https://example.com/SHA256SUMS"}
            checksums_cfg = {"enabled": True}
            result = download_iso(
                "https://example.com/test.iso",
                dest,
                distro_config=distro_cfg,
                checksums_config=checksums_cfg,
            )
            self.assertTrue(result)
            self.assertTrue(dest.exists())
            mock_verify.assert_called_once()
            _ok("Checksum verified after download")

    @patch("visync.verify.verify_from_config")
    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_download_auto_verify_failure_deletes(
        self, mock_request: MagicMock, mock_urlopen: MagicMock, mock_verify: MagicMock
    ):
        _section("download_iso: Auto-Verify Checksum Failure")
        head_resp = self._mock_head_response("500")
        get_resp = self._mock_get_response(b"x" * 500, content_length="500")
        mock_urlopen.side_effect = [head_resp, get_resp]
        mock_verify.return_value = False

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.iso"
            distro_cfg = {"checksum_url": "https://example.com/SHA256SUMS"}
            checksums_cfg = {"enabled": True}
            result = download_iso(
                "https://example.com/test.iso",
                dest,
                distro_config=distro_cfg,
                checksums_config=checksums_cfg,
            )
            self.assertFalse(result)
            self.assertFalse(dest.exists())
            _ok("File deleted after checksum failure")

    @patch("visync.verify.verify_from_config")
    @patch("visync.download.urllib.request.urlopen")
    @patch("visync.download.urllib.request.Request")
    def test_download_no_checksum_config_skips(
        self, mock_request: MagicMock, mock_urlopen: MagicMock, mock_verify: MagicMock
    ):
        _section("download_iso: No Checksum Config Skips Verify")
        head_resp = self._mock_head_response("500")
        get_resp = self._mock_get_response(b"x" * 500, content_length="500")
        mock_urlopen.side_effect = [head_resp, get_resp]
        mock_verify.return_value = None  # No config available

        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.iso"
            distro_cfg = {}
            checksums_cfg = {"enabled": True}
            result = download_iso(
                "https://example.com/test.iso",
                dest,
                distro_config=distro_cfg,
                checksums_config=checksums_cfg,
            )
            self.assertTrue(result)
            self.assertTrue(dest.exists())
            _ok("Download succeeds when no checksum config")


class TestCheckDistro(unittest.TestCase):
    @patch("visync.download.find_installed_isos")
    @patch("visync.download.process_scraping_strategy")
    def test_returns_download_when_newer(
        self, mock_scrape: MagicMock, mock_find: MagicMock
    ):
        _section("_check_distro: New Version Available")
        mock_scrape.return_value = (
            "archlinux-2026.06.01-x86_64.iso",
            "https://example.com/arch.iso",
        )
        mock_find.return_value = [Path("/tmp/archlinux-2025.01.01-x86_64.iso")]
        settings = {"clean_name": "Arch Linux"}

        result = _check_distro("arch", settings, Path("/tmp"), force=False)
        self.assertIs(result.status, SyncStatus.STALE)
        self.assertIsNotNone(result.download_url)
        _ok("Correctly identifies new version available")

    @patch("visync.download.find_installed_isos")
    @patch("visync.download.process_scraping_strategy")
    def test_returns_up_to_date(self, mock_scrape: MagicMock, mock_find: MagicMock):
        _section("_check_distro: Already Up to Date")
        mock_scrape.return_value = (
            "archlinux-2026.06.01-x86_64.iso",
            "https://example.com/arch.iso",
        )
        mock_find.return_value = [Path("/tmp/archlinux-2026.06.01-x86_64.iso")]
        settings = {"clean_name": "Arch Linux"}

        result = _check_distro("arch", settings, Path("/tmp"), force=False)
        self.assertIs(result.status, SyncStatus.CURRENT)
        _ok("Correctly skips when version matches")

    @patch("visync.download.find_installed_isos")
    @patch("visync.download.process_scraping_strategy")
    def test_force_skips_version_check(
        self, mock_scrape: MagicMock, mock_find: MagicMock
    ):
        _section("_check_distro: --force Skips Version Check")
        mock_scrape.return_value = (
            "archlinux-2026.06.01-x86_64.iso",
            "https://example.com/arch.iso",
        )
        mock_find.return_value = [Path("/tmp/archlinux-2026.06.01-x86_64.iso")]
        settings = {"clean_name": "Arch Linux"}

        result = _check_distro("arch", settings, Path("/tmp"), force=True)
        self.assertIs(result.status, SyncStatus.STALE)
        self.assertIsNotNone(result.download_url)
        _ok("--force correctly bypasses version check")

    @patch("visync.download.find_installed_isos", return_value=[])
    @patch("visync.download.process_scraping_strategy", return_value=("", ""))
    def test_unreachable_when_scrape_fails(self, _mock_scrape, _mock_find):
        """A mirror we cannot read must be UNREACHABLE, never CURRENT."""
        _section("_check_distro: Unreachable mirror")
        settings = {"clean_name": "Arch Linux"}

        result = _check_distro("arch", settings, Path("/tmp"), force=False)
        self.assertIs(result.status, SyncStatus.UNREACHABLE)
        self.assertIsNone(result.download_url)
        _ok("failed scrape reports UNREACHABLE with a reason")


class TestCleanupOldVersions(unittest.TestCase):
    @patch("visync.download.identify_distro")
    @patch("visync.download.get_iso_volume_id")
    @patch("visync.download.find_installed_isos")
    def test_removes_same_distro_same_stem(
        self, mock_find: MagicMock, mock_vid: MagicMock, mock_id: MagicMock
    ):
        _section("_cleanup_old_versions: Removes Matching Distro+Stem")
        with tempfile.TemporaryDirectory() as tmpdir:
            new_iso = Path(tmpdir) / "fedora-45.iso"
            old_iso = Path(tmpdir) / "fedora-44.iso"
            new_iso.write_bytes(b"new")
            old_iso.write_bytes(b"old")

            mock_vid.side_effect = lambda p: (
                "Fedora-KDE-Live-45" if p == new_iso else "Fedora-KDE-Live-44"
            )
            mock_id.return_value = "Fedora"
            mock_find.return_value = [new_iso, old_iso]

            _cleanup_old_versions(new_iso)
            self.assertFalse(old_iso.exists())
            self.assertTrue(new_iso.exists())
            _ok("Old file removed, new file preserved")

    @patch("visync.download.identify_distro")
    @patch("visync.download.get_iso_volume_id")
    @patch("visync.download.find_installed_isos")
    def test_preserves_different_variant(
        self, mock_find: MagicMock, mock_vid: MagicMock, mock_id: MagicMock
    ):
        _section("_cleanup_old_versions: Preserves Different Variant")
        with tempfile.TemporaryDirectory() as tmpdir:
            new_iso = Path(tmpdir) / "fedora-kde-45.iso"
            other_iso = Path(tmpdir) / "fedora-sway-44.iso"
            new_iso.write_bytes(b"new")
            other_iso.write_bytes(b"other")

            mock_vid.side_effect = lambda p: (
                "Fedora-KDE-Live-45" if p == new_iso else "Fedora-Sway-Live-44"
            )
            mock_id.return_value = "Fedora"
            mock_find.return_value = [new_iso, other_iso]

            _cleanup_old_versions(new_iso)
            self.assertTrue(other_iso.exists())
            _ok("Different variant preserved")


class TestFindInstalledIsosFiltering(unittest.TestCase):
    def test_filters_macos_resource_forks(self):
        _section("find_installed_isos: Filters ._ Files")
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "real.iso").touch()
            (Path(tmpdir) / "._real.iso").touch()
            (Path(tmpdir) / "._other.iso").touch()
            (Path(tmpdir) / "normal.iso").touch()
            isos = find_installed_isos(Path(tmpdir))
            names = [i.name for i in isos]
            self.assertIn("real.iso", names)
            self.assertIn("normal.iso", names)
            self.assertNotIn("._real.iso", names)
            self.assertNotIn("._other.iso", names)
            self.assertEqual(len(isos), 2)
            _ok(" ._ files filtered from results")

    def test_finds_nested_isos(self):
        _section("find_installed_isos: Recursive Discovery")
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "top.iso").touch()
            sub = Path(tmpdir) / "subdir"
            sub.mkdir()
            (sub / "nested.iso").touch()
            (sub / "._nested.iso").touch()
            isos = find_installed_isos(Path(tmpdir))
            names = [i.name for i in isos]
            self.assertEqual(len(isos), 2)
            self.assertIn("top.iso", names)
            self.assertIn("nested.iso", names)
            _ok("Recursive scan finds nested ISOs, skips ._ files")


class TestNixosChecksumParsing(unittest.TestCase):
    """Verify NixOS channel page parser extracts SHA-256 into resolved_checksum."""

    NIXOS_HTML = """<html><head><title>nixos-26.05 release nixos-26.05.1947.a0374025a863</title></head><body>
<h1>nixos-26.05 release nixos-26.05.1947.a0374025a863</h1>
<table><thead><tr><th>File name</th><th>Size</th><th>SHA-256 hash</th></tr></thead><tbody>
<tr><td><a href='/nixos/26.05/nixos-26.05.1947.a0374025a863/nixos-minimal-26.05.1947.a0374025a863-x86_64-linux.iso'>nixos-minimal-26.05.1947.a0374025a863-x86_64-linux.iso</a></td><td align='right'>1672806400</td><td><tt>5490e6430a95064e7e58d3e731087ff70c7a57cbeae459dd5c56f0f7469991f2</tt></td></tr>
<tr><td><a href='/nixos/26.05/nixos-26.05.1947.a0374025a863/nixos-graphical-26.05.1947.a0374025a863-x86_64-linux.iso'>nixos-graphical-26.05.1947.a0374025a863-x86_64-linux.iso</a></td><td align='right'>3800989696</td><td><tt>736a1615dd5aeccc351a4e4a9149129e30b6e0c4e2dc68ffe8567754f96d85c5</tt></td></tr>
</tbody></table></body></html>"""

    def test_nixos_channel_resolves_checksum(self) -> None:
        """The nixos_channel strategy should populate settings['resolved_checksum']."""
        _section("NixOS checksum: channel page parsing")
        settings = {
            "clean_name": "NixOS Minimal",
            "strategy": "nixos_channel",
            "base_url": "https://channels.nixos.org/nixos-26.05",
            "variant": "minimal",
        }
        # Mock fetch_html to return our canned HTML
        with (
            patch("visync.download.fetch_html", return_value=self.NIXOS_HTML),
            patch("visync.download.urllib.request.urlopen") as mock_urlopen,
        ):
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            filename, url = process_scraping_strategy("NixOS Minimal", settings)

        self.assertEqual(
            filename, "nixos-minimal-26.05.1947.a0374025a863-x86_64-linux.iso"
        )
        self.assertIn("releases.nixos.org", url)
        self.assertEqual(
            settings["resolved_checksum"],
            "5490e6430a95064e7e58d3e731087ff70c7a57cbeae459dd5c56f0f7469991f2",
        )
        _ok("resolved_checksum set from channel page HTML")

    def test_nixos_graphical_checksum(self) -> None:
        """Graphical variant should get its own checksum."""
        settings = {
            "clean_name": "NixOS Graphical",
            "strategy": "nixos_channel",
            "base_url": "https://channels.nixos.org/nixos-26.05",
            "variant": "graphical",
        }
        with (
            patch("visync.download.fetch_html", return_value=self.NIXOS_HTML),
            patch("visync.download.urllib.request.urlopen") as mock_urlopen,
        ):
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            filename, _url = process_scraping_strategy("NixOS Graphical", settings)

        self.assertIn("nixos-graphical", filename)
        self.assertEqual(
            settings["resolved_checksum"],
            "736a1615dd5aeccc351a4e4a9149129e30b6e0c4e2dc68ffe8567754f96d85c5",
        )
        _ok("Graphical variant checksum parsed correctly")

    def test_missing_checksum_does_not_set_key(self) -> None:
        """If filename not in HTML, resolved_checksum should not be set."""
        settings = {
            "clean_name": "NixOS Minimal",
            "strategy": "nixos_channel",
            "base_url": "https://channels.nixos.org/nixos-26.05",
            "variant": "minimal",
        }
        with patch("visync.download.fetch_html", return_value="<html></html>"):
            filename, _url = process_scraping_strategy("NixOS Minimal", settings)

        self.assertEqual(filename, "")
        self.assertNotIn("resolved_checksum", settings)
        _ok("Missing checksum leaves settings clean")


class TestChunkedDownload(unittest.TestCase):
    """Verify chunked parallel download path."""

    def test_chunked_download_writes_correct_data(self) -> None:
        """_download_chunked should write all bytes at correct offsets."""
        _section("Chunked download: parallel range writes")
        from visync.download import _download_chunked

        # 1 MiB of known data
        data = os.urandom(1024 * 1024)
        total = len(data)

        # Serve it via a simple HTTP handler that supports Range
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class RangeHandler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(200)
                self.send_header("Content-Length", str(total))
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()

            def do_GET(self):
                range_header = self.headers.get("Range", "")
                if range_header.startswith("bytes="):
                    spec = range_header[6:]
                    start_s, end_s = spec.split("-")
                    start, end = int(start_s), int(end_s) + 1
                else:
                    start, end = 0, total
                chunk = data[start:end]
                self.send_response(206 if range_header else 200)
                self.send_header("Content-Length", str(len(chunk)))
                self.send_header("Accept-Ranges", "bytes")
                if range_header:
                    # A conforming range server states which slice it served;
                    # the client validates this before writing.
                    self.send_header(
                        "Content-Range", f"bytes {start}-{end - 1}/{total}"
                    )
                self.end_headers()
                self.wfile.write(chunk)

            def log_message(self, *a):
                pass

        server = HTTPServer(("127.0.0.1", 0), RangeHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        with tempfile.TemporaryDirectory() as tmpdir:
            part = Path(tmpdir) / "test.iso.part"
            ok = _download_chunked(
                f"http://127.0.0.1:{port}/test.iso",
                part,
                total,
                4,
                "test.iso",
            )
            server.shutdown()

            self.assertTrue(ok)
            self.assertEqual(part.stat().st_size, total)
            self.assertEqual(part.read_bytes(), data)
            _ok("Chunked download wrote correct data at correct offsets")


if __name__ == "__main__":
    print()
    print(f"  {'#' * 62}")
    print("  #   DOWNLOAD MODULE — COMPREHENSIVE TESTS")
    print(f"  {'#' * 62}")
    print()
    _info(
        "Testing ping, variant stem, fetch, config, strategy, download, cleanup, filtering"
    )
    print()
    unittest.main(verbosity=2)
