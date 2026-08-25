"""Tests for verify CLI wiring and version-aware checksum URL expansion."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.verify import (
    expand_url,
    extract_iso_metadata,
    index_distro_configs,
    resolve_distro_settings,
    run_directory_verify,
)

try:
    from typer.testing import CliRunner

    HAS_TYPER = True
except ImportError:
    HAS_TYPER = False
    CliRunner = None  # type: ignore[misc, assignment]


class TestExtractIsoMetadata(unittest.TestCase):
    def test_fedora_kde_iso(self) -> None:
        meta = extract_iso_metadata("Fedora-KDE-Desktop-Live-44-1.7.x86_64.iso")
        self.assertEqual(meta["version"], "44")
        self.assertEqual(meta["arch"], "x86_64")
        self.assertEqual(meta["variant_dir"], "KDE")
        # dl.fedoraproject.org CHECKSUM convention: Fedora-{variant}-{maj}-{min}-{arch}
        self.assertEqual(meta["checksum_stem"], "Fedora-KDE-44-1.7-x86_64")

    def test_fedora_modern_naming(self) -> None:
        """Modern Fedora spins carry arch as an infix, not a suffix."""
        meta = extract_iso_metadata("Fedora-Workstation-Live-x86_64-42-1.1.iso")
        self.assertEqual(meta["version"], "42")
        self.assertEqual(meta["arch"], "x86_64")
        self.assertEqual(meta["variant_dir"], "Workstation")
        self.assertEqual(
            meta["checksum_stem"], "Fedora-Workstation-Live-x86_64-42-1.1"
        )

    def test_ubuntu_server_iso(self) -> None:
        meta = extract_iso_metadata("ubuntu-24.04.4-live-server-amd64.iso")
        self.assertEqual(meta["version"], "24.04.4")

    def test_arch_iso(self) -> None:
        meta = extract_iso_metadata("archlinux-2026.05.01-x86_64.iso")
        self.assertEqual(meta["version"], "2026.05.01")


class TestExpandUrlVersion(unittest.TestCase):
    def test_ubuntu_checksum_url(self) -> None:
        url = expand_url(
            "{base_url}{version}/SHA256SUMS",
            "ubuntu-24.04.4-live-server-amd64.iso",
            "https://releases.ubuntu.com/",
        )
        self.assertEqual(url, "https://releases.ubuntu.com/24.04.4/SHA256SUMS")

    def test_fedora_checksum_url(self) -> None:
        url = expand_url(
            "{base_url}{version}/{variant_dir}/{arch}/iso/{checksum_stem}-CHECKSUM",
            "Fedora-KDE-Desktop-Live-44-1.7.x86_64.iso",
            "https://dl.fedoraproject.org/pub/fedora/linux/releases/",
        )
        self.assertEqual(
            url,
            "https://dl.fedoraproject.org/pub/fedora/linux/releases/"
            "44/KDE/x86_64/iso/Fedora-KDE-44-1.7-x86_64-CHECKSUM",
        )

    def test_fedora_checksum_url_workstation_real_layout(self) -> None:
        url = expand_url(
            "{base_url}{version}/{variant_dir}/{arch}/iso/{checksum_stem}-CHECKSUM",
            "Fedora-Workstation-Live-43-1.6.x86_64.iso",
            "https://dl.fedoraproject.org/pub/fedora/linux/releases/",
        )
        self.assertEqual(
            url,
            "https://dl.fedoraproject.org/pub/fedora/linux/releases/"
            "43/Workstation/x86_64/iso/Fedora-Workstation-43-1.6-x86_64-CHECKSUM",
        )

    def test_fedora_checksum_url_modern_naming(self) -> None:
        url = expand_url(
            "{base_url}{version}/{variant_dir}/{arch}/iso/{checksum_stem}-CHECKSUM",
            "Fedora-Workstation-Live-x86_64-42-1.1.iso",
            "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/",
        )
        self.assertEqual(
            url,
            "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/"
            "42/Workstation/x86_64/iso/Fedora-Workstation-Live-x86_64-42-1.1-CHECKSUM",
        )


class TestResolveDistroSettings(unittest.TestCase):
    def setUp(self) -> None:
        self.configs = index_distro_configs(
            {
                "distros": {
                    "ArchLinux": {
                        "clean_name": "Arch Linux",
                        "keyword": "archlinux",
                        "checksum_url": "https://example.com/sha256sums.txt",
                    },
                    "UbuntuServer": {
                        "clean_name": "Ubuntu Server",
                        "keyword": "live-server",
                        "checksum_url": "https://example.com/ubuntu/SHA256SUMS",
                    },
                }
            }
        )

    def test_exact_clean_name_match(self) -> None:
        settings = resolve_distro_settings("Arch Linux", "archlinux-2026.iso", self.configs)
        self.assertEqual(settings.get("checksum_url"), "https://example.com/sha256sums.txt")

    def test_keyword_fallback_for_ubuntu_server(self) -> None:
        settings = resolve_distro_settings(
            "Ubuntu",
            "ubuntu-24.04-live-server-amd64.iso",
            self.configs,
        )
        self.assertEqual(settings.get("checksum_url"), "https://example.com/ubuntu/SHA256SUMS")


class TestRunDirectoryVerify(unittest.TestCase):
    @patch("src.verify.verify_from_config")
    @patch("src.verify.build_iso_distro_map")
    def test_runs_one_verify_per_iso(
        self, mock_map: MagicMock, mock_verify: MagicMock
    ) -> None:
        iso = Path("/tmp/test.iso")
        mock_map.return_value = {str(iso): (iso, "Arch Linux")}
        mock_verify.return_value = True

        config = {
            "checksums": {"enabled": True},
            "distros": {
                "ArchLinux": {
                    "clean_name": "Arch Linux",
                    "keyword": "archlinux",
                    "checksum_url": "{base_url}sha256sums.txt",
                    "base_url": "https://example.com/",
                }
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            results = run_directory_verify(Path(tmpdir), config)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][2], True)
        mock_verify.assert_called_once()


@unittest.skipUnless(HAS_TYPER, "typer not installed")
class TestVerifyCommand(unittest.TestCase):
    def setUp(self) -> None:
        from src.main import app

        self.app = app
        self.runner = CliRunner()

    @patch("src.main.run_directory_verify")
    @patch("src.main.find_ventoy_drives")
    @patch("src.main.load_config")
    def test_verify_command_success(
        self,
        mock_load: MagicMock,
        mock_drives: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        mock_load.return_value = {"checksums": {"enabled": True}, "distros": {}}
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_drive = Path(tmpdir)
            mock_drives.return_value = [fake_drive]
            mock_run.return_value = [(fake_drive / "arch.iso", "Arch Linux", True)]

            result = self.runner.invoke(self.app, ["verify"])

            self.assertEqual(result.exit_code, 0)
            self.assertIn("✓", result.stdout)
            self.assertIn("1 verified", result.stdout)

    @patch("src.main.run_directory_verify")
    @patch("src.main.load_config")
    def test_verify_command_fails_on_bad_checksum(
        self, mock_load: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_load.return_value = {"checksums": {"enabled": True}, "distros": {}}
        mock_run.return_value = [(Path("/tmp/bad.iso"), "Arch Linux", False)]

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(self.app, ["verify", "--drive", tmpdir])

        self.assertEqual(result.exit_code, 1)
        output = result.stdout + result.stderr
        self.assertIn("✗", output)

    @patch("src.main.find_ventoy_drives", return_value=[])
    @patch("src.main.load_config", return_value={})
    def test_verify_command_no_ventoy(self, _load: MagicMock, _drives: MagicMock) -> None:
        result = self.runner.invoke(self.app, ["verify"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No Ventoy drives detected", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
