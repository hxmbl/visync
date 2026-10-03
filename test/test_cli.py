"""Strict CLI tests — every command, every flag, every edge case."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import typer

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typer.testing import CliRunner

from visync import main as visync_main
from visync.main import _get_drives, app

runner = CliRunner()

MOCK_CONFIG = {
    "distros": {
        "ArchLinux": {
            "clean_name": "Arch Linux",
            "strategy": "direct_match",
            "base_url": "https://example.com/arch/",
            "keyword": "archlinux",
            "checksum_format": "sha256sums",
        },
        "UbuntuServer": {
            "clean_name": "Ubuntu Server",
            "strategy": "ubuntu_nested",
            "base_url": "https://example.com/ubuntu/",
            "keyword": "live-server",
            "checksum_format": "sha256sums",
        },
    }
}


def _mock_find_installed(iso_dir: Path) -> list[Path]:
    return sorted(iso_dir.glob("*.iso"))


def _make_ventoy_dir(tmpdir: str) -> Path:
    """Give a temp dir the marker that makes --drive treat it as a real drive.

    Without this, a test that exercises a command's own prompt would have its
    "n" swallowed by the not-a-Ventoy-drive prompt, and --yes would skip both.
    """
    (Path(tmpdir) / "ventoy").mkdir(exist_ok=True)
    return Path(tmpdir)


def _mock_get_vid(iso_path: Path) -> str:
    return ""


def _mock_identify_distro(vid: str, filename: str) -> str:
    fn = filename.lower()
    if "archlinux" in fn or "arch" in fn:
        return "Arch Linux"
    if "ubuntu" in fn and "server" in fn:
        return "Ubuntu Server"
    if "ubuntu" in fn:
        return "Ubuntu"
    return "Unknown OS"


# ── install ──────────────────────────────────────────────────────────────────


class TestInstall(unittest.TestCase):
    @patch("visync.main.find_ventoy_drives", return_value=[])
    @patch("visync.main.load_config")
    def test_install_requires_name_or_file(self, *_: MagicMock) -> None:
        result = runner.invoke(app, ["install"])
        self.assertNotEqual(result.exit_code, 0)

    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.get_iso_volume_id", side_effect=_mock_get_vid)
    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_install_unknown_distro_fails(
        self, mock_cfg: MagicMock, *_: MagicMock
    ) -> None:
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                app, ["--yes", "install", "bogus-distro", "--drive", tmpdir]
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("Unknown distro", result.stdout)

    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    def test_install_dry_run_does_not_download(self, _mock: MagicMock) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch("visync.main.load_config", return_value=MOCK_CONFIG),
        ):
            result = runner.invoke(
                app, ["--yes", "install", "archlinux", "--drive", tmpdir, "--dry-run"]
            )
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Would download", result.stdout)
            self.assertEqual(list(Path(tmpdir).glob("*.iso")), [])

    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_install_ambiguous_query_lists_candidates(
        self, mock_cfg: MagicMock, _mock: MagicMock
    ) -> None:
        """Ambiguous install queries must list candidates, not just say unknown."""
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["--yes", "install", "u", "--drive", tmpdir])
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("Ambiguous distro", result.stdout)
            self.assertIn("Arch Linux", result.stdout)
            self.assertIn("Ubuntu Server", result.stdout)

    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_install_dry_run_creates_no_staging_dir(
        self, mock_cfg: MagicMock, _mock: MagicMock
    ) -> None:
        """--dry-run must not create the staging cache directory."""
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("visync.main.Path.home", return_value=Path(tmpdir)):
                result = runner.invoke(
                    app,
                    ["--yes", "install", "archlinux", "--drive", tmpdir, "--dry-run"],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertIn("Would download", result.stdout)
            self.assertFalse((Path(tmpdir) / ".cache" / "visync" / "staging").exists())

    @patch("visync.pm.mark_installed")
    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.get_iso_volume_id", side_effect=_mock_get_vid)
    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_install_already_on_drive(self, mock_cfg: MagicMock, *_: MagicMock) -> None:
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "archlinux-2026.iso"
            iso.write_bytes(b"\x00" * 1024)
            result = runner.invoke(
                app, ["--yes", "install", "archlinux", "--drive", tmpdir]
            )
            self.assertEqual(result.exit_code, 0)
            self.assertIn("already on the drive", result.stdout)

    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.get_iso_volume_id", side_effect=_mock_get_vid)
    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_install_dry_run_leaves_state_file_untouched(
        self, mock_cfg: MagicMock, *_: MagicMock
    ) -> None:
        """--dry-run must not rewrite installed.json, nor blank a recorded version."""
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "archlinux-2026.iso"
            iso.write_bytes(b"\x00" * 1024)
            state = Path(tmpdir) / ".visync" / "installed.json"
            state.parent.mkdir(parents=True)
            state.write_text(
                '{"ArchLinux": {"installed_at": "2026-01-01T00:00:00+00:00",'
                ' "version": "2026.01.01"}}'
            )
            before = state.read_bytes()

            result = runner.invoke(
                app, ["--yes", "install", "archlinux", "--drive", tmpdir, "--dry-run"]
            )

            self.assertEqual(result.exit_code, 0)
            self.assertEqual(
                state.read_bytes(), before, "--dry-run must not write drive state"
            )
            self.assertIn("2026.01.01", state.read_text(), "version must survive")

    def test_install_file_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                app,
                [
                    "--yes",
                    "install",
                    "-i",
                    "/nonexistent/packages.txt",
                    "--drive",
                    tmpdir,
                ],
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("File not found", result.stdout)

    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    def test_install_file_with_comments_and_blanks(self, _mock: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_file = Path(tmpdir) / "packages.txt"
            pkg_file.write_text("# comment\n\narchlinux\n\n# another comment\n")
            with patch("visync.main.load_config", return_value=MOCK_CONFIG):
                result = runner.invoke(
                    app,
                    [
                        "--yes",
                        "install",
                        "-i",
                        str(pkg_file),
                        "--drive",
                        tmpdir,
                        "--dry-run",
                    ],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertIn("Would download 1 distro(s)", result.stdout)

    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    def test_install_file_multiple_distros(self, _mock: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_file = Path(tmpdir) / "packages.txt"
            pkg_file.write_text("archlinux\nubuntuserver\n")
            with patch("visync.main.load_config", return_value=MOCK_CONFIG):
                result = runner.invoke(
                    app,
                    [
                        "--yes",
                        "install",
                        "-i",
                        str(pkg_file),
                        "--drive",
                        tmpdir,
                        "--dry-run",
                    ],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertIn("Would download 2 distro(s)", result.stdout)

    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    def test_install_file_no_valid_distros(self, _mock: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_file = Path(tmpdir) / "packages.txt"
            pkg_file.write_text("bogus1\nbogus2\n")
            with patch("visync.main.load_config", return_value=MOCK_CONFIG):
                result = runner.invoke(
                    app, ["--yes", "install", "-i", str(pkg_file), "--drive", tmpdir]
                )
                self.assertNotEqual(result.exit_code, 0)
                self.assertIn("No valid distros", result.stdout)

    def test_install_has_all_flags(self) -> None:
        result = runner.invoke(app, ["install", "--help"])
        for flag in ["--config", "--drive", "--dry-run", "--file"]:
            self.assertIn(flag, result.stdout, f"install missing {flag}")


# ── remove ───────────────────────────────────────────────────────────────────


class TestRemove(unittest.TestCase):
    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.get_iso_volume_id", side_effect=_mock_get_vid)
    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_remove_unknown_distro_fails(
        self, mock_cfg: MagicMock, *_: MagicMock
    ) -> None:
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                app, ["--yes", "remove", "bogus-distro", "--drive", tmpdir]
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("Unknown distro", result.stdout)

    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.get_iso_volume_id", side_effect=_mock_get_vid)
    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_remove_no_files_warns(self, mock_cfg: MagicMock, *_: MagicMock) -> None:
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                app, ["--yes", "remove", "archlinux", "--drive", tmpdir]
            )
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No files found", result.stdout)

    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.get_iso_volume_id", side_effect=_mock_get_vid)
    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_remove_dry_run_does_not_delete(
        self, mock_cfg: MagicMock, *_: MagicMock
    ) -> None:
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "archlinux-2026.iso"
            iso.write_bytes(b"\x00" * 1024)
            result = runner.invoke(
                app, ["--yes", "remove", "archlinux", "--drive", tmpdir, "--dry-run"]
            )
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Would remove", result.stdout)
            self.assertTrue(iso.exists(), "File should still exist after dry-run")

    @patch("visync.finder.remove_iso_metadata")
    @patch("visync.pm.mark_removed")
    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.get_iso_volume_id", side_effect=_mock_get_vid)
    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_remove_deletes_file(self, mock_cfg: MagicMock, *_: MagicMock) -> None:
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "archlinux-2026.iso"
            iso.write_bytes(b"\x00" * 1024)
            result = runner.invoke(
                app, ["--yes", "remove", "archlinux", "--drive", tmpdir, "--yes"]
            )
            self.assertEqual(result.exit_code, 0)
            self.assertFalse(iso.exists(), "File should be deleted")
            self.assertIn("removed", result.stdout)

    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.get_iso_volume_id", side_effect=_mock_get_vid)
    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_remove_requires_confirmation_without_yes(
        self, mock_cfg: MagicMock, *_: MagicMock
    ) -> None:
        """Without --yes and without interactive confirmation, nothing is deleted."""
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_ventoy_dir(tmpdir)
            iso = Path(tmpdir) / "archlinux-2026.iso"
            iso.write_bytes(b"\x00" * 1024)
            # No input provided -> confirm() aborts -> file must survive
            result = runner.invoke(app, ["remove", "archlinux", "--drive", tmpdir])
            self.assertNotEqual(result.exit_code, 0)
            self.assertTrue(iso.exists(), "File must survive aborted confirmation")

    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.get_iso_volume_id", side_effect=_mock_get_vid)
    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_remove_confirm_no_keeps_file(
        self, mock_cfg: MagicMock, *_: MagicMock
    ) -> None:
        """Answering 'n' to the confirmation keeps the file."""
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_ventoy_dir(tmpdir)
            iso = Path(tmpdir) / "archlinux-2026.iso"
            iso.write_bytes(b"\x00" * 1024)
            result = runner.invoke(
                app, ["remove", "archlinux", "--drive", tmpdir], input="n\n"
            )
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(iso.exists())
            self.assertIn("nothing deleted", result.stdout)

    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.get_iso_volume_id", side_effect=_mock_get_vid)
    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_remove_global_yes_also_skips_the_prompt(
        self, mock_cfg: MagicMock, *_: MagicMock
    ) -> None:
        """`--yes` before the command means the same as `remove --yes`.

        The global flag answers every confirmation, so a script can put it once
        at the front instead of remembering which commands have their own.
        """
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "archlinux-2026.iso"
            iso.write_bytes(b"\x00" * 1024)
            result = runner.invoke(
                app, ["--yes", "remove", "archlinux", "--drive", tmpdir]
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertFalse(iso.exists(), "global --yes must skip the prompt")
            self.assertNotIn("Delete these file(s)?", result.output)

    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.get_iso_volume_id", side_effect=_mock_get_vid)
    @patch("visync.main.find_installed_isos", side_effect=_mock_find_installed)
    @patch("visync.main.load_config")
    def test_remove_ambiguous_query_fails(
        self, mock_cfg: MagicMock, *_: MagicMock
    ) -> None:
        """Ambiguous partial queries list candidates instead of picking one."""
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["--yes", "remove", "u", "--drive", tmpdir])
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("Ambiguous distro", result.stdout)
            self.assertIn("Arch Linux", result.stdout)
            self.assertIn("Ubuntu Server", result.stdout)

    def test_remove_has_flags(self) -> None:
        result = runner.invoke(app, ["remove", "--help"])
        for flag in ["--config", "--drive", "--dry-run"]:
            self.assertIn(flag, result.stdout, f"remove missing {flag}")


# ── update ───────────────────────────────────────────────────────────────────


class TestUpdate(unittest.TestCase):
    @patch("visync.main.find_ventoy_drives", return_value=[Path("/tmp")])
    @patch("visync.main.load_config")
    def test_update_no_installed(self, *_: MagicMock) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch("visync.main.find_ventoy_drives", return_value=[Path(tmpdir)]),
        ):
            result = runner.invoke(app, ["update"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No distros installed", result.stdout)

    def test_update_has_flags(self) -> None:
        result = runner.invoke(app, ["update", "--help"])
        for flag in ["--config", "--drive", "--force", "--clean", "--dry-run"]:
            self.assertIn(flag, result.stdout, f"update missing {flag}")

    @patch("visync.main.load_config")
    def test_update_unknown_distro_fails(self, mock_cfg: MagicMock) -> None:
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                app, ["--yes", "update", "bogus-distro", "--drive", tmpdir]
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("Unknown distro", result.stdout)


# ── search ───────────────────────────────────────────────────────────────────


class TestSearch(unittest.TestCase):
    @patch("visync.pm.get_installed_ids", return_value=[])
    @patch("visync.main.find_ventoy_drives", return_value=[Path("/tmp")])
    @patch("visync.main.load_config", return_value=MOCK_CONFIG)
    def test_search_lists_distros(self, *_: MagicMock) -> None:
        result = runner.invoke(app, ["search"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Arch Linux", result.stdout)
        self.assertIn("Ubuntu Server", result.stdout)

    @patch("visync.pm.get_installed_ids", return_value=[])
    @patch("visync.main.find_ventoy_drives", return_value=[Path("/tmp")])
    @patch("visync.main.load_config", return_value=MOCK_CONFIG)
    def test_search_by_query(self, *_: MagicMock) -> None:
        result = runner.invoke(app, ["search", "archlinux"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Arch Linux", result.stdout)

    @patch("visync.pm.get_installed_ids", return_value=[])
    @patch("visync.main.find_ventoy_drives", return_value=[Path("/tmp")])
    @patch("visync.main.load_config", return_value=MOCK_CONFIG)
    def test_search_no_match(self, *_: MagicMock) -> None:
        result = runner.invoke(app, ["search", "bogus"])
        self.assertIn("No match", result.stdout)

    def test_search_has_config_and_drive(self) -> None:
        result = runner.invoke(app, ["search", "--help"])
        self.assertIn("--config", result.stdout)
        self.assertIn("--drive", result.stdout)

    @patch("visync.main.load_config", return_value={"distros": {}})
    def test_search_no_distros_configured(self, _mock: MagicMock) -> None:
        result = runner.invoke(app, ["search"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("No distros configured", result.stdout)

    def test_search_does_not_have_dry_run(self) -> None:
        result = runner.invoke(app, ["search", "--help"])
        self.assertNotIn("--dry-run", result.stdout)

    @patch("visync.main.load_config", return_value=MOCK_CONFIG)
    def test_search_works_with_no_drive_attached(self, *_: MagicMock) -> None:
        """Browsing the catalogue must not require the drive to be plugged in."""
        with patch("visync.main.find_ventoy_drives", return_value=[]):
            result = runner.invoke(app, ["search"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Arch Linux", result.stdout)
        self.assertIn("no Ventoy drive detected", result.stdout)

    @patch("visync.pm.get_installed_ids", return_value=[])
    @patch("visync.main.load_config", return_value=MOCK_CONFIG)
    def test_search_by_query_works_with_no_drive(self, *_: MagicMock) -> None:
        with patch("visync.main.find_ventoy_drives", return_value=[]):
            result = runner.invoke(app, ["search", "archlinux"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Arch Linux", result.stdout)
        self.assertIn("no Ventoy drive detected", result.stdout)

    @patch("visync.pm.get_installed_ids", return_value=[])
    @patch("visync.main.load_config", return_value=MOCK_CONFIG)
    def test_explicit_drive_still_validated_for_search(self, *_: MagicMock) -> None:
        """An explicit --drive that is not there is still a typo, not a hint."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                app, ["--yes", "search", "--drive", str(Path(tmpdir) / "nope")]
            )
        self.assertEqual(result.exit_code, 1)


# ── info ─────────────────────────────────────────────────────────────────────


class TestInfo(unittest.TestCase):
    @patch("visync.pm.get_installed_ids", return_value=[])
    @patch("visync.main.find_ventoy_drives", return_value=[Path("/tmp")])
    @patch("visync.main.load_config", return_value=MOCK_CONFIG)
    def test_info_shows_details(self, *_: MagicMock) -> None:
        result = runner.invoke(app, ["info", "archlinux"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Arch Linux", result.stdout)
        self.assertIn("strategy:", result.stdout)

    @patch("visync.main.find_ventoy_drives", return_value=[Path("/tmp")])
    @patch("visync.main.load_config", return_value=MOCK_CONFIG)
    def test_info_unknown_distro_fails(self, *_: MagicMock) -> None:
        result = runner.invoke(app, ["info", "bogus-distro"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Unknown distro", result.stdout)

    def test_info_has_flags(self) -> None:
        result = runner.invoke(app, ["info", "--help"])
        self.assertIn("--config", result.stdout)
        self.assertIn("--drive", result.stdout)

    def test_info_does_not_have_dry_run(self) -> None:
        result = runner.invoke(app, ["info", "--help"])
        self.assertNotIn("--dry-run", result.stdout)

    @patch("visync.main.load_config", return_value=MOCK_CONFIG)
    def test_info_works_with_no_drive_attached(self, *_: MagicMock) -> None:
        """`info` describes the catalogue entry, which needs no drive."""
        with patch("visync.main.find_ventoy_drives", return_value=[]):
            result = runner.invoke(app, ["info", "archlinux"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Arch Linux", result.stdout)
        self.assertIn("no Ventoy drive detected", result.stdout)


# ── autodetect ───────────────────────────────────────────────────────────────


class TestAutodetect(unittest.TestCase):
    @patch("visync.pm.get_installed_ids", return_value=[])
    @patch("visync.main.load_config")
    def test_autodetect_no_files(self, mock_cfg: MagicMock, *_: MagicMock) -> None:
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["--yes", "autodetect", "--drive", tmpdir])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No new distros detected", result.stdout)

    @patch("visync.pm.get_installed_ids", return_value=[])
    @patch("visync.pm.mark_installed")
    @patch("visync.main.load_config")
    def test_autodetect_dry_run(self, mock_cfg: MagicMock, *_: MagicMock) -> None:
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "archlinux-2026.iso"
            iso.write_bytes(b"\x00" * 1024)
            with patch(
                "visync.main.identify_distro", side_effect=_mock_identify_distro
            ):
                result = runner.invoke(
                    app, ["--yes", "autodetect", "--drive", tmpdir, "--dry-run"]
                )
                self.assertEqual(result.exit_code, 0)
                self.assertIn("Would detect", result.stdout)

    @patch("visync.pm.get_installed_ids", return_value=[])
    @patch("visync.pm.mark_installed")
    @patch("visync.main.extract_version_from_filename", return_value="2026")
    @patch("visync.main.identify_distro", side_effect=_mock_identify_distro)
    @patch("visync.main.load_config")
    def test_autodetect_registers_iso(self, mock_cfg: MagicMock, *_: MagicMock) -> None:
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "archlinux-2026.iso"
            iso.write_bytes(b"\x00" * 1024)
            result = runner.invoke(app, ["--yes", "autodetect", "--drive", tmpdir])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Detected", result.stdout)

    @patch("visync.pm.get_installed_ids", return_value=["ArchLinux"])
    @patch("visync.pm.mark_installed")
    @patch("visync.main.load_config")
    def test_autodetect_skips_already_registered(
        self, mock_cfg: MagicMock, *_: MagicMock
    ) -> None:
        """autodetect does not re-register already tracked distros."""
        mock_cfg.return_value = MOCK_CONFIG
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "archlinux-2026.iso"
            iso.write_bytes(b"\x00" * 1024)
            with patch(
                "visync.main.identify_distro", side_effect=_mock_identify_distro
            ):
                result = runner.invoke(app, ["--yes", "autodetect", "--drive", tmpdir])
                self.assertEqual(result.exit_code, 0)
                self.assertIn("No new distros detected", result.stdout)

    def test_autodetect_has_flags(self) -> None:
        result = runner.invoke(app, ["autodetect", "--help"])
        for flag in ["--config", "--drive", "--dry-run"]:
            self.assertIn(flag, result.stdout, f"autodetect missing {flag}")


# ── list ─────────────────────────────────────────────────────────────────────


class TestList(unittest.TestCase):
    def test_list_empty_drive(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["--yes", "list", "--drive", tmpdir])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No ISO files found", result.stdout)

    def test_list_shows_isos(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = Path(tmpdir) / "archlinux-2026.iso"
            iso.write_bytes(b"\x00" * (1024 * 1024))
            with patch("visync.main.load_all_metadata", return_value={}):
                result = runner.invoke(app, ["--yes", "list", "--drive", tmpdir])
                self.assertEqual(result.exit_code, 0)
                self.assertIn("archlinux-2026.iso", result.stdout)

    def test_list_has_flags(self) -> None:
        result = runner.invoke(app, ["list", "--help"])
        self.assertIn("--drive", result.stdout)
        self.assertNotIn(
            "--config",
            result.stdout,
            "list reads the drive and the metadata sidecars only; a --config "
            "it ignored was a lie about what the flag does",
        )

    def test_list_does_not_have_dry_run(self) -> None:
        result = runner.invoke(app, ["list", "--help"])
        self.assertNotIn("--dry-run", result.stdout)


# ── sync ─────────────────────────────────────────────────────────────────────


class TestSync(unittest.TestCase):
    @patch("visync.main.find_ventoy_drives", return_value=[Path("/tmp")])
    @patch("visync.main.load_config", return_value=MOCK_CONFIG)
    def test_sync_no_installed(self, *_: MagicMock) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch("visync.main.find_ventoy_drives", return_value=[Path(tmpdir)]),
        ):
            result = runner.invoke(app, ["sync"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No distros installed", result.stdout)

    def test_sync_has_flags(self) -> None:
        result = runner.invoke(app, ["sync", "--help"])
        for flag in ["--config", "--drive", "--dry-run", "--force", "--clean", "--all"]:
            self.assertIn(flag, result.stdout, f"sync missing {flag}")


# ── verify ───────────────────────────────────────────────────────────────────


class TestVerify(unittest.TestCase):
    def test_verify_has_flags(self) -> None:
        result = runner.invoke(app, ["verify", "--help"])
        self.assertIn("--config", result.stdout)
        self.assertIn("--drive", result.stdout)

    def test_verify_does_not_have_dry_run(self) -> None:
        result = runner.invoke(app, ["verify", "--help"])
        self.assertNotIn("--dry-run", result.stdout)


# ── nuke-metadata ───────────────────────────────────────────────────────────


class TestNukeMetadata(unittest.TestCase):
    def test_nuke_metadata_no_dir(self) -> None:
        """nuke-metadata on drive with no .visync/metadata shows message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["--yes", "nuke-metadata", "--drive", tmpdir])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No metadata directory found", result.stdout)

    def test_nuke_metadata_empty_dir(self) -> None:
        """nuke-metadata on empty metadata dir shows message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            meta_dir = Path(tmpdir) / ".visync" / "metadata"
            meta_dir.mkdir(parents=True)
            result = runner.invoke(app, ["--yes", "nuke-metadata", "--drive", tmpdir])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Metadata directory is empty", result.stdout)

    def test_nuke_metadata_dry_run(self) -> None:
        """nuke-metadata --dry-run shows files without deleting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            meta_dir = Path(tmpdir) / ".visync" / "metadata"
            meta_dir.mkdir(parents=True)
            (meta_dir / "arch.iso.json").write_text("{}")
            (meta_dir / "ubuntu.iso.json").write_text("{}")
            result = runner.invoke(
                app, ["--yes", "nuke-metadata", "--drive", tmpdir, "--dry-run"]
            )
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Would delete", result.stdout)
            self.assertTrue((meta_dir / "arch.iso.json").exists())
            self.assertTrue((meta_dir / "ubuntu.iso.json").exists())

    def test_nuke_metadata_deletes(self) -> None:
        """nuke-metadata deletes metadata files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            meta_dir = Path(tmpdir) / ".visync" / "metadata"
            meta_dir.mkdir(parents=True)
            (meta_dir / "arch.iso.json").write_text("{}")
            (meta_dir / "ubuntu.iso.json").write_text("{}")
            result = runner.invoke(
                app, ["--yes", "nuke-metadata", "--drive", tmpdir, "--yes"]
            )
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Deleted 2 metadata", result.stdout)
            self.assertFalse(meta_dir.exists())


class TestGlobalYesFlag(unittest.TestCase):
    """--yes is a single global answer, not a per-command option."""

    def setUp(self) -> None:
        self._saved = visync_main._ASSUME_YES
        self.addCleanup(setattr, visync_main, "_ASSUME_YES", self._saved)

    def test_flag_is_global_not_per_command(self) -> None:
        root = runner.invoke(app, ["--help"])
        self.assertIn("--yes", root.stdout)
        # Accepting it before the subcommand is the documented position.
        for command in ("sync", "install", "remove", "nuke-metadata"):
            with self.subTest(command=command):
                result = runner.invoke(app, ["--yes", command, "--help"])
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertNotIn("--yes", result.stdout.split("Usage")[0])

    def test_flag_sets_the_flag(self) -> None:
        visync_main._ASSUME_YES = False
        result = runner.invoke(app, ["--yes", "version"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(visync_main._ASSUME_YES)

    def test_omitting_it_leaves_the_flag_off(self) -> None:
        visync_main._ASSUME_YES = True
        with patch("visync.main.version"):
            result = runner.invoke(app, ["version"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertFalse(visync_main._ASSUME_YES)

    def test_non_interactive_sync_on_plain_dir_still_asks(self) -> None:
        """Without --yes a script must not silently adopt an unrelated directory."""
        visync_main._ASSUME_YES = False
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["list", "--drive", tmpdir], input="n\n")
            self.assertEqual(result.exit_code, 1)
            self.assertIn("Ventoy/Visync-managed drive", result.stdout)
            self.assertIn("Aborted", result.stdout)

    def test_nuke_metadata_requires_confirmation(self) -> None:
        """Without --yes, aborting the prompt leaves everything intact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            meta_dir = Path(tmpdir) / ".visync" / "metadata"
            meta_dir.mkdir(parents=True)
            (meta_dir / "arch.iso.json").write_text("{}")
            result = runner.invoke(app, ["nuke-metadata", "--drive", tmpdir])
            self.assertNotEqual(result.exit_code, 0)
            self.assertTrue((meta_dir / "arch.iso.json").exists())

    def test_nuke_metadata_global_yes_skips_the_prompt(self) -> None:
        """`--yes` before the command is enough; the local flag is optional."""
        with tempfile.TemporaryDirectory() as tmpdir:
            meta_dir = Path(tmpdir) / ".visync" / "metadata"
            meta_dir.mkdir(parents=True)
            (meta_dir / "arch.iso.json").write_text("{}")
            result = runner.invoke(app, ["--yes", "nuke-metadata", "--drive", tmpdir])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertNotIn("Delete these file(s)?", result.output)
            self.assertFalse((meta_dir / "arch.iso.json").exists())

    def test_nuke_metadata_never_deletes_non_json(self) -> None:
        """Files other than .json inside metadata/ are never deleted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            meta_dir = Path(tmpdir) / ".visync" / "metadata"
            meta_dir.mkdir(parents=True)
            planted = meta_dir / "treasure.iso"
            planted.write_bytes(b"MZ not-really-an-iso")
            (meta_dir / "arch.iso.json").write_text("{}")
            result = runner.invoke(
                app, ["--yes", "nuke-metadata", "--drive", tmpdir, "--yes"]
            )
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(planted.exists(), "non-json file must survive")
            self.assertIn("left in place", result.stdout)
            self.assertFalse((meta_dir / "arch.iso.json").exists())

    def test_nuke_metadata_has_flags(self) -> None:
        """nuke-metadata accepts --drive, --dry-run, --yes; no --config.

        It deletes .visync/metadata/*.json off the drive and reads nothing else,
        so a --config it ignored would only mislead.
        """
        result = runner.invoke(app, ["nuke-metadata", "--help"])
        self.assertNotIn("--config", result.stdout)
        self.assertIn("--drive", result.stdout)
        self.assertIn("--dry-run", result.stdout)
        self.assertIn("--yes", result.stdout)


# ── version ──────────────────────────────────────────────────────────────────


class TestVersion(unittest.TestCase):
    def test_version_shows_version(self) -> None:
        result = runner.invoke(app, ["version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Visync version:", result.stdout)


# ── flag consistency ─────────────────────────────────────────────────────────


class TestFlagConsistency(unittest.TestCase):
    """Every mutating command must have --config, --drive, --dry-run."""

    def _get_options(self, cmd: str) -> str:
        return runner.invoke(app, [cmd, "--help"]).stdout

    def test_install_consistency(self) -> None:
        for flag in ["--config", "--drive", "--dry-run", "--file"]:
            self.assertIn(flag, self._get_options("install"), f"install missing {flag}")

    def test_remove_consistency(self) -> None:
        for flag in ["--config", "--drive", "--dry-run"]:
            self.assertIn(flag, self._get_options("remove"), f"remove missing {flag}")

    def test_update_consistency(self) -> None:
        for flag in ["--config", "--drive", "--force", "--clean", "--dry-run"]:
            self.assertIn(flag, self._get_options("update"), f"update missing {flag}")

    def test_sync_consistency(self) -> None:
        for flag in ["--config", "--drive", "--dry-run", "--force", "--clean", "--all"]:
            self.assertIn(flag, self._get_options("sync"), f"sync missing {flag}")

    def test_autodetect_consistency(self) -> None:
        for flag in ["--config", "--drive", "--dry-run"]:
            self.assertIn(
                flag, self._get_options("autodetect"), f"autodetect missing {flag}"
            )

    def test_read_commands_no_dry_run(self) -> None:
        for cmd in ["search", "info", "list", "verify", "version"]:
            self.assertNotIn(
                "--dry-run", self._get_options(cmd), f"{cmd} should not have --dry-run"
            )

    def test_read_commands_have_config_and_drive(self) -> None:
        """Every read command takes --config and --drive, except the two that
        need neither.

        `list` and `nuke-metadata` read nothing but the drive itself and its
        metadata sidecars, so both flags were previously accepted and ignored.
        A flag that does nothing is a bug report waiting to happen, so they are
        gone rather than lying.
        """
        for cmd in ["search", "info", "verify"]:
            opts = self._get_options(cmd)
            self.assertIn("--config", opts, f"{cmd} missing --config")
            self.assertIn("--drive", opts, f"{cmd} missing --drive")
        for cmd in ["list", "nuke-metadata"]:
            opts = self._get_options(cmd)
            self.assertNotIn("--config", opts, f"{cmd} should not take --config")
            self.assertIn("--drive", opts, f"{cmd} missing --drive")


class TestShortFlags(unittest.TestCase):
    """Verify short flag aliases appear in help text."""

    def _get_options(self, cmd: str) -> str:
        return runner.invoke(app, [cmd, "--help"]).stdout

    def test_c_is_config(self) -> None:
        for cmd in [
            "install",
            "remove",
            "update",
            "search",
            "info",
            "sync",
            "verify",
            "autodetect",
        ]:
            opts = self._get_options(cmd)
            self.assertIn("--config", opts)
            self.assertIn("-c", opts, f"{cmd} missing -c")

    def test_no_stray_c_where_config_is_gone(self) -> None:
        """-c must not linger on a command that no longer reads a config."""
        for cmd in ["list", "nuke-metadata"]:
            self.assertNotIn("-c", self._get_options(cmd))

    def test_d_is_drive(self) -> None:
        for cmd in [
            "install",
            "remove",
            "update",
            "search",
            "info",
            "list",
            "sync",
            "verify",
            "autodetect",
        ]:
            opts = self._get_options(cmd)
            self.assertIn("--drive", opts)
            self.assertIn("-d", opts, f"{cmd} missing -d")

    def test_n_is_dry_run(self) -> None:
        for cmd in ["install", "remove", "update", "sync", "autodetect"]:
            opts = self._get_options(cmd)
            self.assertIn("--dry-run", opts)
            self.assertIn("-n", opts, f"{cmd} missing -n")

    def test_i_is_file_on_install(self) -> None:
        opts = self._get_options("install")
        self.assertIn("--file", opts)
        self.assertIn("-i", opts, "install missing -i for --file")

    def test_f_is_force_on_update_sync(self) -> None:
        for cmd in ["update", "sync"]:
            opts = self._get_options(cmd)
            self.assertIn("--force", opts)
            self.assertIn("-f", opts, f"{cmd} missing -f for --force")

    def test_no_verify_on_install_sync_update(self) -> None:
        for cmd in ["install", "sync", "update"]:
            opts = self._get_options(cmd)
            self.assertIn("--no-verify", opts, f"{cmd} missing --no-verify")


# ── multi-drive support ─────────────────────────────────────────────────────


class TestGetDrives(unittest.TestCase):
    """Tests for _get_drives() multi-drive selection logic."""

    def test_single_drive_returns_it(self) -> None:
        """With one detected drive, returns it without prompting."""
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch("visync.main.find_ventoy_drives", return_value=[Path(tmpdir)]),
        ):
            result = _get_drives()
            self.assertEqual(result, [Path(tmpdir)])

    def test_explicit_drive_flag_bypasses_detection(self) -> None:
        """When --drive is provided, detection is skipped entirely."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "ventoy").mkdir()
            result = _get_drives(drives=[Path(tmpdir)])
            self.assertEqual(result, [Path(tmpdir)])

    def test_explicit_drive_flag_invalid_path_fails(self) -> None:
        """When --drive points to a non-existent path, exits with error."""
        with self.assertRaises(typer.Exit):
            _get_drives(drives=[Path("/nonexistent/path")])

    @patch("visync.main.find_ventoy_drives")
    def test_multiple_drives_prompts_user(self, mock_drives: MagicMock) -> None:
        """With multiple drives, prompts user to select."""
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            mock_drives.return_value = [Path(d1), Path(d2)]
            # Simulate user entering "1"
            with patch("visync.main.typer.prompt", return_value="1"):
                result = _get_drives()
                self.assertEqual(result, [Path(d1)])

    @patch("visync.main.find_ventoy_drives")
    def test_multiple_drives_second_choice(self, mock_drives: MagicMock) -> None:
        """With multiple drives, user can select the second one."""
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            mock_drives.return_value = [Path(d1), Path(d2)]
            with patch("visync.main.typer.prompt", return_value="2"):
                result = _get_drives()
                self.assertEqual(result, [Path(d2)])

    @patch("visync.main.find_ventoy_drives")
    def test_multiple_drives_select_multiple(self, mock_drives: MagicMock) -> None:
        """With multiple drives, user can select more than one."""
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            mock_drives.return_value = [Path(d1), Path(d2)]
            with patch("visync.main.typer.prompt", return_value="1,2"):
                result = _get_drives()
                self.assertEqual(result, [Path(d1), Path(d2)])

    @patch("visync.main.find_ventoy_drives")
    def test_multiple_drives_retries_on_invalid(self, mock_drives: MagicMock) -> None:
        """Invalid selection retries prompt until valid."""
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            mock_drives.return_value = [Path(d1), Path(d2)]
            # First call returns invalid ("0"), second returns valid ("1")
            with patch("visync.main.typer.prompt", side_effect=["0", "1"]):
                result = _get_drives()
                self.assertEqual(result, [Path(d1)])

    @patch("visync.main.find_ventoy_drives")
    def test_multiple_drives_abort_exits(self, mock_drives: MagicMock) -> None:
        """User abort (Ctrl+C) during prompt exits cleanly."""
        mock_drives.return_value = [Path("/tmp/a"), Path("/tmp/b")]
        with (
            patch("visync.main.typer.prompt", side_effect=typer.Abort()),
            self.assertRaises(typer.Exit),
        ):
            _get_drives()

    def test_no_drives_exits(self) -> None:
        """No drives detected exits with error."""
        with (
            patch("visync.main.find_ventoy_drives", return_value=[]),
            self.assertRaises(typer.Exit),
        ):
            _get_drives()


class TestNonVentoyDriveConfirmation(unittest.TestCase):
    """--drive pointing somewhere that is not a Ventoy drive is a footgun.

    Cleanup unlinks ISOs it recognises in the target directory, so a typo in
    --drive can delete real images from an unrelated folder. These tests pin
    the confirmation, and --yes as the escape hatch for scripts.
    """

    def setUp(self) -> None:
        self._saved = visync_main._ASSUME_YES
        self.addCleanup(setattr, visync_main, "_ASSUME_YES", self._saved)
        visync_main._ASSUME_YES = False

    def test_plain_directory_asks_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with (
                patch("visync.main.typer.confirm", return_value=True) as confirm,
            ):
                result = _get_drives(drives=[Path(tmpdir)])
            self.assertEqual(result, [Path(tmpdir)])
            confirm.assert_called_once()

    def test_declining_aborts(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch("visync.main.typer.confirm", return_value=False),
            self.assertRaises(typer.Exit),
        ):
            _get_drives(drives=[Path(tmpdir)])

    def test_assume_yes_skips_prompt(self) -> None:
        visync_main._ASSUME_YES = True
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("visync.main.typer.confirm") as confirm:
                result = _get_drives(drives=[Path(tmpdir)])
            self.assertEqual(result, [Path(tmpdir)])
            confirm.assert_not_called()

    def test_ventoy_marker_needs_no_prompt(self) -> None:
        """A directory that really is a Ventoy drive is used without asking."""
        for marker in ("ventoy", ".visync"):
            with tempfile.TemporaryDirectory() as tmpdir, self.subTest(marker=marker):
                (Path(tmpdir) / marker).mkdir()
                with patch("visync.main.typer.confirm") as confirm:
                    result = _get_drives(drives=[Path(tmpdir)])
                self.assertEqual(result, [Path(tmpdir)])
                confirm.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
