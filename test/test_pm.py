"""Tests for the package manager (pm.py) and CLI commands."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.pm import (
    load_installed,
    save_installed,
    mark_installed,
    mark_removed,
    get_installed_ids,
    resolve_distro,
)
from src.finder import load_config


# ── Helpers ──────────────────────────────────────────────────────

def _make_drive(tmpdir: Path) -> Path:
    """Create a fake Ventoy drive with .visync directory."""
    drive = tmpdir / "Ventoy"
    drive.mkdir()
    (drive / ".visync").mkdir()
    return drive


def _make_iso(drive: Path, name: str, size: int = 1024) -> Path:
    """Create a fake ISO file on the drive."""
    iso = drive / name
    iso.write_bytes(b"\x00" * size)
    return iso


def _write_installed(drive: Path, data: dict) -> None:
    """Write installed.json to the drive."""
    path = drive / ".visync" / "installed.json"
    with open(path, "w") as f:
        json.dump(data, f)


# ── State Management Tests ──────────────────────────────────────

class TestStateManagement(unittest.TestCase):
    def test_load_installed_empty(self):
        """load_installed returns empty dict when no file exists."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            result = load_installed(drive)
            self.assertEqual(result, {})

    def test_load_installed_valid(self):
        """load_installed parses valid JSON."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            _write_installed(drive, {"ArchLinux": {"version": "2026.06.01"}})
            result = load_installed(drive)
            self.assertEqual(result["ArchLinux"]["version"], "2026.06.01")

    def test_load_installed_corrupt(self):
        """load_installed returns empty dict on corrupt JSON."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            (drive / ".visync" / "installed.json").write_text("not json")
            result = load_installed(drive)
            self.assertEqual(result, {})

    def test_save_and_load(self):
        """save_installed persists data that load_installed reads back."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            data = {"NixOS": {"version": "26.05", "installed_at": "2026-06-20T00:00:00"}}
            save_installed(drive, data)
            loaded = load_installed(drive)
            self.assertEqual(loaded, data)

    def test_mark_installed(self):
        """mark_installed adds entry with version and timestamp."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mark_installed(drive, "Tails", version="7.9")
            installed = load_installed(drive)
            self.assertIn("Tails", installed)
            self.assertEqual(installed["Tails"]["version"], "7.9")
            self.assertIn("installed_at", installed["Tails"])

    def test_mark_installed_overwrite(self):
        """mark_installed overwrites existing entry."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mark_installed(drive, "Tails", version="7.7")
            mark_installed(drive, "Tails", version="7.9")
            installed = load_installed(drive)
            self.assertEqual(installed["Tails"]["version"], "7.9")

    def test_mark_removed(self):
        """mark_removed deletes the entry."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mark_installed(drive, "Tails")
            mark_removed(drive, "Tails")
            installed = load_installed(drive)
            self.assertNotIn("Tails", installed)

    def test_mark_removed_nonexistent(self):
        """mark_removed is safe to call on non-existent entry."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mark_removed(drive, "NonExistent")  # Should not raise

    def test_get_installed_ids(self):
        """get_installed_ids returns list of entry IDs."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            _write_installed(drive, {
                "ArchLinux": {"version": "2026.06.01"},
                "NixOS": {"version": "26.05"},
            })
            ids = get_installed_ids(drive)
            self.assertIn("ArchLinux", ids)
            self.assertIn("NixOS", ids)
            self.assertEqual(len(ids), 2)

    def test_get_installed_ids_empty(self):
        """get_installed_ids returns empty list when no entries."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            ids = get_installed_ids(drive)
            self.assertEqual(ids, [])


# ── Distro Resolution Tests ─────────────────────────────────────

class TestResolveDistro(unittest.TestCase):
    def setUp(self):
        self.config = load_config()

    def test_resolve_exact_entry_id(self):
        """Resolve by exact entry_id (case-insensitive)."""
        result = resolve_distro("ArchLinux", self.config)
        self.assertEqual(result, "ArchLinux")

    def test_resolve_exact_entry_id_lowercase(self):
        """Resolve by lowercase entry_id."""
        result = resolve_distro("archlinux", self.config)
        self.assertEqual(result, "ArchLinux")

    def test_resolve_exact_clean_name(self):
        """Resolve by exact clean_name."""
        result = resolve_distro("Fedora KDE", self.config)
        self.assertEqual(result, "FedoraKDE")

    def test_resolve_clean_name_case_insensitive(self):
        """Resolve clean_name case-insensitively."""
        result = resolve_distro("fedora kde", self.config)
        self.assertEqual(result, "FedoraKDE")

    def test_resolve_partial_clean_name(self):
        """Resolve by partial match on clean_name."""
        result = resolve_distro("parrot", self.config)
        self.assertEqual(result, "ParrotSecurity")

    def test_resolve_partial_entry_id(self):
        """Resolve by unambiguous partial match."""
        result = resolve_distro("minimal", self.config)
        self.assertEqual(result, "NixOS")

    def test_resolve_ambiguous_partial_returns_none(self):
        """Ambiguous partial matches must not silently pick one distro."""
        # "nixo" partially matches both NixOS and NixOSGraphical
        result = resolve_distro("nixo", self.config)
        self.assertIsNone(result)

    def test_resolve_not_found(self):
        """Returns None for unknown distro."""
        result = resolve_distro("NonExistent", self.config)
        self.assertIsNone(result)

    def test_resolve_empty_string(self):
        """Returns None for empty string."""
        result = resolve_distro("", self.config)
        self.assertIsNone(result)


# ── CLI Command Tests ───────────────────────────────────────────

class TestSearchCommand(unittest.TestCase):
    def setUp(self):
        from src.main import app
        self.app = app
        from typer.testing import CliRunner
        self.runner = CliRunner()

    @patch("src.main.find_ventoy_drives")
    def test_search_lists_all(self, mock_drives):
        """search without args lists all distros."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_drives.return_value = [_make_drive(Path(tmp))]
            result = self.runner.invoke(self.app, ["search"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Available distros", result.stdout)
            self.assertIn("Arch Linux", result.stdout)
            self.assertIn("NixOS", result.stdout)

    @patch("src.main.find_ventoy_drives")
    def test_search_with_query(self, mock_drives):
        """search with query filters results."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_drives.return_value = [_make_drive(Path(tmp))]
            result = self.runner.invoke(self.app, ["search", "nixos"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("NixOS", result.stdout)

    @patch("src.main.find_ventoy_drives")
    def test_search_shows_installed_marker(self, mock_drives):
        """search shows + marker for installed distros."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mock_drives.return_value = [drive]
            _write_installed(drive, {"ArchLinux": {"version": "2026.06.01"}})
            result = self.runner.invoke(self.app, ["search"])
            self.assertEqual(result.exit_code, 0)
            # Arch Linux should have + marker
            self.assertIn("+", result.stdout)

    @patch("src.main.find_ventoy_drives")
    def test_search_not_found(self, mock_drives):
        """search with bad query shows error message."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_drives.return_value = [_make_drive(Path(tmp))]
            result = self.runner.invoke(self.app, ["search", "NonExistent"])
            self.assertIn("No match", result.stdout)


class TestInfoCommand(unittest.TestCase):
    def setUp(self):
        from src.main import app
        self.app = app
        from typer.testing import CliRunner
        self.runner = CliRunner()

    @patch("src.main.find_ventoy_drives")
    def test_info_shows_distro(self, mock_drives):
        """info shows distro details."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_drives.return_value = [_make_drive(Path(tmp))]
            result = self.runner.invoke(self.app, ["info", "tails"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Tails", result.stdout)
            self.assertIn("tails_api", result.stdout)

    @patch("src.main.find_ventoy_drives")
    def test_info_installed_status(self, mock_drives):
        """info shows installed status."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mock_drives.return_value = [drive]
            _write_installed(drive, {"Tails": {"version": "7.9"}})
            result = self.runner.invoke(self.app, ["info", "tails"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("installed", result.stdout)

    @patch("src.main.find_ventoy_drives")
    def test_info_not_found(self, mock_drives):
        """info with bad name shows error."""
        with tempfile.TemporaryDirectory() as tmp:
            mock_drives.return_value = [_make_drive(Path(tmp))]
            result = self.runner.invoke(self.app, ["info", "NonExistent"])
            self.assertEqual(result.exit_code, 1)


class TestAutodetectCommand(unittest.TestCase):
    def setUp(self):
        from src.main import app
        self.app = app
        from typer.testing import CliRunner
        self.runner = CliRunner()

    @patch("src.main.find_ventoy_drives")
    def test_autodetect_empty_drive(self, mock_drives):
        """autodetect on empty drive finds nothing."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mock_drives.return_value = [drive]
            result = self.runner.invoke(self.app, ["autodetect"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No new distros detected", result.stdout)

    @patch("src.main.get_iso_volume_id")
    @patch("src.main.find_ventoy_drives")
    def test_autodetect_finds_iso(self, mock_drives, mock_vid):
        """autodetect registers ISOs found on drive."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mock_drives.return_value = [drive]
            _make_iso(drive, "archlinux-2026.06.01-x86_64.iso")
            mock_vid.return_value = "Arch Linux 2026.06.01 x86_64"
            result = self.runner.invoke(self.app, ["autodetect"])
            self.assertEqual(result.exit_code, 0)
            installed = load_installed(drive)
            self.assertIn("ArchLinux", installed)

    @patch("src.main.get_iso_volume_id")
    @patch("src.main.find_ventoy_drives")
    def test_autodetect_skips_already_registered(self, mock_drives, mock_vid):
        """autodetect skips distros already in installed.json."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mock_drives.return_value = [drive]
            _make_iso(drive, "archlinux-2026.06.01-x86_64.iso")
            _write_installed(drive, {"ArchLinux": {"version": "2026.06.01"}})
            mock_vid.return_value = "Arch Linux 2026.06.01 x86_64"
            result = self.runner.invoke(self.app, ["autodetect"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No new distros detected", result.stdout)


class TestRemoveCommand(unittest.TestCase):
    def setUp(self):
        from src.main import app
        self.app = app
        from typer.testing import CliRunner
        self.runner = CliRunner()

    @patch("src.main.find_ventoy_drives")
    def test_remove_deletes_file(self, mock_drives):
        """remove deletes the ISO file from drive."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mock_drives.return_value = [drive]
            _make_iso(drive, "archlinux-2026.06.01-x86_64.iso")
            _write_installed(drive, {"ArchLinux": {"version": "2026.06.01"}})
            with patch("src.main.get_iso_volume_id", return_value="Arch Linux 2026.06.01 x86_64"):
                result = self.runner.invoke(self.app, ["remove", "archlinux", "--yes"])
            self.assertEqual(result.exit_code, 0)
            self.assertFalse((drive / "archlinux-2026.06.01-x86_64.iso").exists())
            installed = load_installed(drive)
            self.assertNotIn("ArchLinux", installed)

    @patch("src.main.find_ventoy_drives")
    def test_remove_not_found(self, mock_drives):
        """remove with no matching files warns."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mock_drives.return_value = [drive]
            result = self.runner.invoke(self.app, ["remove", "archlinux"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No files found", result.stdout)


# ── Sync Filtering Tests ────────────────────────────────────────

class TestSyncFiltering(unittest.TestCase):
    def setUp(self):
        from src.main import app
        self.app = app
        from typer.testing import CliRunner
        self.runner = CliRunner()

    @patch("src.main.find_ventoy_drives")
    def test_sync_no_installed_shows_message(self, mock_drives):
        """sync with no installed distros shows hint."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mock_drives.return_value = [drive]
            result = self.runner.invoke(self.app, ["sync"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No distros installed", result.stdout)

    @patch("src.main.find_ventoy_drives")
    @patch("src.download.sync_all_configured_distros")
    def test_sync_all_bypasses_installed_filter(self, mock_sync, mock_drives):
        """sync --all does not filter by installed list."""
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive(Path(tmp))
            mock_drives.return_value = [drive]
            result = self.runner.invoke(self.app, ["sync", "--all"])
            self.assertEqual(result.exit_code, 0)
            self.assertNotIn("No distros installed", result.stdout)
            mock_sync.assert_called_once()


# ── .img File Support Tests ─────────────────────────────────────

class TestImgFileSupport(unittest.TestCase):
    def test_find_installed_isos_finds_img(self):
        """find_installed_isos finds .img files."""
        from src.finder import find_installed_isos
        with tempfile.TemporaryDirectory() as tmp:
            drive = Path(tmp)
            _make_iso(drive, "tails-amd64-7.9.img")
            _make_iso(drive, "archlinux-2026.06.01-x86_64.iso")
            result = find_installed_isos(drive)
            names = [p.name for p in result]
            self.assertIn("tails-amd64-7.9.img", names)
            self.assertIn("archlinux-2026.06.01-x86_64.iso", names)

    def test_find_installed_isos_skips_visync(self):
        """find_installed_isos ignores .visync directory."""
        from src.finder import find_installed_isos
        with tempfile.TemporaryDirectory() as tmp:
            drive = Path(tmp)
            visync = drive / ".visync"
            visync.mkdir()
            _make_iso(drive, "archlinux-2026.06.01-x86_64.iso")
            _make_iso(visync, "fake.iso")
            result = find_installed_isos(drive)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].name, "archlinux-2026.06.01-x86_64.iso")

    def test_find_installed_isos_skips_resource_forks(self):
        """find_installed_isos ignores macOS resource forks."""
        from src.finder import find_installed_isos
        with tempfile.TemporaryDirectory() as tmp:
            drive = Path(tmp)
            _make_iso(drive, "archlinux-2026.06.01-x86_64.iso")
            _make_iso(drive, "._archlinux-2026.06.01-x86_64.iso")
            result = find_installed_isos(drive)
            self.assertEqual(len(result), 1)


# ── Clean Flag Tests ────────────────────────────────────────────

class TestCleanFlag(unittest.TestCase):
    def test_sweep_dry_run_by_default(self):
        """_sweep_old_versions dry-runs without clean flag."""
        from src.download import _sweep_old_versions
        with tempfile.TemporaryDirectory() as tmp:
            drive = Path(tmp)
            # Create two "versions" of same distro
            _make_iso(drive, "tails-amd64-7.7.img")
            _make_iso(drive, "tails-amd64-7.9.img")
            _sweep_old_versions(drive, clean=False)
            # Both files should still exist
            self.assertTrue((drive / "tails-amd64-7.7.img").exists())
            self.assertTrue((drive / "tails-amd64-7.9.img").exists())

    def test_sweep_clean_removes_old(self):
        """_sweep_old_versions with clean=True removes old versions."""
        from src.download import _sweep_old_versions
        with tempfile.TemporaryDirectory() as tmp:
            drive = Path(tmp)
            _make_iso(drive, "tails-amd64-7.7.img")
            _make_iso(drive, "tails-amd64-7.9.img")
            _sweep_old_versions(drive, clean=True)
            # Old version should be gone, new one kept
            self.assertFalse((drive / "tails-amd64-7.7.img").exists())
            self.assertTrue((drive / "tails-amd64-7.9.img").exists())


# ── Download Failure Handling Tests ─────────────────────────────

class TestDownloadFailure(unittest.TestCase):
    @patch("src.download.shutil.disk_usage")
    def test_download_returns_false_on_no_space(self, mock_disk):
        """download_iso returns False when disk space is insufficient."""
        from src.download import download_iso
        mock_disk.return_value = MagicMock(free=100)  # 100 bytes free
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "test.iso"
            result = download_iso("https://example.com/test.iso", dest)
            self.assertFalse(result)
            self.assertFalse(dest.exists())

    @patch("src.download.shutil.disk_usage")
    @patch("src.download.urllib.request.urlopen")
    def test_download_returns_true_on_success(self, mock_urlopen, mock_disk):
        """download_iso returns True on successful download."""
        from src.download import download_iso
        mock_disk.return_value = MagicMock(free=10 * 1024**3)  # 10GB free
        # Mock HEAD request for size check
        head_resp = MagicMock()
        head_resp.__enter__ = MagicMock(return_value=head_resp)
        head_resp.__exit__ = MagicMock(return_value=False)
        head_resp.headers = {"Content-Length": "4"}
        # Mock GET request for download
        get_resp = MagicMock()
        get_resp.__enter__ = MagicMock(return_value=get_resp)
        get_resp.__exit__ = MagicMock(return_value=False)
        get_resp.headers = {"Content-Length": "4"}
        get_resp.read = MagicMock(side_effect=[b"data", b""])
        mock_urlopen.side_effect = [head_resp, get_resp]
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "test.iso"
            result = download_iso("https://example.com/test.iso", dest)
            self.assertTrue(result)
            self.assertTrue(dest.exists())


if __name__ == "__main__":
    unittest.main()
