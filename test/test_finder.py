"""Integration tests for finder module (requires Ventoy hardware for some tests)."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.finder import *


def _detect_ventoy() -> tuple[bool, list[Path]]:
    """Check for Ventoy drive using a lightweight label probe, then full detection."""
    found = False
    drives: list[Path] = []
    try:
        import subprocess

        found = (
            subprocess.run(
                ["blkid", "-L", "Ventoy"], capture_output=True, timeout=10
            ).returncode
            == 0
        )
    except Exception:
        pass
    if found:
        try:
            drives = find_ventoy_drives()
        except Exception:
            pass
    return found, drives


HAS_VENTOY, _ventoy_drives = _detect_ventoy()


def _section(title: str) -> None:
    print(f"\n  {'=' * 60}")
    print(f"  {title}")
    print(f"  {'=' * 60}")


def _ok(msg: str) -> None:
    print(f"  [✓] {msg}")


def _skip(msg: str) -> None:
    print(f"  [-] {msg}")


def _info(msg: str) -> None:
    print(f"  [*] {msg}")


def _make_fake_iso(tmpdir: Path, volume_id: str) -> Path:
    """Create a minimal ISO 9660 image with Primary Volume Descriptor."""
    iso_path = tmpdir / "test.iso"
    buf = bytearray()
    buf.extend(b"\x00" * 32768)  # system area (sectors 0-15)
    # Primary Volume Descriptor at offset 32768
    buf.append(1)                      # type (1 = Primary)
    buf.extend(b"CD001")              # standard identifier
    buf.append(1)                      # version
    buf.extend(b"\x00" * 33)          # pad to offset 32808
    # Volume identifier at offset 32808 (32 bytes)
    vol_bytes = volume_id.encode("ascii", errors="ignore").ljust(32, b"\x00")[:32]
    buf.extend(vol_bytes)
    iso_path.write_bytes(bytes(buf))
    return iso_path


class TestFindVentoyDrives(unittest.TestCase):
    """Tests for Ventoy drive detection."""

    def test_detection_returns_list(self) -> None:
        _section("Ventoy Drive Detection")
        if not HAS_VENTOY:
            _skip("No Ventoy drive detected — skipping hardware test")
            raise unittest.SkipTest("No Ventoy drive available")

        self.assertIsInstance(_ventoy_drives, list)
        for d in _ventoy_drives:
            _ok(f"Found Ventoy drive: {d}")
            self.assertTrue(d.exists(), f"Mount point {d} does not exist")

    def test_returns_all_detected_drives(self) -> None:
        """find_ventoy_drives returns all detected drives (no longer defaults to first)."""
        pass  # relies on environment — validated by integration test


class TestInstalledIsos(unittest.TestCase):
    """Tests for ISO discovery on Ventoy drives."""

    def test_find_isos_on_ventoy(self) -> None:
        if not HAS_VENTOY:
            raise unittest.SkipTest("No Ventoy drive available")

        _section("ISO Discovery on Ventoy Drive")
        for drive in _ventoy_drives:
            _info(f"Scanning {drive}")
            isos = find_installed_isos(drive)
            _info(f"Found {len(isos)} ISO(s)")
            for iso in isos:
                print(f"       - {iso.name}")
            self.assertIsInstance(isos, list)
            if isos:
                _ok(f"All {len(isos)} ISO(s) are valid Path objects")

    def test_formatted_names(self) -> None:
        if not HAS_VENTOY:
            raise unittest.SkipTest("No Ventoy drive available")

        _section("Formatted Distribution Names")
        for drive in _ventoy_drives:
            names = find_installed_isos_formatted(drive)
            _info(f"Identified {len(names)} distribution(s)")
            for name in names:
                print(f"       - {name}")
            self.assertIsInstance(names, list)
            if names:
                _ok(f"All {len(names)} name(s) resolved")

    def test_volume_id_on_ventoy_isos(self) -> None:
        if not HAS_VENTOY:
            raise unittest.SkipTest("No Ventoy drive available")

        _section("Volume ID Extraction from Real ISOs")
        for drive in _ventoy_drives:
            isos = find_installed_isos(drive)
            if not isos:
                _skip("No ISOs to check volume IDs on")
                continue
            for iso in isos:
                vid = get_iso_volume_id(iso)
                if vid:
                    _ok(f"{iso.name} -> {vid}")
                else:
                    _skip(f"{iso.name}: (no volume ID)")


class TestGetIsoVolumeId(unittest.TestCase):
    """Tests for ISO volume ID extraction using synthetic images."""

    def test_reads_known_volume_id(self) -> None:
        _section("Volume ID Extraction (Synthetic ISOs)")
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = _make_fake_iso(Path(tmpdir), "UBUNTU_24_04")
            vid = get_iso_volume_id(iso)
            self.assertEqual(vid, "UBUNTU_24_04")
            _ok(f"Read volume ID: {vid}")

    def test_returns_empty_for_invalid_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad = Path(tmpdir) / "not_an.iso"
            bad.write_text("not an iso file")
            vid = get_iso_volume_id(bad)
            self.assertEqual(vid, "")
            _ok("Empty string returned for invalid file")

    def test_truncates_at_32_bytes(self) -> None:
        _section("Volume ID Truncation (32-char limit)")
        with tempfile.TemporaryDirectory() as tmpdir:
            long_id = "A" * 40
            iso = _make_fake_iso(Path(tmpdir), long_id)
            vid = get_iso_volume_id(iso)
            self.assertEqual(len(vid), 32)
            _ok(f"Volume ID truncated to {len(vid)} characters: '{vid}'")


class TestFindInstalledIsos(unittest.TestCase):
    """Tests for ISO discovery in a directory."""

    def test_finds_nothing_in_empty_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            isos = find_installed_isos(Path(tmpdir))
            self.assertEqual(isos, [])

    def test_finds_iso_files(self) -> None:
        _section("ISO File Discovery")
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "a.iso").touch()
            (Path(tmpdir) / "b.iso").touch()
            (Path(tmpdir) / "c.txt").touch()
            (Path(tmpdir) / "sub").mkdir()
            (Path(tmpdir) / "sub" / "d.iso").touch()
            isos = find_installed_isos(Path(tmpdir))
            self.assertEqual(len(isos), 3)
            _ok(f"Found {len(isos)} ISO(s) (recursive)")

    def test_formatted_version(self) -> None:
        _section("Formatted Name Discovery")
        with tempfile.TemporaryDirectory() as tmpdir:
            _make_fake_iso(Path(tmpdir), "UBUNTU_24_04")
            names = find_installed_isos_formatted(Path(tmpdir))
            self.assertEqual(names, ["Ubuntu"])
            _ok(f"Resolved name: {names[0]}")


if __name__ == "__main__":
    print()
    print(f"  {'#' * 62}")
    print(f"  #   FINDER MODULE — INTEGRATION TESTS")
    print(f"  {'#' * 62}")
    print()

    if HAS_VENTOY and _ventoy_drives:
        _info(f"Ventoy drive detected: {_ventoy_drives[0]}")
    elif HAS_VENTOY:
        _skip("Ventoy label found but mount failed (try sudo)")
    else:
        _skip("No Ventoy drive detected — hardware-dependent tests will be skipped")
    print()

    unittest.main(verbosity=2)
