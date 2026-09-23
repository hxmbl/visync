"""Unit tests for distro identification (no Ventoy hardware required)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.finder import *


def _section(title: str) -> None:
    print(f"\n  {'=' * 60}")
    print(f"  {title}")
    print(f"  {'=' * 60}")


def _ok(msg: str) -> None:
    print(f"  [✓] {msg}")


def _info(msg: str) -> None:
    print(f"  [*] {msg}")


class TestIdentifyDistro(unittest.TestCase):
    def test_base_distro_from_volume_id(self) -> None:
        _section("Layer 1: Base Distro from Volume ID")
        cases = [
            ("UBUNTU_24_04", "ubuntu-24.04.iso", "Ubuntu"),
            ("FEDORA_41", "fedora-workstation.iso", "Fedora"),
        ]
        for vid, fname, expected in cases:
            result = identify_distro(vid, fname)
            self.assertEqual(result, expected)
            _ok(f"'{vid}' / '{fname}' -> {result}")

    def test_fork_override_from_filename(self) -> None:
        _section("Layer 2: Fork Override via Filename")
        cases = [
            ("ARCH_2024", "manjaro-kde-24.iso", "Manjaro"),
            ("DEBIAN_12", "kali-linux-2024.iso", "Kali Linux"),
        ]
        for vid, fname, expected in cases:
            result = identify_distro(vid, fname)
            self.assertEqual(result, expected)
            _ok(f"'{vid}' / '{fname}' -> {result}")

    def test_standalone_match(self) -> None:
        _section("Layer 3: Standalone Match Rules")
        cases = [
            ("NIXOS_24", "nixos.iso", "NixOS Minimal"),
            ("", "nixos-graphical-26.05.iso", "NixOS Graphical"),
            ("", "systemrescue-amd64.iso", "SystemRescue"),
        ]
        for vid, fname, expected in cases:
            result = identify_distro(vid, fname)
            self.assertEqual(result, expected)
            _ok(f"'{vid}' / '{fname}' -> {result}")

    def test_filename_fallback(self) -> None:
        _section("Layer 4: Filename Regex Fallback")
        result = identify_distro("UNKNOWN", "alpine-3.19.iso")
        self.assertEqual(result, "Alpine")
        _ok(f"UNKNOWN / alpine-3.19.iso -> {result}")

    def test_unknown_os(self) -> None:
        _section("Unknown OS Detection")
        result = identify_distro("", "readme.txt")
        self.assertEqual(result, "Unknown OS")
        _ok(f"'' / readme.txt -> {result}")


if __name__ == "__main__":
    print()
    print(f"  {'#' * 62}")
    print("  #   IDENTIFY MODULE — DISTRO DETECTION TESTS")
    print(f"  {'#' * 62}")
    print()
    _info(
        "Testing cascading identification layers (vol ID → fork → standalone → fallback)"
    )
    print()
    unittest.main(verbosity=2)
