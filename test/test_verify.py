"""Unit tests for verify module (no network or large ISOs required)."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from visync.verify import *


def _section(title: str) -> None:
    print(f"\n  {'=' * 60}")
    print(f"  {title}")
    print(f"  {'=' * 60}")


def _ok(msg: str) -> None:
    print(f"  [✓] {msg}")


def _info(msg: str) -> None:
    print(f"  [*] {msg}")


class TestComputeIsoHash(unittest.TestCase):
    def test_unknown_algo_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.iso"
            f.write_bytes(b"x")
            with self.assertRaises(ValueError):
                compute_iso_hash(f, "md5")
            _ok("Unknown algorithm raises ValueError")

    def test_sha256_of_synthetic_file(self) -> None:
        _section("compute_iso_hash: SHA256")
        data = b"hello visync integrity test\n" * 2000
        expected = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.iso"
            f.write_bytes(data)
            result = compute_iso_hash(f, "sha256")
            self.assertEqual(result, expected)
            _ok(f"SHA256: {result[:16]}...")

    def test_sha1(self) -> None:
        data = b"data for sha1\n" * 500
        expected = hashlib.sha1(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.iso"
            f.write_bytes(data)
            result = compute_iso_hash(f, "sha1")
            self.assertEqual(result, expected)
            _ok(f"SHA1: {result[:16]}...")

    def test_sha512(self) -> None:
        data = b"data for sha512\n" * 500
        expected = hashlib.sha512(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.iso"
            f.write_bytes(data)
            result = compute_iso_hash(f, "sha512")
            self.assertEqual(result, expected)
            _ok(f"SHA512: {result[:16]}...")

    def test_blake2b(self) -> None:
        data = b"data for blake2b\n" * 500
        expected = hashlib.blake2b(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.iso"
            f.write_bytes(data)
            result = compute_iso_hash(f, "blake2b")
            self.assertEqual(result, expected)
            _ok(f"BLAKE2b: {result[:16]}...")


class TestParseGpgChecksum(unittest.TestCase):
    def test_parses_fedora_format(self) -> None:
        _section("parse_gpg_checksum: Fedora-style CHECKSUM")
        content = """
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

# Fedora Workstation 41-1.4
SHA256 (Fedora-Workstation-Live-x86_64-41-1.4.iso) = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
SHA256 (Fedora-Workstation-Live-x86_64-41-1.4.iso?key=val) = deadbeef
-----BEGIN PGP SIGNATURE-----
"""
        result = parse_gpg_checksum(
            content, "Fedora-Workstation-Live-x86_64-41-1.4.iso"
        )
        self.assertEqual(
            result, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        )
        _ok("Extracted SHA256 from GPG-signed CHECKSUM")

    def test_no_match_returns_none(self) -> None:
        content = "SHA256 (other.iso) = abcd"
        result = parse_gpg_checksum(content, "missing.iso")
        self.assertIsNone(result)

    def test_ignores_non_sha_lines(self) -> None:
        content = "SHA1 (file.iso) = abc\nSHA256 (file.iso) = " + "aa" * 32
        result = parse_gpg_checksum(content, "file.iso")
        self.assertEqual(result, "aa" * 32)
        _ok("Only SHA256/SHA512 lines are matched")

    def test_selects_requested_algo_when_both_present(self) -> None:
        """A file listing SHA256 and SHA512 for one ISO must honour *algo*."""
        content = (
            "SHA256 (file.iso) = " + "aa" * 32 + "\n"
            "SHA512 (file.iso) = " + "bb" * 64 + "\n"
        )
        self.assertEqual(parse_gpg_checksum(content, "file.iso", "sha512"), "bb" * 64)
        self.assertEqual(parse_gpg_checksum(content, "file.iso", "sha256"), "aa" * 32)
        _ok("Algorithm label selects the right digest")

    def test_rejects_digest_of_wrong_length(self) -> None:
        """A mislabelled line (SHA256 label, 128-hex body) is not accepted."""
        content = "SHA256 (file.iso) = " + "cc" * 64
        self.assertIsNone(parse_gpg_checksum(content, "file.iso", "sha256"))
        _ok("Length mismatch rejected rather than compared")

    def test_unknown_algo_returns_none(self) -> None:
        self.assertIsNone(
            parse_gpg_checksum("SHA256 (f.iso) = " + "aa" * 32, "f.iso", "crc32")
        )


class TestParseHashsums(unittest.TestCase):
    def test_parses_ubuntu_style(self) -> None:
        _section("parse_hashsums: Ubuntu/Debian SHA256SUMS")
        content = (
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  ubuntu-24.04-live-server-amd64.iso\n"
            "0000000000000000000000000000000000000000000000000000000000000000  other.iso\n"
        )
        result = parse_hashsums(content, "ubuntu-24.04-live-server-amd64.iso")
        self.assertEqual(
            result, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        )
        _ok("Extracted hash from SHA256SUMS")

    def test_parses_arch_style(self) -> None:
        content = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  archlinux-2025.01.01-x86_64.iso\n"
        result = parse_hashsums(content, "archlinux-2025.01.01-x86_64.iso")
        self.assertEqual(
            result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        _ok("Extracted hash for Arch ISO")

    def test_no_match_returns_none(self) -> None:
        result = parse_hashsums("aaaa  some-other.iso\n", "missing.iso")
        self.assertIsNone(result)

    def test_empty_content(self) -> None:
        result = parse_hashsums("", "file.iso")
        self.assertIsNone(result)

    def test_binary_mode_asterisk_prefix(self) -> None:
        content = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  *ubuntu-24.04-live-server-amd64.iso\n"
        result = parse_hashsums(content, "ubuntu-24.04-live-server-amd64.iso")
        self.assertEqual(
            result, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        )
        _ok("Parsed Debian-style *filename field")

    def test_no_substring_false_positive(self) -> None:
        content = (
            "0000000000000000000000000000000000000000000000000000000000000000  not-ubuntu-24.04-live-server-amd64.iso\n"
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  ubuntu-24.04-live-server-amd64.iso\n"
        )
        result = parse_hashsums(content, "ubuntu-24.04-live-server-amd64.iso")
        self.assertEqual(
            result, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        )
        _ok("Exact filename match avoids substring false positives")

    def test_multi_algorithm_sections_pick_requested_algo(self) -> None:
        """Parrot-shaped signed-hashes.txt: md5/sha256/sha512 sections.

        This is the regression for the data-loss bug: the md5 line comes first,
        so a first-match parser returned a 32-hex digest that could never match
        a sha256 comparison, and download_iso deleted the finished download.
        """
        content = (
            "md5\n"
            "a3ddddeb89af1768ff28d45dce5c6285  Parrot-security-7.4_amd64.iso\n"
            "sha256\n"
            "ca241282068701f481d96487dcd1af788bd897cd586ceb38ee16f61e387aa291"
            "  Parrot-security-7.4_amd64.iso\n"
            "sha512\n"
            "cc85c85061aa5539afc865895c9a2354a709ca53e246264a71dc93eeb2eedaac1"
            "7b9d548f25235655fefbc7c7e080398af061c041f8ba91d4ae43ddd163e931b"
            "  Parrot-security-7.4_amd64.iso\n"
        )
        iso = "Parrot-security-7.4_amd64.iso"
        self.assertEqual(
            parse_hashsums(content, iso, "sha256"),
            "ca241282068701f481d96487dcd1af788bd897cd586ceb38ee16f61e387aa291",
        )
        self.assertEqual(
            parse_hashsums(content, iso, "sha512"),
            "cc85c85061aa5539afc865895c9a2354a709ca53e246264a71dc93eeb2eedaac1"
            "7b9d548f25235655fefbc7c7e080398af061c041f8ba91d4ae43ddd163e931b",
        )
        self.assertEqual(
            parse_hashsums(content, iso, "md5"),
            "a3ddddeb89af1768ff28d45dce5c6285",
        )
        _ok("Section headers select the requested algorithm, not the first line")

    def test_multi_algorithm_default_algo_is_sha256(self) -> None:
        """Defaulting to sha256 must not regress to 'first match' behaviour."""
        content = (
            "md5\n"
            "a3ddddeb89af1768ff28d45dce5c6285  Parrot-security-7.4_amd64.iso\n"
            "sha256\n"
            "ca241282068701f481d96487dcd1af788bd897cd586ceb38ee16f61e387aa291"
            "  Parrot-security-7.4_amd64.iso\n"
        )
        self.assertEqual(
            parse_hashsums(content, "Parrot-security-7.4_amd64.iso"),
            "ca241282068701f481d96487dcd1af788bd897cd586ceb38ee16f61e387aa291",
        )

    def test_absent_algo_section_returns_none(self) -> None:
        """No sha512 section means unavailable, not a wrong-length digest."""
        content = (
            "md5\n"
            "a3ddddeb89af1768ff28d45dce5c6285  Parrot-security-7.4_amd64.iso\n"
            "sha256\n"
            "ca241282068701f481d96487dcd1af788bd897cd586ceb38ee16f61e387aa291"
            "  Parrot-security-7.4_amd64.iso\n"
        )
        self.assertIsNone(
            parse_hashsums(content, "Parrot-security-7.4_amd64.iso", "sha512")
        )
        _ok("Missing algorithm yields None so the caller keeps the file")

    def test_section_headers_absent_length_is_backstop(self) -> None:
        """With no headers, digest length alone must disambiguate."""
        content = (
            "a3ddddeb89af1768ff28d45dce5c6285  Parrot-security-7.4_amd64.iso\n"
            "ca241282068701f481d96487dcd1af788bd897cd586ceb38ee16f61e387aa291"
            "  Parrot-security-7.4_amd64.iso\n"
        )
        self.assertEqual(
            parse_hashsums(content, "Parrot-security-7.4_amd64.iso", "sha256"),
            "ca241282068701f481d96487dcd1af788bd897cd586ceb38ee16f61e387aa291",
        )
        _ok("Length check still protects header-less files")

    def test_sha1sums_selects_sha1(self) -> None:
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # 40 hex
        sha256 = "ca241282068701f481d96487dcd1af788bd897cd586ceb38ee16f61e387aa291"
        content = (
            f"{sha1}  Parrot-security-7.4_amd64.iso\n"
            f"{sha256}  Parrot-security-7.4_amd64.iso\n"
        )
        self.assertEqual(
            parse_hashsums(content, "Parrot-security-7.4_amd64.iso", "sha1"), sha1
        )
        self.assertEqual(
            parse_hashsums(content, "Parrot-security-7.4_amd64.iso", "sha256"), sha256
        )
        _ok("40-hex and 64-hex digests disambiguate by length")


class TestParseTailsJson(unittest.TestCase):
    def test_parses_valid_json(self) -> None:
        _section("parse_tails_json: Tails latest.json")
        data = {
            "sha256": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "version": "6.5",
        }
        content = json.dumps(data)
        result = parse_tails_json(content)
        self.assertEqual(
            result, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
        )
        _ok("Extracted sha256 from Tails JSON")

    def test_missing_field_returns_none(self) -> None:
        result = parse_tails_json('{"version": "6.5"}')
        self.assertIsNone(result)

    def test_invalid_json_returns_none(self) -> None:
        result = parse_tails_json("not json")
        self.assertIsNone(result)

    def test_rejects_digest_of_wrong_length(self) -> None:
        """A short digest must not be compared against a sha256 local hash."""
        data = {"sha256": "abcd1234"}
        self.assertIsNone(parse_tails_json(json.dumps(data)))


class TestExpandUrl(unittest.TestCase):
    def test_substitutes_iso_name(self) -> None:
        _section("expand_url: Template Substitution")
        result = expand_url(
            "{base_url}sha256sums.txt", "debian-12.iso", "https://example.com/debian/"
        )
        self.assertEqual(result, "https://example.com/debian/sha256sums.txt")
        _ok("Substituted {base_url}")

    def test_substitutes_iso_name_only(self) -> None:
        result = expand_url(
            "{base_url}{iso_name}.sig", "test.iso", "https://example.com/"
        )
        self.assertEqual(result, "https://example.com/test.iso.sig")
        _ok("Substituted {iso_name}")

    def test_strips_trailing_slash(self) -> None:
        result = expand_url(
            "{base_url}sha256sums.txt", "f.iso", "https://example.com/dir///"
        )
        self.assertEqual(result, "https://example.com/dir/sha256sums.txt")
        _ok("Trailing slashes stripped")

    def test_substitutes_version(self) -> None:
        result = expand_url(
            "{base_url}{version}/SHA256SUMS",
            "ubuntu-24.04.4-live-server-amd64.iso",
            "https://releases.ubuntu.com/",
        )
        self.assertEqual(result, "https://releases.ubuntu.com/24.04.4/SHA256SUMS")
        _ok("Substituted {version}")


class TestVerifyIso(unittest.TestCase):
    def _make_iso(self, tmpdir: Path, data: bytes) -> Path:
        p = Path(tmpdir) / "test.iso"
        p.write_bytes(data)
        return p

    @patch("visync.verify.urlopen")
    def test_verify_matching_hash(self, mock_urlopen: MagicMock) -> None:
        _section("verify_iso: Matching Hash")
        data = b"debian-netinst bytes\n" * 1000
        local_hash = hashlib.sha256(data).hexdigest()
        checksum_content = f"{local_hash}  test.iso\n"

        mock_resp = MagicMock()
        mock_resp.read.return_value = checksum_content.encode()
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with tempfile.TemporaryDirectory() as tmpdir:
            iso = self._make_iso(Path(tmpdir), data)
            result = verify_iso(
                iso, "https://example.com/SHA256SUMS", checksum_format="sha256sums"
            )
            self.assertTrue(result)
            _ok("ISO verified successfully against SHA256SUMS")

    @patch("visync.verify.urlopen")
    def test_verify_wrong_hash(self, mock_urlopen: MagicMock) -> None:
        _section("verify_iso: Wrong Hash")
        data = b"tampered content\n" * 500
        wrong_hash = "00" * 32
        checksum_content = f"{wrong_hash}  test.iso\n"

        mock_resp = MagicMock()
        mock_resp.read.return_value = checksum_content.encode()
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with tempfile.TemporaryDirectory() as tmpdir:
            iso = self._make_iso(Path(tmpdir), data)
            result = verify_iso(
                iso, "https://example.com/SHA256SUMS", checksum_format="sha256sums"
            )
            self.assertFalse(result)
            _ok("Wrong hash correctly rejected")

    @patch("visync.verify.urlopen")
    def test_network_failure_raises_unavailable(self, mock_urlopen: MagicMock) -> None:
        _section("verify_iso: Network Failure")
        mock_urlopen.side_effect = Exception("connection timeout")
        with tempfile.TemporaryDirectory() as tmpdir:
            iso = self._make_iso(Path(tmpdir), b"x")
            with self.assertRaises(ChecksumUnavailable):
                verify_iso(iso, "https://example.com/SHA256SUMS")
            _ok("Network failure raises ChecksumUnavailable (file must be kept)")

    @patch("visync.verify.urlopen")
    def test_verify_json_format(self, mock_urlopen: MagicMock) -> None:
        _section("verify_iso: JSON Format (Tails)")
        data = b"tails iso bytes\n" * 200
        local_hash = hashlib.sha256(data).hexdigest()
        checksum_content = json.dumps({"sha256": local_hash, "version": "6.5"})

        mock_resp = MagicMock()
        mock_resp.read.return_value = checksum_content.encode()
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with tempfile.TemporaryDirectory() as tmpdir:
            iso = self._make_iso(Path(tmpdir), data)
            result = verify_iso(
                iso, "https://example.com/latest.json", checksum_format="json"
            )
            self.assertTrue(result)
            _ok("JSON checksum format verified end-to-end")

    @patch("visync.verify.urlopen")
    def test_unknown_format_raises_unavailable(self, mock_urlopen: MagicMock) -> None:
        _section("verify_iso: Unknown Format")
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with tempfile.TemporaryDirectory() as tmpdir:
            iso = self._make_iso(Path(tmpdir), b"x")
            with self.assertRaises(ChecksumUnavailable):
                verify_iso(iso, "https://example.com/x", checksum_format="unknown")
            _ok("Unknown format raises ChecksumUnavailable (file must be kept)")

    @patch("visync.verify.urlopen")
    def test_missing_entry_raises_unavailable(self, mock_urlopen: MagicMock) -> None:
        """ISO absent from the sums file is 'unavailable', not a mismatch."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"aaaa  some-other.iso\n"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with tempfile.TemporaryDirectory() as tmpdir:
            iso = self._make_iso(Path(tmpdir), b"real data")
            with self.assertRaises(ChecksumUnavailable):
                verify_iso(iso, "https://example.com/SHA256SUMS")


class TestVerifyFromConfig(unittest.TestCase):
    def test_no_checksum_url_returns_none(self) -> None:
        _section("verify_from_config: No checksum config")
        result = verify_from_config(
            iso_path=Path("/tmp/test.iso"),
            distro_name="Fedora",
            distro_config={},
            checksums_config={},
        )
        self.assertIsNone(result)
        _ok("Returns None when no checksum_url configured")

    def test_disabled_checksums_returns_none(self) -> None:
        result = verify_from_config(
            iso_path=Path("/tmp/test.iso"),
            distro_name="Fedora",
            distro_config={"checksum_url": "https://example.com/CHECKSUM"},
            checksums_config={"enabled": False},
        )
        self.assertIsNone(result)
        _ok("Returns None when checksums disabled in config")


class TestVerifyAllIsos(unittest.TestCase):
    def test_iterates_over_distro_map(self) -> None:
        _section("verify_all_isos: Iteration")
        distro_map = {
            "/tmp/isos/a.iso": (Path("/tmp/isos/a.iso"), "Arch Linux"),
            "/tmp/isos/b.iso": (Path("/tmp/isos/b.iso"), "Ubuntu Server"),
        }
        configs = {
            "Arch Linux": {"checksum_url": "https://example.com/sha256sums.txt"},
            "Ubuntu Server": {},
        }
        results = verify_all_isos(distro_map, configs, {})
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][1], "Arch Linux")
        self.assertEqual(results[1][1], "Ubuntu Server")
        _info(f"Processed {len(results)} ISOs")
        _ok("verify_all_isos iterated correctly")


if __name__ == "__main__":
    print()
    print(f"  {'#' * 62}")
    print("  #   VERIFY MODULE — UNIT TESTS")
    print(f"  {'#' * 62}")
    print()
    _info("Testing hash computation, checksum parsers, URL expansion, and verification")
    print()
    unittest.main(verbosity=2)
