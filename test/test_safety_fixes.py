"""Regression tests for STRM-502, STRM-503, STRM-504 and STRM-505.

No network access or Ventoy hardware is required: every filesystem effect is a
real temporary directory, and the few provider calls involved are patched.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from visync.download import (
    DistroCheck,
    SyncStatus,
    _check_distro,
    _cleanup_old_versions,
    _commit_iso_metadata,
    _place_on_drive,
    sync_all_configured_distros,
)
from visync.finder import (
    get_config_error,
    get_config_path,
    load_config,
    reset_config_cache,
    write_iso_metadata,
)
from visync.verify import (
    ChecksumUnavailable,
    VerifyStatus,
    extract_arch_from_filename,
    extract_build_version,
    extract_version_from_filename,
    run_directory_verify,
)

try:
    from typer.testing import CliRunner

    HAS_TYPER = True
except ImportError:  # pragma: no cover - typer is a runtime dependency
    HAS_TYPER = False
    CliRunner = None  # type: ignore[misc, assignment]


def _write_iso(path: Path, content: bytes = b"iso-bytes") -> None:
    path.write_bytes(content)


def _metadata(drive: Path, filename: str, **fields) -> None:
    meta_dir = drive / ".visync" / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"variant_stem": "fedora", "version": "44", "sha256": "", "size": 0}
    manifest.update(fields)
    (meta_dir / f"{filename}.json").write_text(json.dumps(manifest))


# ── STRM-503: architecture and build revision ────────────────────────────────


class TestUpdateMatchingKeys(unittest.TestCase):
    def test_fedora_build_revision_is_comparable(self) -> None:
        build = extract_build_version("Fedora-Workstation-Live-x86_64-44-1.1.iso")
        self.assertEqual(build, "44.1.1")
        self.assertGreater(
            extract_build_version("Fedora-Workstation-Live-x86_64-44-1.2.iso"),
            extract_build_version("Fedora-Workstation-Live-x86_64-44-1.1.iso"),
        )
        # The display version stays the release people read.
        self.assertEqual(
            extract_version_from_filename("Fedora-Workstation-Live-x86_64-44-1.1.iso"),
            "44",
        )

    def test_popos_build_number_is_comparable(self) -> None:
        self.assertEqual(
            extract_build_version("pop-os_24.04_amd64_intel_25.iso"), "24.04.25"
        )

    def test_arch_families(self) -> None:
        self.assertEqual(extract_arch_from_filename("foo-x86_64.iso"), "x86_64")
        self.assertEqual(extract_arch_from_filename("foo-amd64.iso"), "x86_64")
        self.assertEqual(extract_arch_from_filename("foo-aarch64.iso"), "aarch64")
        self.assertEqual(extract_arch_from_filename("foo-arm64.iso"), "aarch64")
        self.assertEqual(extract_arch_from_filename("Zorin-OS-18-Core-64-bit.iso"), "")


class TestDistroUpdateMatching(unittest.TestCase):
    def _check(self, tmpdir: str, remote: str) -> DistroCheck:
        settings = {"clean_name": "Fedora", "keyword": "fedora"}
        with patch(
            "visync.download.process_scraping_strategy",
            return_value=(remote, "https://example.com/remote.iso"),
        ):
            return _check_distro("Fedora", settings, Path(tmpdir), force=False)

    def test_missing_architecture_is_not_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_iso(Path(tmpdir) / "Fedora-Workstation-Live-x86_64-44-1.1.iso")
            result = self._check(tmpdir, "Fedora-Workstation-Live-aarch64-44-1.1.iso")
        self.assertIs(result.status, SyncStatus.STALE)

    def test_unidentified_local_architecture_is_not_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_iso(Path(tmpdir) / "Fedora-Workstation-Live-44-1.1.iso")
            result = self._check(tmpdir, "Fedora-Workstation-Live-x86_64-44-1.1.iso")
        self.assertIs(result.status, SyncStatus.STALE)

    def test_same_release_rebuilt_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_iso(Path(tmpdir) / "Fedora-Workstation-Live-x86_64-44-1.1.iso")
            result = self._check(tmpdir, "Fedora-Workstation-Live-x86_64-44-1.2.iso")
        self.assertIs(result.status, SyncStatus.STALE)

    def test_popos_same_release_rebuild_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_iso(Path(tmpdir) / "pop-os_24.04_amd64_intel_24.iso")
            result = self._check(tmpdir, "pop-os_24.04_amd64_intel_25.iso")
        self.assertIs(result.status, SyncStatus.STALE)

    def test_identical_build_is_current(self) -> None:
        name = "Fedora-Workstation-Live-x86_64-44-1.1.iso"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_iso(Path(tmpdir) / name)
            result = self._check(tmpdir, name)
        self.assertIs(result.status, SyncStatus.CURRENT)


# ── STRM-502: transactional placement ────────────────────────────────────────


class TestPlaceOnDrive(unittest.TestCase):
    def test_cross_filesystem_copy_is_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            src = root / "staging.iso"
            dst = root / "drive.iso"
            _write_iso(src, b"complete image")
            with patch.object(Path, "rename", side_effect=OSError(18, "cross-device")):
                _place_on_drive(src, dst)
            self.assertEqual(dst.read_bytes(), b"complete image")
            self.assertEqual(
                [p.name for p in root.glob(".*.part")], [], "temp file must be removed"
            )

    def test_interruption_leaves_no_partial_final_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            src = root / "staging.iso"
            dst = root / "drive.iso"
            _write_iso(src, b"new image")
            dst.write_bytes(b"previous working image")
            with (
                patch.object(Path, "rename", side_effect=OSError(18, "cross-device")),
                patch(
                    "visync.download._copy_with_progress",
                    side_effect=KeyboardInterrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                _place_on_drive(src, dst)
            self.assertEqual(dst.read_bytes(), b"previous working image")
            self.assertEqual(list(root.glob(".*.part")), [])

    def test_disk_full_preserves_previous_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            src = root / "staging.iso"
            dst = root / "drive.iso"
            _write_iso(src, b"new image")
            dst.write_bytes(b"previous working image")
            with (
                patch.object(Path, "rename", side_effect=OSError(18, "cross-device")),
                patch(
                    "visync.download._copy_with_progress",
                    side_effect=OSError(28, "No space left on device"),
                ),
                self.assertRaises(OSError),
            ):
                _place_on_drive(src, dst)
            self.assertEqual(dst.read_bytes(), b"previous working image")
            self.assertEqual(list(root.glob(".*.part")), [])

    def test_failed_atomic_replace_preserves_previous_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            src = root / "staging.iso"
            dst = root / "drive.iso"
            _write_iso(src, b"new image")
            dst.write_bytes(b"previous working image")
            with (
                patch.object(Path, "rename", side_effect=OSError(18, "cross-device")),
                patch(
                    "pathlib.Path.replace",
                    side_effect=OSError(5, "I/O error"),
                ),
                self.assertRaises(OSError),
            ):
                _place_on_drive(src, dst)
            self.assertEqual(dst.read_bytes(), b"previous working image")
            self.assertEqual(list(root.glob(".*.part")), [])

    def test_same_size_corruption_fails_copy_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            src = root / "staging.iso"
            dst = root / "drive.iso"
            _write_iso(src, b"new image")
            dst.write_bytes(b"previous working image")
            with (
                patch.object(Path, "rename", side_effect=OSError(18, "cross-device")),
                patch(
                    "visync.download._copy_with_progress",
                    side_effect=lambda _src, temp, _name: temp.write_bytes(
                        b"bad image"
                    ),
                ),
                self.assertRaisesRegex(OSError, "SHA-256"),
            ):
                _place_on_drive(src, dst)
            self.assertEqual(dst.read_bytes(), b"previous working image")
            self.assertEqual(list(root.glob(".*.part")), [])

    def test_forced_replacement_swaps_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            src = root / "staging.iso"
            dst = root / "drive.iso"
            _write_iso(src, b"new image")
            dst.write_bytes(b"previous working image")
            with patch.object(Path, "rename", side_effect=OSError(18, "cross-device")):
                _place_on_drive(src, dst)
            self.assertEqual(dst.read_bytes(), b"new image")

    def test_same_filesystem_uses_rename(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            src = root / "staging.iso"
            dst = root / "drive.iso"
            _write_iso(src, b"new image")
            _place_on_drive(src, dst)
            self.assertEqual(dst.read_bytes(), b"new image")
            self.assertFalse(src.exists())


class TestMetadataCommitOrder(unittest.TestCase):
    def test_metadata_records_provenance_after_placement(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = Path(tmpdir)
            iso = drive / "Fedora-Workstation-Live-x86_64-44-1.1.iso"
            _write_iso(iso, b"payload")
            outcome = {
                "sha256": hashlib.sha256(b"payload").hexdigest(),
                "verified": True,
                "version": "44",
                "variant_stem": "fedora",
                "upstream_sha256": "AB" * 32,
                "upstream_source": "https://example.com/CHECKSUM",
                "upstream_algo": "sha256",
                "signature": "gpg-verified",
            }
            _commit_iso_metadata(drive, iso, outcome)
            manifest = json.loads(
                (drive / ".visync" / "metadata" / f"{iso.name}.json").read_text()
            )
            self.assertEqual(manifest["upstream_sha256"], "ab" * 32)
            self.assertEqual(
                manifest["upstream_source"], "https://example.com/CHECKSUM"
            )
            self.assertEqual(manifest["signature"], "gpg-verified")

    def test_failed_placement_commits_no_metadata(self) -> None:
        filename = "Fedora-Workstation-Live-x86_64-44-1.1.iso"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            drive = root / "drive"
            staging = root / "staging"
            drive.mkdir()
            staging.mkdir()
            # A previous working image of the same name must survive.
            (drive / filename).write_bytes(b"previous working image")

            config = {
                "iso": {"download_dir": str(staging)},
                "checksums": {"enabled": False},
                "distros": {"Fedora": {"clean_name": "Fedora", "keyword": "fedora"}},
            }

            def fake_download(_url, dest, **kwargs):
                dest.write_bytes(b"new image")
                kwargs["outcome"].update(
                    {
                        "sha256": hashlib.sha256(b"new image").hexdigest(),
                        "verified": True,
                        "version": "44",
                        "variant_stem": "fedora",
                    }
                )
                return True

            with (
                patch("visync.download.visync_watchdog"),
                patch("visync.download.load_config", return_value=config),
                patch("visync.download.download_iso", side_effect=fake_download),
                patch(
                    "visync.download._check_distro",
                    return_value=DistroCheck(
                        "Fedora",
                        "Fedora",
                        filename,
                        SyncStatus.STALE,
                        "https://example.com/x.iso",
                    ),
                ),
                patch(
                    "visync.download._place_on_drive",
                    side_effect=OSError(28, "No space left on device"),
                ),
            ):
                _dir, downloaded, failures = sync_all_configured_distros(
                    drive_override=drive,
                    only=["Fedora"],
                    use_buffer=True,
                )

            self.assertEqual(downloaded, [])
            self.assertTrue(failures)
            self.assertEqual((drive / filename).read_bytes(), b"previous working image")
            self.assertFalse(
                (drive / ".visync" / "metadata" / f"{filename}.json").exists(),
                "no metadata may describe a file that never landed",
            )

    def test_drive_cleanup_requires_clean_and_verified_replacement(self) -> None:
        filename = "Fedora-Workstation-Live-x86_64-44-1.2.iso"
        for clean in (False, True):
            with self.subTest(clean=clean), tempfile.TemporaryDirectory() as tmpdir:
                drive = Path(tmpdir)
                config = {
                    "iso": {"download_dir": ""},
                    "checksums": {"enabled": True},
                    "distros": {
                        "Fedora": {"clean_name": "Fedora", "keyword": "fedora"}
                    },
                }

                def fake_download(_url, dest, **kwargs):
                    dest.write_bytes(b"verified image")
                    kwargs["outcome"].update(
                        {
                            "sha256": hashlib.sha256(b"verified image").hexdigest(),
                            "verified": True,
                            "version": "44",
                            "variant_stem": "fedora",
                        }
                    )
                    return True

                with (
                    patch("visync.download.visync_watchdog"),
                    patch("visync.download._sweep_old_versions"),
                    patch("visync.download.load_config", return_value=config),
                    patch("visync.download.download_iso", side_effect=fake_download),
                    patch(
                        "visync.download._check_distro",
                        return_value=DistroCheck(
                            "Fedora",
                            "Fedora",
                            filename,
                            SyncStatus.STALE,
                            "https://example.com/x.iso",
                        ),
                    ),
                    patch("visync.download._cleanup_old_versions") as cleanup,
                ):
                    sync_all_configured_distros(
                        clean=clean,
                        drive_override=drive,
                        only=["Fedora"],
                        use_buffer=False,
                    )

                self.assertEqual(cleanup.call_count, int(clean))
                if clean:
                    self.assertTrue(cleanup.call_args.kwargs["verified"])


class TestInterruptMessage(unittest.TestCase):
    def test_interrupt_reports_kept_files(self) -> None:
        import typer

        from visync.main import _interruptible
        from visync.output import console

        @_interruptible
        def boom() -> None:
            raise KeyboardInterrupt

        with console.capture() as captured, self.assertRaises(typer.Exit):
            boom()
        text = captured.get()
        self.assertIn("In-flight downloads were removed", text)
        self.assertIn("were kept", text)
        self.assertIn("replaced only after verification", text)


# ── STRM-504: persisted verification evidence ────────────────────────────────


class TestPersistedVerificationEvidence(unittest.TestCase):
    def _run(self, drive: Path, filename: str, config: dict):
        iso = drive / filename
        with (
            patch(
                "visync.verify.build_iso_distro_map",
                return_value={str(iso): (iso, "Unknown OS")},
            ),
        ):
            return run_directory_verify(drive, config)

    def test_evidence_recovered_after_restart(self) -> None:
        content = b"downloaded payload"
        digest = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = Path(tmpdir)
            iso = drive / "pop-os_24.04_amd64_intel_25.iso"
            _write_iso(iso, content)
            _metadata(
                drive,
                iso.name,
                upstream_sha256=digest,
                upstream_source="https://api.pop-os.org/builds/24.04/generic",
                upstream_algo="sha256",
            )
            results = self._run(
                drive,
                iso.name,
                {"checksums": {"enabled": True}, "distros": {}},
            )
        self.assertEqual(results[0].status, VerifyStatus.VERIFIED)
        self.assertEqual(
            results[0].upstream_source,
            "https://api.pop-os.org/builds/24.04/generic",
        )

    def test_evidence_mismatch_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = Path(tmpdir)
            iso = drive / "pop-os_24.04_amd64_intel_25.iso"
            _write_iso(iso, b"corrupted payload")
            _metadata(
                drive,
                iso.name,
                upstream_sha256=hashlib.sha256(b"expected payload").hexdigest(),
                upstream_source="https://api.pop-os.org/builds/24.04/generic",
            )
            results = self._run(
                drive,
                iso.name,
                {"checksums": {"enabled": True}, "distros": {}},
            )
        self.assertEqual(results[0].status, VerifyStatus.MISMATCH)

    def test_local_hash_is_not_upstream_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = Path(tmpdir)
            iso = drive / "pop-os_24.04_amd64_intel_25.iso"
            _write_iso(iso, b"payload")
            _metadata(
                drive,
                iso.name,
                sha256=hashlib.sha256(b"payload").hexdigest(),
                size=len(b"payload"),
            )
            results = self._run(
                drive,
                iso.name,
                {"checksums": {"enabled": True}, "distros": {}},
            )
        self.assertEqual(results[0].status, VerifyStatus.NO_CONFIG)
        self.assertEqual(results[0].upstream_source, "")

    def test_unreachable_source_falls_back_to_evidence(self) -> None:
        content = b"payload"
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = Path(tmpdir)
            iso = drive / "pop-os_24.04_amd64_intel_25.iso"
            _write_iso(iso, content)
            _metadata(
                drive,
                iso.name,
                upstream_sha256=hashlib.sha256(content).hexdigest(),
                upstream_source="https://api.pop-os.org/builds/24.04/generic",
            )
            with patch(
                "visync.verify.verify_from_config",
                side_effect=ChecksumUnavailable("mirror unreachable"),
            ):
                results = self._run(
                    drive,
                    iso.name,
                    {"checksums": {"enabled": True}, "distros": {}},
                )
        self.assertEqual(results[0].status, VerifyStatus.VERIFIED)

    def test_metadata_keeps_local_and_upstream_separate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = Path(tmpdir)
            write_iso_metadata(
                drive,
                "x.iso",
                "stem",
                "1",
                "aa" * 32,
                size=10,
                upstream_sha256="bb" * 32,
                upstream_source="https://example.com/SUMS",
                upstream_algo="sha256",
            )
            manifest = json.loads(
                (drive / ".visync" / "metadata" / "x.iso.json").read_text()
            )
        self.assertEqual(manifest["sha256"], "aa" * 32)
        self.assertEqual(manifest["upstream_sha256"], "bb" * 32)
        self.assertEqual(manifest["upstream_source"], "https://example.com/SUMS")


class TestRollbackRetention(unittest.TestCase):
    @patch("visync.download.identify_distro", return_value="Fedora")
    @patch("visync.download.get_iso_volume_id")
    @patch("visync.download.find_installed_isos")
    def test_unverified_replacement_keeps_previous(
        self, mock_find, mock_vid, _mock_id
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = Path(tmpdir)
            new_iso = drive / "Fedora-Workstation-Live-x86_64-44-1.2.iso"
            old_iso = drive / "Fedora-Workstation-Live-x86_64-44-1.1.iso"
            _write_iso(new_iso, b"new")
            _write_iso(old_iso, b"old")
            mock_vid.side_effect = lambda p: (
                "Fedora-Workstation-Live-44-1.2"
                if p == new_iso
                else "Fedora-Workstation-Live-44-1.1"
            )
            mock_find.return_value = [new_iso, old_iso]
            _cleanup_old_versions(new_iso, drive, verified=False)
            self.assertTrue(old_iso.exists(), "verified rollback must be retained")

    @patch("visync.download.identify_distro", return_value="Fedora")
    @patch("visync.download.get_iso_volume_id")
    @patch("visync.download.find_installed_isos")
    def test_verified_replacement_removes_previous(
        self, mock_find, mock_vid, _mock_id
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            drive = Path(tmpdir)
            new_iso = drive / "Fedora-Workstation-Live-x86_64-44-1.2.iso"
            old_iso = drive / "Fedora-Workstation-Live-x86_64-44-1.1.iso"
            _write_iso(new_iso, b"new")
            _write_iso(old_iso, b"old")
            mock_vid.side_effect = lambda p: (
                "Fedora-Workstation-Live-44-1.2"
                if p == new_iso
                else "Fedora-Workstation-Live-44-1.1"
            )
            mock_find.return_value = [new_iso, old_iso]
            _cleanup_old_versions(new_iso, drive, verified=True)
            self.assertFalse(old_iso.exists())


# ── STRM-505: configuration selection ────────────────────────────────────────


class TestConfigSelection(unittest.TestCase):
    def setUp(self) -> None:
        reset_config_cache()

    def tearDown(self) -> None:
        reset_config_cache()

    def test_missing_explicit_env_path_is_an_error(self) -> None:
        missing = "/nonexistent/visync/config.toml"
        with patch.dict(os.environ, {"VISYNC_CONFIG": missing}):
            data = load_config()
        self.assertEqual(data, {})
        self.assertIn("VISYNC_CONFIG", get_config_error() or "")
        self.assertIn(missing, get_config_error() or "")
        self.assertIsNone(get_config_path())

    def test_explicit_env_path_does_not_fall_back(self) -> None:
        """A bad VISYNC_CONFIG must not silently use the packaged catalogue."""
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = str(Path(tmpdir) / "absent.toml")
            with patch.dict(os.environ, {"VISYNC_CONFIG": missing}):
                data = load_config()
            self.assertEqual(data, {})

    def test_invalid_toml_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.toml"
            path.write_text("this is not [ valid toml")
            data = load_config(path)
        self.assertEqual(data, {})
        self.assertIn("Invalid TOML", get_config_error() or "")
        self.assertIn(str(path), get_config_error() or "")

    def test_missing_explicit_path_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "absent.toml"
            data = load_config(path)
        self.assertEqual(data, {})
        self.assertIn("not found", (get_config_error() or "").lower())

    def test_effective_path_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.toml"
            path.write_text('[distros.Arch]\nclean_name = "Arch Linux"\n')
            data = load_config(path)
            self.assertIn("Arch", data.get("distros", {}))
            self.assertEqual(get_config_path(), path)

    def test_user_config_is_considered_without_env_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "user-config.toml"
            path.write_text('[distros.Arch]\nclean_name = "Arch Linux"\n')
            with (
                patch.dict(os.environ, {}, clear=True),
                patch(
                    "visync.finder._config_candidates",
                    return_value=[path, Path(tmpdir) / "packaged-config.toml"],
                ),
            ):
                data = load_config()
        self.assertIn("Arch", data.get("distros", {}))
        self.assertEqual(get_config_path(), path)


@unittest.skipUnless(HAS_TYPER, "typer not installed")
class TestConfigCommand(unittest.TestCase):
    def setUp(self) -> None:
        reset_config_cache()
        from visync.main import app

        self.app = app
        self.runner = CliRunner()

    def tearDown(self) -> None:
        reset_config_cache()

    def test_config_reports_effective_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.toml"
            path.write_text('[distros.Arch]\nclean_name = "Arch Linux"\n')
            result = self.runner.invoke(self.app, ["config", "--config", str(path)])
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn(str(path), result.stdout)
        self.assertIn("1 distribution(s)", result.stdout)

    def test_config_fails_on_invalid_env_path(self) -> None:
        missing = "/nonexistent/visync/config.toml"
        with patch.dict(os.environ, {"VISYNC_CONFIG": missing}):
            result = self.runner.invoke(self.app, ["config"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn(missing, result.stdout)

    def test_config_makes_no_download(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.toml"
            path.write_text('[distros.Arch]\nclean_name = "Arch Linux"\n')
            with patch("visync.download.download_iso") as mock_download:
                result = self.runner.invoke(self.app, ["config", "--config", str(path)])
        self.assertEqual(result.exit_code, 0, result.stdout)
        mock_download.assert_not_called()
