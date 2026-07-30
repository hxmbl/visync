"""
Discover Ventoy drives and locate ISO files.

Detects Ventoy volumes on Windows, macOS and Linux, reads ISO volume IDs
from the file header, maps IDs to friendly distro names, and discovers
.iso files under a directory.
"""

import json
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from src.output import console, warn

def load_config(config_path: Path | None = None) -> dict:
    """Load configuration dictionary maps and distro settings from config.toml."""
    if config_path is None:
        cwd = Path.cwd()
        for candidate in [
            cwd / "config.toml",
            cwd.parent / "config.toml",
            Path(__file__).parent.parent / "config.toml",
        ]:
            if candidate.is_file():
                config_path = candidate
                break
        else:
            config_path = cwd / "config.toml"
    try:
        with open(config_path, "rb") as f:
            return tomllib.load(f)
    except Exception as e:
        console.print(f"  [red]✗[/red] Failed to parse config.toml: {e}")
        return {}


def _mount_device(dev: str, detected: list[Path]) -> None:
    """Try to mount a device temporarily and add its path if successful."""
    import subprocess

    import tempfile

    mount_dir = Path(tempfile.mkdtemp(prefix="ventoy_"))
    try:
        subprocess.run(
            ["mount", dev, str(mount_dir)],
            capture_output=True, timeout=10,
        )
        if mount_dir.is_dir() and any(mount_dir.iterdir()):
            detected.append(mount_dir)
    except Exception:
        pass


def _udisksctl_mount(dev: str) -> Path | None:
    """Mount a block device using udisksctl (no root required on most setups)."""
    import subprocess

    try:
        result = subprocess.run(
            ["udisksctl", "mount", "-b", dev],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            # Output: "Mounted /dev/sdX1 at /run/media/$USER/Ventoy"
            for line in result.stdout.strip().splitlines():
                if "at " in line:
                    mount_point = line.split("at ", 1)[-1].strip().rstrip(".")
                    return Path(mount_point)
    except FileNotFoundError:
        pass  # udisksctl not installed
    except Exception:
        pass
    return None


def _try_mount_ventoy(partition: dict, detected: list[Path]) -> None:
    """When Ventoy data partition is unmounted, find the dm-exposed device and mount it."""
    for child in partition.get("children", []):
        if child.get("mountpoint"):
            continue
        child_name = child.get("name", "")
        child_type = child.get("type", "")
        if not child_name:
            continue
        # dm devices live under /dev/mapper/<name>
        if child_type == "dm":
            dev_path = f"/dev/mapper/{child_name}"
        else:
            dev_path = f"/dev/{child_name}"
        # Try udisksctl first (no root required)
        mount_point = _udisksctl_mount(dev_path)
        if mount_point:
            detected.append(mount_point)
            return
        # Fallback to manual mount
        _mount_device(dev_path, detected)
        if detected:
            return


def find_ventoy_drives() -> list[Path]:
    """Detect mounted Ventoy drives across Windows, macOS, and Linux.

    Returns a list of Path objects pointing to the root of each detected
    Ventoy drive. Index [0] for the primary drive.
    """
    import platform
    import subprocess

    system = platform.system()
    detected_paths = []

    if system == "Linux":
        import json

        cmd = ["lsblk", "-o", "NAME,TYPE,LABEL,MOUNTPOINT", "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                for device in data.get("blockdevices", []):
                    for partition in device.get("children", []):
                        label = partition.get("label")
                        mount = partition.get("mountpoint")
                        if label in ("Ventoy", "VTOYEFI"):
                            if mount:
                                detected_paths.append(Path(mount))
                            elif label == "Ventoy":
                                _try_mount_ventoy(partition, detected_paths)
            except (json.JSONDecodeError, KeyError):
                pass

        # Fallback: blkid + findmnt (covers systems without lsblk)
        if not detected_paths:
            for lbl in ("Ventoy", "VTOYEFI"):
                try:
                    blkid_proc = subprocess.run(
                        ["blkid", "-L", lbl], capture_output=True, text=True, timeout=10
                    )
                    if blkid_proc.returncode != 0 or not blkid_proc.stdout.strip():
                        continue
                    dev = blkid_proc.stdout.strip()
                    mnt_proc = subprocess.run(
                        ["findmnt", "-n", "-o", "TARGET", dev],
                        capture_output=True, text=True, timeout=10,
                    )
                    if mnt_proc.returncode == 0 and mnt_proc.stdout.strip():
                        detected_paths.append(Path(mnt_proc.stdout.strip()))
                    elif lbl == "Ventoy":
                        mount_point = _udisksctl_mount(dev)
                        if mount_point:
                            detected_paths.append(mount_point)
                        else:
                            _mount_device(dev, detected_paths)
                except Exception:
                    continue

    elif system == "Darwin":
        import plistlib

        cmd = ["diskutil", "list", "-plist"]
        result = subprocess.run(cmd, capture_output=True)

        if result.returncode != 0:
            return []

        try:
            data = plistlib.loads(result.stdout)

            for pool in data.get("AllDisksAndPartitions", []):
                for partition in pool.get("Partitions", [pool]):
                    volume_name = partition.get("VolumeName")
                    mount_point = partition.get("MountPoint")

                    if volume_name in ["Ventoy", "VTOYEFI"] and mount_point:
                        detected_paths.append(Path(mount_point))
        except Exception:
            return []

    elif system == "Windows":
        import json

        cmd = "@(Get-Volume | Where-Object {$_.FileSystemLabel -match 'Ventoy|VTOYEFI'} | Select-Object DriveLetter) | ConvertTo-Json"
        result = subprocess.run(
            ["powershell", "-Command", cmd], capture_output=True, text=True
        )

        if not result.stdout.strip():
            return []

        detected_paths = []
        try:
            drives_data = json.loads(result.stdout)
            if isinstance(drives_data, dict):
                drives_data = [drives_data]

            detected_paths = [
                Path(f"{drive['DriveLetter']}:\\")
                for drive in drives_data
                if drive.get("DriveLetter")
            ]
        except json.JSONDecodeError:
            return []

    else:
        raise NotImplementedError(
            f"Unsupported operating system: {system}\nThis script currently supports Windows, macOS, and Linux.\nTo add support for your OS, please contribute to github.com/hxmbl/visync"
        )

    return detected_paths


def get_iso_volume_id(iso_path: Path) -> str:
    """Read the unchangeable internal Volume Identifier of an ISO file."""
    try:
        with open(iso_path, "rb") as f:
            # Skip directly to the ISO 9660 primary descriptor header
            f.seek(32808)
            volume_id = f.read(32)
            return volume_id.decode("utf-8", errors="ignore").strip("\x00 ")
    except Exception:
        return ""


def identify_distro(volume_id: str, file_name: str) -> str:
    """Match the OS distribution using a cascading hybrid approach.

    Checks strict Volume ID matches, contextual filename overrides for forks,
    standalone keyword rules, and finally regex filename parsing as fallback.
    """
    import re

    vol_lower = volume_id.lower().strip()
    file_lower = file_name.lower().strip()

    config = load_config()

    # Check standalone matches first — they're more specific than base distros
    standalone_matches = config.get("standalone_matches", {})
    for keyword, clean_name in standalone_matches.items():
        if keyword in vol_lower or keyword in file_lower:
            return clean_name

    base_distros = config.get("base_distros", {})
    fork_overrides = config.get("fork_overrides", {})

    for base_key, base_name in base_distros.items():
        if base_key in vol_lower:
            for override_key, clean_name in fork_overrides.items():
                parent, _, keyword = override_key.partition(".")
                if parent == base_key and keyword in file_lower:
                    return clean_name
            return base_name

    if not file_lower.endswith(".iso"):
        return "Unknown OS"

    name_match = re.match(r"^([a-zA-Z_\-]+?)(?:[-_]v?\d|\.)", file_name)
    if name_match:
        extracted_name = (
            name_match.group(1).replace("-", " ").replace("_", " ").title().strip()
        )
        return extracted_name

    return "Unknown OS"


def find_installed_isos(directory: Path) -> list[Path]:
    """Find all ISO/IMG files under the given directory, ignoring macOS resource forks and .visync metadata."""
    return [
        p for p in directory.rglob("*")
        if p.suffix.lower() in (".iso", ".img")
        and not p.name.startswith("._")
        and ".visync" not in p.parts
    ]


# ── .visync metadata engine ──────────────────────────────────────


def ensure_visync_dir(drive_root: Path) -> Path:
    """Create .visync/metadata/ at the drive root if it doesn't exist. Returns the metadata dir."""
    visync_dir = drive_root / ".visync"
    metadata_dir = visync_dir / "metadata"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    return metadata_dir


def read_iso_metadata(drive_root: Path, filename: str) -> dict | None:
    """Read cached JSON metadata for a given ISO filename. Returns None if not found or invalid."""
    metadata_dir = drive_root / ".visync" / "metadata"
    meta_file = metadata_dir / f"{filename}.json"
    try:
        with open(meta_file, "r") as f:
            data = json.load(f)
        # Validate required keys exist
        if "variant_stem" in data and "version" in data:
            return data
    except (json.JSONDecodeError, OSError, KeyError):
        pass
    return None


def write_iso_metadata(
    drive_root: Path,
    filename: str,
    variant_stem: str,
    version: str,
    sha256: str,
) -> None:
    """Write a JSON metadata manifest for a successfully synced ISO."""
    metadata_dir = ensure_visync_dir(drive_root)
    meta_file = metadata_dir / f"{filename}.json"
    manifest = {
        "variant_stem": variant_stem,
        "version": version,
        "sha256": sha256,
        "sync_timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with open(meta_file, "w") as f:
            json.dump(manifest, f, indent=2)
    except OSError as e:
        console.print(f"  [yellow]⚠[/yellow] Could not write metadata for {filename}: {e}")


def remove_iso_metadata(drive_root: Path, filename: str) -> None:
    """Delete the metadata file for a given ISO (called when an ISO is removed)."""
    metadata_dir = drive_root / ".visync" / "metadata"
    meta_file = metadata_dir / f"{filename}.json"
    try:
        meta_file.unlink(missing_ok=True)
    except OSError:
        pass


def load_all_metadata(drive_root: Path) -> dict[str, dict]:
    """Bulk-load all ISO metadata from .visync/metadata/. Returns {filename: manifest}."""
    metadata_dir = drive_root / ".visync" / "metadata"
    if not metadata_dir.is_dir():
        return {}
    result = {}
    for meta_file in metadata_dir.glob("*.json"):
        if meta_file.name.startswith("._"):
            continue
        filename = meta_file.stem
        data = read_iso_metadata(drive_root, filename)
        if data:
            result[filename] = data
    return result


def find_installed_isos_formatted(directory: Path) -> list[str]:
    """Find all ISOs and return their verified distribution names."""
    detected_names = []

    for iso_path in find_installed_isos(directory):
        # Read the internal header label instead of trusting the filename
        volume_id = get_iso_volume_id(iso_path)
        distro = identify_distro(volume_id, iso_path.name)
        detected_names.append(distro)

    return detected_names


# ── .visync watchdog ─────────────────────────────────────────────

VISYNC_SIZE_LIMIT = 1_073_741_824  # 1 GiB
_WATCHDOG_DIR_NAME = ".visync"
_WATCHDOG_ALLOWED_EXTENSIONS = {".json"}  # Only these may be deleted by unlink
_WATCHDOG_BLOCKED_EXTENSIONS = {".iso", ".img"}  # Hard-blocked from deletion


def _guard_json_only(path: Path) -> None:
    """Assert that a file path is a permitted extension for metadata cleanup.

    Raises ValueError immediately if the file is not a .json file.
    This prevents accidental deletion of ISO or IMG files.
    """
    if path.suffix.lower() not in _WATCHDOG_ALLOWED_EXTENSIONS:
        raise ValueError(
            f"SAFETY BLOCK: refusing to delete '{path.name}' — "
            f"only {_WATCHDOG_ALLOWED_EXTENSIONS} files are permitted. "
            f"Blocked extension: {path.suffix}"
        )


def _guard_visync_path(target: Path) -> None:
    """Assert that a directory path is exactly '.visync' and not drive root.

    Raises ValueError immediately if:
    - The path does not end with '.visync'
    - The path IS the drive root itself
    - The path name doesn't match exactly (prevents '../' traversal)
    """
    if target.name != _WATCHDOG_DIR_NAME:
        raise ValueError(
            f"SAFETY BLOCK: refusing to wipe '{target}' — "
            f"target directory must be named exactly '{_WATCHDOG_DIR_NAME}'. "
            f"Got name: '{target.name}'"
        )
    if not target.is_dir():
        raise ValueError(
            f"SAFETY BLOCK: refusing to wipe '{target}' — "
            f"target is not a directory."
        )
    # Ensure it's a direct child, not a traversal to root
    if target == target.parent:
        raise ValueError(
            f"SAFETY BLOCK: refusing to wipe '{target}' — "
            f"target resolves to itself (would delete root)."
        )


def _dir_size(path: Path) -> int:
    """Return total size in bytes of a directory tree."""
    total = 0
    try:
        for entry in path.rglob("*"):
            if entry.is_file():
                total += entry.stat().st_size
    except OSError:
        pass
    return total


def visync_watchdog(drive_root: Path) -> None:
    """Enforce a 1 GiB ceiling on .visync/.

    If the directory exceeds the limit:
    1. Deep clean — delete metadata files whose ISO no longer exists on the drive.
    2. If still over budget — wipe the entire .visync/ directory.

    SAFETY: Before any rmtree call, the target path is validated to be
    exactly '.visync' and not the drive root. A ValueError is raised
    immediately if the path doesn't match.
    """
    try:
        visync_dir = drive_root / _WATCHDOG_DIR_NAME
        if not visync_dir.is_dir():
            return

        size = _dir_size(visync_dir)
        if size <= VISYNC_SIZE_LIMIT:
            return

        console.print(f"  [yellow]⚠[/yellow] Watchdog: .visync/ is {size / (1024**2):.1f} MiB (limit: 1 GiB). Running deep clean...")
        _deep_clean_metadata(drive_root)

        size_after = _dir_size(visync_dir)
        if size_after <= VISYNC_SIZE_LIMIT:
            console.print(f"  [green]✓[/green] Deep clean recovered space. .visync/ now {size_after / (1024**2):.1f} MiB.")
            return

        # GUARDRAIL: Validate target before any recursive deletion
        _guard_visync_path(visync_dir)

        console.print(f"  [yellow]⚠[/yellow] Watchdog: .visync/ still {size_after / (1024**2):.1f} MiB after deep clean. Wiping entirely.")
        import shutil
        try:
            shutil.rmtree(visync_dir)
            console.print(f"  [green]✓[/green] .visync/ wiped. Metadata will rebuild on next sync.")
        except OSError as e:
            console.print(f"  [yellow]⚠[/yellow] Could not wipe .visync/: {e}")
    except ValueError:
        raise
    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow] Watchdog error: {e}")


def _deep_clean_metadata(drive_root: Path) -> None:
    """Remove metadata files whose corresponding ISO no longer exists on the drive.

    SAFETY: Only files ending with '.json' inside the metadata directory
    are eligible for deletion. A ValueError is raised immediately if any
    non-.json file is encountered.
    """
    try:
        metadata_dir = drive_root / _WATCHDOG_DIR_NAME / "metadata"
        if not metadata_dir.is_dir():
            return

        existing_isos = {p.name for p in find_installed_isos(drive_root)}
        removed = 0
        for meta_file in metadata_dir.iterdir():
            # GUARDRAIL: Only allow .json files — reject anything else immediately
            if not meta_file.is_file():
                continue
            _guard_json_only(meta_file)

            iso_name = meta_file.stem  # .json filename = ISO filename
            if iso_name not in existing_isos:
                try:
                    meta_file.unlink()
                    removed += 1
                except OSError as e:
                    console.print(f"  [yellow]⚠[/yellow] Could not remove {meta_file.name}: {e}")
        if removed:
            console.print(f"  [dim]Removed {removed} orphaned metadata file(s).[/dim]")
    except ValueError:
        raise
    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow] Deep clean error: {e}")
