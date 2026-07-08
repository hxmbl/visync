"""Visync - Ventoy Package Manager.

Built with typer. Run `visync --help` for available commands.
"""

from pathlib import Path

import typer

from src.finder import (
    find_installed_isos,
    find_ventoy_drives,
    get_iso_volume_id,
    identify_distro,
    load_config,
    load_all_metadata,
)
from src.output import console, error, header, info as output_info, iso_table, success, warn
from src.verify import extract_version_from_filename, run_directory_verify

app = typer.Typer()


def _get_drive(drive: Path | None = None) -> Path:
    """Resolve the Ventoy drive path."""
    if drive is not None:
        return drive
    drives = find_ventoy_drives()
    if not drives:
        error("No Ventoy drives detected.")
        raise typer.Exit(1)
    return drives[0]


@app.command()
def install(
    name: str | None = typer.Argument(default=None, help="Distro name or keyword to install"),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: Path | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path"
    ),
    file: Path | None = typer.Option(
        None, "--file", "-i", help="File with one distro name per line"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Show what would be installed without downloading"
    ),
    no_verify: bool = typer.Option(
        False, "--no-verify", help="Skip checksum verification after download"
    ),
    no_staging: bool = typer.Option(
        False, "--no-staging", "--no-buffer", help="Download directly to the Ventoy drive (skip staging buffer)"
    ),
) -> None:
    """Download and install distros to the Ventoy drive.

    Use a distro name directly, or pass a file with one name per line.
    """
    from src.download import sync_all_configured_distros
    from src.pm import mark_installed, resolve_distro

    config_data = load_config(config)
    ventoy_root = _get_drive(drive)

    # Build list of distros to install
    names: list[str] = []
    if file:
        if not file.exists():
            error(f"File not found: {file}")
            raise typer.Exit(1)
        names = [
            line.strip()
            for line in file.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    elif name:
        names = [name]
    else:
        error("Provide a distro name or --file")
        raise typer.Exit(1)

    # Resolve all names first
    to_install: list[tuple[str, str]] = []  # (entry_id, clean_name)
    for n in names:
        entry_id = resolve_distro(n, config_data)
        if not entry_id:
            error(f"Unknown distro: '{n}'")
            continue
        distro_config = config_data.get("distros", {}).get(entry_id, {})
        clean_name = distro_config.get("clean_name", entry_id)
        to_install.append((entry_id, clean_name))

    if not to_install:
        error("No valid distros to install.")
        raise typer.Exit(1)

    # Check staging space once
    import shutil as _shutil
    staging_dir = Path.home() / ".cache" / "visync" / "staging"
    try:
        usage = _shutil.disk_usage(staging_dir.parent)
        use_buffer = usage.free > 512 * 1024 * 1024
    except Exception:
        use_buffer = False

    if no_staging:
        use_buffer = False

    existing = find_installed_isos(ventoy_root)
    already_on_drive: list[str] = []
    to_download: list[str] = []

    for entry_id, clean_name in to_install:
        found = False
        for iso_path in existing:
            vid = get_iso_volume_id(iso_path)
            if vid:
                distro = identify_distro(vid, iso_path.name)
            else:
                distro = identify_distro("", iso_path.name)
            if distro.lower() == clean_name.lower():
                warn(f"{clean_name} is already on the drive: {iso_path.name}")
                mark_installed(ventoy_root, entry_id)
                already_on_drive.append(entry_id)
                found = True
                break
        if not found:
            to_download.append(entry_id)

    if not to_download:
        output_info("All distros already on drive.")
        return

    if dry_run:
        output_info(f"Would download {len(to_download)} distro(s):")
        for entry_id in to_download:
            distro_config = config_data.get("distros", {}).get(entry_id, {})
            console.print(f"    [cyan]→[/cyan] {distro_config.get('clean_name', entry_id)}")
        return

    output_info(f"Installing {len(to_download)} distro(s)...")
    sync_all_configured_distros(
        force=True,
        config_path=config,
        only=to_download,
        drive_override=ventoy_root,
        use_buffer=use_buffer,
        no_verify=no_verify,
    )

    # Mark installed if file is now on drive
    for entry_id in to_download:
        distro_config = config_data.get("distros", {}).get(entry_id, {})
        clean_name = distro_config.get("clean_name", entry_id)
        fresh = find_installed_isos(ventoy_root)
        for iso_path in fresh:
            vid = get_iso_volume_id(iso_path)
            if vid:
                distro = identify_distro(vid, iso_path.name)
            else:
                distro = identify_distro("", iso_path.name)
            if distro.lower() == clean_name.lower():
                version = extract_version_from_filename(iso_path.name) or ""
                mark_installed(ventoy_root, entry_id, version=version)
                success(f"{clean_name} installed")
                break
        else:
            warn(f"{clean_name} — file not found on drive after download")


@app.command()
def remove(
    name: str = typer.Argument(help="Distro name or keyword to remove"),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: Path | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Show what would be removed without deleting"
    ),
) -> None:
    """Remove a distro from the Ventoy drive."""
    from src.finder import remove_iso_metadata
    from src.pm import mark_removed, resolve_distro

    config_data = load_config(config)
    ventoy_root = _get_drive(drive)

    entry_id = resolve_distro(name, config_data)
    if not entry_id:
        error(f"Unknown distro: '{name}'")
        raise typer.Exit(1)

    distro_config = config_data.get("distros", {}).get(entry_id, {})
    clean_name = distro_config.get("clean_name", entry_id)

    # Find matching files on drive
    existing = find_installed_isos(ventoy_root)
    removed_count = 0
    for iso_path in existing:
        vid = get_iso_volume_id(iso_path)
        if vid:
            distro = identify_distro(vid, iso_path.name)
        else:
            distro = identify_distro("", iso_path.name)
        if distro.lower() == clean_name.lower():
            if dry_run:
                output_info(f"Would remove {iso_path.name}")
                removed_count += 1
            else:
                try:
                    iso_path.unlink(missing_ok=True)
                    remove_iso_metadata(ventoy_root, iso_path.name)
                    success(f"Removed {iso_path.name}")
                    removed_count += 1
                except OSError as e:
                    error(f"Could not remove {iso_path.name}: {e}")

    if removed_count == 0:
        warn(f"No files found for {clean_name} on the drive.")
    elif not dry_run:
        mark_removed(ventoy_root, entry_id)
        success(f"{clean_name} removed")


@app.command()
def update(
    name: str | None = typer.Argument(default=None, help="Distro to update (all if omitted)"),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: Path | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path"
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Force re-download"
    ),
    clean: bool = typer.Option(
        False, "--clean", help="Remove old versions"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Show what would be updated without downloading"
    ),
    no_verify: bool = typer.Option(
        False, "--no-verify", help="Skip checksum verification after download"
    ),
    no_staging: bool = typer.Option(
        False, "--no-staging", "--no-buffer", help="Download directly to the Ventoy drive (skip staging buffer)"
    ),
) -> None:
    """Update installed distros to latest versions."""
    from src.download import sync_all_configured_distros
    from src.pm import get_installed_ids, resolve_distro

    config_data = load_config(config)
    ventoy_root = _get_drive(drive)

    if name:
        entry_id = resolve_distro(name, config_data)
        if not entry_id:
            error(f"Unknown distro: '{name}'")
            raise typer.Exit(1)
        only = [entry_id]
    else:
        only = get_installed_ids(ventoy_root)
        if not only:
            output_info("No distros installed. Use 'visync install <name>' first.")
            return

    sync_all_configured_distros(
        dry_run=dry_run,
        force=force,
        clean=clean,
        config_path=config,
        only=only,
        drive_override=ventoy_root,
        no_verify=no_verify,
        use_buffer=not no_staging,
    )


@app.command()
def search(
    query: str | None = typer.Argument(default=None, help="Search query (lists all if omitted)"),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: Path | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path"
    ),
) -> None:
    """Search available distros."""
    from src.pm import get_installed_ids, resolve_distro

    config_data = load_config(config)
    distros = config_data.get("distros", {})

    if not distros:
        warn("No distros configured.")
        return

    ventoy_root = _get_drive(drive)
    installed = set(get_installed_ids(ventoy_root))

    if query:
        entry_id = resolve_distro(query, config_data)
        if entry_id:
            s = distros[entry_id]
            status = "installed" if entry_id in installed else "available"
            console.print(f"  {s.get('clean_name', entry_id)} ({entry_id}) [{status}]")
            console.print(f"    strategy: {s.get('strategy', '?')}")
            if s.get("base_url"):
                console.print(f"    url: {s['base_url']}")
        else:
            error(f"No match for '{query}'")
        return

    rows = []
    for entry_id, s in sorted(distros.items()):
        clean = s.get("clean_name", entry_id)
        strategy = s.get("strategy", "?")
        status = "+" if entry_id in installed else " "
        rows.append((status, clean, strategy))

    console.print()
    console.print("  [bold]Available distros:[/bold]")
    for status, name, strategy in rows:
        marker = f"[green]{status}[/green]" if status == "+" else f"[dim]{status}[/dim]"
        console.print(f"    {marker} {name} [dim]({strategy})[/dim]")
    console.print()
    console.print("  [dim]+ = installed[/dim]")


@app.command()
def info(
    name: str = typer.Argument(help="Distro name or keyword"),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: Path | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path"
    ),
) -> None:
    """Show details about a distro."""
    from src.pm import get_installed_ids, resolve_distro

    config_data = load_config(config)
    distros = config_data.get("distros", {})

    entry_id = resolve_distro(name, config_data)
    if not entry_id:
        error(f"Unknown distro: '{name}'")
        raise typer.Exit(1)

    s = distros[entry_id]
    ventoy_root = _get_drive(drive)
    installed = set(get_installed_ids(ventoy_root))

    console.print()
    console.print(f"  [bold]{s.get('clean_name', entry_id)}[/bold]")
    console.print(f"    entry_id:  {entry_id}")
    console.print(f"    strategy:  {s.get('strategy', '?')}")
    if s.get("base_url"):
        console.print(f"    base_url:  {s['base_url']}")
    if s.get("api_url"):
        console.print(f"    api_url:   {s['api_url']}")
    console.print(f"    checksums: {s.get('checksum_format', 'none')}")
    status = "[green]installed[/green]" if entry_id in installed else "[dim]available[/dim]"
    console.print(f"    status:    {status}")

    # Check if file exists on drive
    existing = find_installed_isos(ventoy_root)
    clean_name = s.get("clean_name", entry_id)
    for iso_path in existing:
        vid = get_iso_volume_id(iso_path)
        if vid:
            distro = identify_distro(vid, iso_path.name)
        else:
            distro = identify_distro("", iso_path.name)
        if distro.lower() == clean_name.lower():
            size_gb = iso_path.stat().st_size / (1024**3)
            console.print(f"    file:      {iso_path.name} ({size_gb:.1f}G)")
            break
    else:
        console.print("    file:      [dim]not on drive[/dim]")
    console.print()


@app.command()
def autodetect(
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: Path | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Show what would be detected without registering"
    ),
) -> None:
    """Auto-detect ISOs on the drive and mark them as installed."""
    from src.pm import mark_installed, resolve_distro

    config_data = load_config(config)
    ventoy_root = _get_drive(drive)
    distros = config_data.get("distros", {})

    existing = find_installed_isos(ventoy_root)
    found = 0
    for iso_path in existing:
        vid = get_iso_volume_id(iso_path)
        if vid:
            distro = identify_distro(vid, iso_path.name)
        else:
            distro = identify_distro("", iso_path.name)
        if distro in ("Unknown OS", ""):
            continue

        # Find matching config entry — prefer exact clean_name match, then keyword in filename
        entry_id = None
        file_lower = iso_path.name.lower()
        for eid, s in distros.items():
            clean = s.get("clean_name", "")
            if clean.lower() == distro.lower():
                entry_id = eid
                break
        if not entry_id:
            # Fallback: check if any config keyword appears in the filename
            for eid, s in distros.items():
                keyword = s.get("keyword", "")
                if keyword and keyword.lower() in file_lower:
                    entry_id = eid
                    break
        if not entry_id:
            continue

        # Check if already marked
        from src.pm import get_installed_ids
        installed = set(get_installed_ids(ventoy_root))
        if entry_id in installed:
            continue

        version = extract_version_from_filename(iso_path.name) or ""
        if dry_run:
            output_info(f"Would detect {distro}: {iso_path.name}")
            found += 1
        else:
            mark_installed(ventoy_root, entry_id, version=version)
            success(f"Detected {distro}: {iso_path.name}")
            found += 1

    if found == 0:
        output_info("No new distros detected (all already registered).")
    else:
        success(f"{'Would detect' if dry_run else 'Marked'} {found} distro(s) as installed.")


@app.command()
def list(
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: Path | None = typer.Option(
        None,
        "--drive",
        "-d",
        help="Directory to scan (defaults to detected Ventoy drive)",
    ),
) -> None:
    """List ISOs on the Ventoy drive with distro, version, and size."""
    from src.pm import get_installed_ids

    if drive is not None:
        iso_dir = drive
    else:
        drives = find_ventoy_drives()
        if not drives:
            error("No Ventoy drives detected.")
            raise typer.Exit(1)
        iso_dir = drives[0]

    if not iso_dir.is_dir():
        error(f"Not a directory: {iso_dir}")
        raise typer.Exit(1)

    iso_paths = find_installed_isos(iso_dir)
    if not iso_paths:
        warn("No ISO files found.")
        return

    all_meta = load_all_metadata(iso_dir)

    rows = []
    for iso_path in sorted(iso_paths, key=lambda p: p.name):
        meta = all_meta.get(iso_path.name)
        if meta:
            distro = identify_distro(meta.get("variant_stem", ""), iso_path.name)
            version = meta.get("version") or "—"
        else:
            vid = get_iso_volume_id(iso_path)
            distro = identify_distro(vid, iso_path.name)
            version = extract_version_from_filename(iso_path.name) or "—"
        size_gb = iso_path.stat().st_size / (1024**3)
        rows.append((distro, version, f"{size_gb:.1f}G", iso_path.name))

    total_gb_val = sum(
        iso_path.stat().st_size / (1024**3) for iso_path in iso_paths
    )
    iso_table(rows, total_gb_val)


@app.command()
def sync(
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: Path | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Show what would be done without doing it"
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Force re-download even if version matches"
    ),
    clean: bool = typer.Option(
        False, "--clean", help="Remove old versions of the same distro (dry-run by default)"
    ),
    all: bool = typer.Option(
        False, "--all", "-a", help="Sync all configured distros (not just installed)"
    ),
    no_verify: bool = typer.Option(
        False, "--no-verify", help="Skip checksum verification after download"
    ),
    no_staging: bool = typer.Option(
        False, "--no-staging", "--no-buffer", help="Download directly to the Ventoy drive (skip staging buffer)"
    ),
) -> None:
    """Sync installed distros to the Ventoy drive."""
    from src.download import sync_all_configured_distros
    from src.pm import get_installed_ids

    drive_root = _get_drive(drive)

    if all:
        only = None  # None = sync everything
    else:
        only = get_installed_ids(drive_root)
        if not only:
            output_info("No distros installed. Use 'visync install <name>' or 'visync sync --all'.")
            return

    sync_all_configured_distros(
        dry_run=dry_run,
        force=force,
        clean=clean,
        config_path=config,
        only=only,
        drive_override=drive_root,
        no_verify=no_verify,
        use_buffer=not no_staging,
    )


@app.command()
def verify(
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: Path | None = typer.Option(
        None,
        "--drive",
        "-d",
        help="Directory to scan (defaults to detected Ventoy drive)",
    ),
) -> None:
    """Verify integrity of ISOs on the Ventoy drive."""
    config_data = load_config(config)
    if drive is not None:
        iso_dir = drive
    else:
        drives = find_ventoy_drives()
        if not drives:
            error("No Ventoy drives detected.")
            raise typer.Exit(1)
        iso_dir = drives[0]

    if not iso_dir.is_dir():
        error(f"Not a directory: {iso_dir}")
        raise typer.Exit(1)

    output_info(f"Verifying ISOs in {iso_dir} ...")
    results = run_directory_verify(iso_dir, config_data)

    if not results:
        warn("No ISO files found.")
        return

    verified = failed = skipped = 0
    for iso_path, distro, result in results:
        label = f"{iso_path.name} ({distro})"
        if result is True:
            success(label)
            verified += 1
        elif result is False:
            error(f"{label} — checksum mismatch or fetch failed")
            failed += 1
        else:
            output_info(f"{label} — no checksum config")
            skipped += 1

    console.print()
    output_info(f"Done: {verified} verified, {failed} failed, {skipped} skipped (no config).")
    if failed:
        raise typer.Exit(1)


@app.command()
def nuke_metadata(
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: Path | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Show what would be deleted without deleting"
    ),
) -> None:
    """Delete all ISO metadata from .visync/metadata/.

    Keeps installed.json and other state. Metadata rebuilds on next sync.
    """
    import shutil

    ventoy_root = _get_drive(drive)
    metadata_dir = ventoy_root / ".visync" / "metadata"

    if not metadata_dir.is_dir():
        output_info("No metadata directory found.")
        return

    files = [f for f in metadata_dir.iterdir()]
    json_files = [f for f in files if f.is_file() and f.suffix == ".json"]
    total_size = sum(f.stat().st_size for f in json_files)

    if not json_files:
        output_info("Metadata directory is empty.")
        return

    if dry_run:
        output_info(f"Would delete {len(json_files)} metadata file(s) ({total_size / 1024:.1f} KiB):")
        for f in sorted(json_files):
            console.print(f"    [cyan]→[/cyan] {f.name}")
        return

    shutil.rmtree(metadata_dir)
    success(f"Deleted {len(json_files)} metadata file(s) ({total_size / 1024:.1f} KiB)")
    output_info("Metadata will rebuild on next sync.")


@app.command()
def version() -> None:
    """Show the version of Visync."""
    from . import __version__

    typer.echo(f"Visync version: {__version__}")


if __name__ == "__main__":
    app()
