"""Visync - Ventoy Package Manager.

Built with typer. Run `visync --help` for available commands.
"""

from pathlib import Path

import typer
from rich.markup import escape as _esc

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


def _parse_drives(raw: str | None) -> list[Path] | None:
    """Parse comma-separated drive paths from CLI option."""
    if not raw:
        return None
    return [Path(p.strip()) for p in raw.split(",") if p.strip()]


def _get_drives(drives: list[Path] | None = None) -> list[Path]:
    """Resolve Ventoy drive paths.

    If *drives* is provided, validate and return them.
    If exactly one drive is detected, return it.
    If multiple drives are detected, prompt the user to select one or more.
    """
    if drives is not None:
        validated = []
        for d in drives:
            if not d.is_dir():
                error(f"Not a directory: {d}")
                raise typer.Exit(1)
            if not (d / ".visync").is_dir():
                marker = d / "ventoy"
                if not marker.is_dir():
                    warn(f"{d} does not look like a Ventoy/Visync-managed drive")
            validated.append(d)
        return validated

    detected = find_ventoy_drives()
    if not detected:
        error("No Ventoy drives detected.")
        raise typer.Exit(1)

    if len(detected) == 1:
        return detected

    # Multiple drives — prompt user to select
    console.print()
    console.print("  [bold]Multiple Ventoy drives detected:[/bold]")
    for i, d in enumerate(detected, 1):
        console.print(f"    [cyan]{i}[/cyan]) {_esc(str(d))}")
    console.print("  [dim]Enter numbers separated by commas (e.g. 1,3)[/dim]")
    console.print()

    while True:
        try:
            raw = typer.prompt("Select drive(s)")
        except (typer.Abort, EOFError):
            raise typer.Exit(1)
        try:
            indices = [int(x.strip()) for x in raw.split(",") if x.strip()]
            if not indices:
                raise ValueError("empty")
            selected = []
            for idx in indices:
                if 1 <= idx <= len(detected):
                    selected.append(detected[idx - 1])
                else:
                    raise ValueError(f"invalid index {idx}")
            return selected
        except ValueError as e:
            error(f"Invalid input: {e}. Enter numbers 1-{len(detected)} separated by commas.")


@app.command()
def install(
    name: str | None = typer.Argument(default=None, help="Distro name or keyword to install"),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: str | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path(s), comma-separated for multiple"
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
    target_drives = _get_drives(_parse_drives(drive))

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

    # Prefer the staging buffer whenever it is usable; per-download disk space
    # checks during the actual download remain the authoritative guard.
    staging_dir = Path.home() / ".cache" / "visync" / "staging"
    try:
        staging_dir.mkdir(parents=True, exist_ok=True)
        use_buffer = True
    except OSError as e:
        warn(f"Staging buffer unavailable: {e} — downloading directly to drive")
        use_buffer = False

    if no_staging:
        use_buffer = False

    for ventoy_root in target_drives:
        if len(target_drives) > 1:
            console.print()
            header(f"Drive: {ventoy_root}")

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
            continue

        if dry_run:
            output_info(f"Would download {len(to_download)} distro(s):")
            for entry_id in to_download:
                distro_config = config_data.get("distros", {}).get(entry_id, {})
                console.print(f"    [cyan]→[/cyan] {_esc(str(distro_config.get('clean_name', entry_id)))}")
            continue

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
    drive: str | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path(s), comma-separated for multiple"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Show what would be removed without deleting"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation prompt"
    ),
) -> None:
    """Remove a distro from the Ventoy drive."""
    from src.finder import remove_iso_metadata
    from src.pm import mark_removed, matching_distros, resolve_distro

    config_data = load_config(config)
    target_drives = _get_drives(_parse_drives(drive))

    entry_id = resolve_distro(name, config_data)
    if not entry_id:
        _, partials = matching_distros(name, config_data)
        if partials:
            candidate_names = ", ".join(sorted(
                config_data.get("distros", {}).get(p, {}).get("clean_name", p)
                for p in partials
            ))
            error(f"Ambiguous distro '{name}' — matches: {candidate_names}. Be specific.")
        else:
            error(f"Unknown distro: '{name}'")
        raise typer.Exit(1)

    distro_config = config_data.get("distros", {}).get(entry_id, {})
    clean_name = distro_config.get("clean_name", entry_id)

    for ventoy_root in target_drives:
        if len(target_drives) > 1:
            console.print()
            header(f"Drive: {ventoy_root}")

        # Find matching files on drive before touching anything
        existing = find_installed_isos(ventoy_root)
        matches = []
        for iso_path in existing:
            vid = get_iso_volume_id(iso_path)
            if vid:
                distro = identify_distro(vid, iso_path.name)
            else:
                distro = identify_distro("", iso_path.name)
            if distro.lower() == clean_name.lower():
                matches.append(iso_path)

        if not matches:
            warn(f"No files found for {clean_name} on the drive.")
            continue

        if dry_run:
            for iso_path in matches:
                output_info(f"Would remove {iso_path.name}")
            continue

        if not yes:
            console.print(f"  About to delete {len(matches)} file(s) from {_esc(str(ventoy_root))}:")
            for iso_path in matches:
                console.print(f"    [red]×[/red] {_esc(iso_path.name)}")
            try:
                confirmed = typer.confirm("Delete these file(s)?")
            except typer.Abort:
                error("Aborted — nothing deleted.")
                raise typer.Exit(1)
            if not confirmed:
                output_info("Aborted — nothing deleted.")
                continue

        removed_count = 0
        for iso_path in matches:
            try:
                iso_path.unlink(missing_ok=True)
                remove_iso_metadata(ventoy_root, iso_path.name)
                success(f"Removed {iso_path.name}")
                removed_count += 1
            except OSError as e:
                error(f"Could not remove {iso_path.name}: {e}")

        if removed_count:
            mark_removed(ventoy_root, entry_id)
            success(f"{clean_name} removed")


@app.command()
def update(
    name: str | None = typer.Argument(default=None, help="Distro to update (all if omitted)"),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: str | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path(s), comma-separated for multiple"
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
    from src.pm import get_installed_ids, mark_installed as _mark_installed, resolve_distro
    from src.verify import extract_version_from_filename as _extract_ver

    config_data = load_config(config)
    target_drives = _get_drives(_parse_drives(drive))

    for ventoy_root in target_drives:
        if len(target_drives) > 1:
            console.print()
            header(f"Drive: {ventoy_root}")

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
                continue

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

        if not dry_run:
            existing = find_installed_isos(ventoy_root)
            for eid in only:
                distro_config = config_data.get("distros", {}).get(eid, {})
                clean_name = distro_config.get("clean_name", eid)
                for iso_path in existing:
                    vid = get_iso_volume_id(iso_path)
                    distro = identify_distro(vid, iso_path.name) if vid else identify_distro("", iso_path.name)
                    if distro.lower() == clean_name.lower():
                        version = _extract_ver(iso_path.name) or ""
                        _mark_installed(ventoy_root, eid, version=version)
                        break


@app.command()
def search(
    query: str | None = typer.Argument(default=None, help="Search query (lists all if omitted)"),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: str | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path(s), comma-separated for multiple"
    ),
) -> None:
    """Search available distros."""
    from src.pm import get_installed_ids, resolve_distro

    config_data = load_config(config)
    distros = config_data.get("distros", {})

    if not distros:
        warn("No distros configured.")
        return

    target_drives = _get_drives(_parse_drives(drive))

    # Collect installed status across all drives
    installed_by_drive: dict[Path, set[str]] = {}
    for vr in target_drives:
        installed_by_drive[vr] = set(get_installed_ids(vr))

    if query:
        entry_id = resolve_distro(query, config_data)
        if entry_id:
            s = distros[entry_id]
            console.print()
            console.print(f"  [bold]{_esc(str(s.get('clean_name', entry_id)))}[/bold] [dim]({_esc(entry_id)})[/dim]")
            console.print(f"    strategy: {s.get('strategy', '?')}")
            if s.get("base_url"):
                console.print(f"    url: {_esc(str(s['base_url']))}")
            for vr in target_drives:
                status = "installed" if entry_id in installed_by_drive[vr] else "available"
                marker = "[green]installed[/green]" if status == "installed" else "[dim]available[/dim]"
                console.print(f"    {_esc(str(vr))}: {marker}")
        else:
            error(f"No match for '{query}'")
        return

    rows = []
    for entry_id, s in sorted(distros.items()):
        clean = s.get("clean_name", entry_id)
        strategy = s.get("strategy", "?")
        # Show which drives have it installed
        drive_status = []
        for vr in target_drives:
            if entry_id in installed_by_drive[vr]:
                drive_status.append("+")
            else:
                drive_status.append(" ")
        rows.append((drive_status, clean, strategy))

    console.print()
    console.print("  [bold]Available distros:[/bold]")
    if len(target_drives) > 1:
        # Show drive headers
        drive_labels = [f"D{i+1}" for i in range(len(target_drives))]
        console.print(f"    {'':3} {'Name':<25} {'Strategy':<20} {' '.join(drive_labels)}")
        console.print(f"    {'':3} {'-'*25} {'-'*20} {' '.join(['--' for _ in target_drives])}")
        for drive_status, name, strategy in rows:
            markers = " ".join(f"[green]{s}[/green]" if s == "+" else f"[dim]{s}[/dim]" for s in drive_status)
            console.print(f"    {'':3} {_esc(name):<25} {_esc(strategy):<20} {markers}")
    else:
        for drive_status, name, strategy in rows:
            marker = f"[green]{drive_status[0]}[/green]" if drive_status[0] == "+" else f"[dim]{drive_status[0]}[/dim]"
            console.print(f"    {marker} {_esc(name)} [dim]({_esc(strategy)})[/dim]")
    console.print()
    console.print("  [dim]+ = installed[/dim]")


@app.command()
def info(
    name: str = typer.Argument(help="Distro name or keyword"),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: str | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path(s), comma-separated for multiple"
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
    target_drives = _get_drives(_parse_drives(drive))

    console.print()
    console.print(f"  [bold]{_esc(str(s.get('clean_name', entry_id)))}[/bold]")
    console.print(f"    entry_id:  {_esc(entry_id)}")
    console.print(f"    strategy:  {s.get('strategy', '?')}")
    if s.get("base_url"):
        console.print(f"    base_url:  {_esc(str(s['base_url']))}")
    if s.get("api_url"):
        console.print(f"    api_url:   {_esc(str(s['api_url']))}")
    console.print(f"    checksums: {s.get('checksum_format', 'none')}")

    clean_name = s.get("clean_name", entry_id)
    for vr in target_drives:
        installed = set(get_installed_ids(vr))
        status = "[green]installed[/green]" if entry_id in installed else "[dim]available[/dim]"

        existing = find_installed_isos(vr)
        file_info = "[dim]not on drive[/dim]"
        for iso_path in existing:
            vid = get_iso_volume_id(iso_path)
            if vid:
                distro = identify_distro(vid, iso_path.name)
            else:
                distro = identify_distro("", iso_path.name)
            if distro.lower() == clean_name.lower():
                size_gb = iso_path.stat().st_size / (1024**3)
                file_info = f"{iso_path.name} ({size_gb:.1f}G)"
                break

        if len(target_drives) > 1:
            console.print(f"    [bold]{vr}[/bold]")
        console.print(f"    status:    {status}")
        console.print(f"    file:      {_esc(file_info)}")
    console.print()


@app.command()
def autodetect(
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: str | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path(s), comma-separated for multiple"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Show what would be detected without registering"
    ),
) -> None:
    """Auto-detect ISOs on the drive and mark them as installed."""
    from src.pm import mark_installed

    config_data = load_config(config)
    target_drives = _get_drives(_parse_drives(drive))
    distros = config_data.get("distros", {})

    for ventoy_root in target_drives:
        if len(target_drives) > 1:
            console.print()
            header(f"Drive: {ventoy_root}")

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
                from src.finder import keyword_hit
                for eid, s in distros.items():
                    keyword = s.get("keyword", "")
                    if keyword and keyword_hit(keyword, file_lower):
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
    drive: str | None = typer.Option(
        None,
        "--drive",
        "-d",
        help="Ventoy drive path(s), comma-separated for multiple",
    ),
) -> None:
    """List ISOs on the Ventoy drive with distro, version, and size."""
    target_drives = _get_drives(_parse_drives(drive))

    for iso_dir in target_drives:
        if len(target_drives) > 1:
            console.print()
            header(f"Drive: {iso_dir}")

        iso_paths = find_installed_isos(iso_dir)
        if not iso_paths:
            warn("No ISO files found.")
            continue

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
    drive: str | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path(s), comma-separated for multiple"
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

    target_drives = _get_drives(_parse_drives(drive))

    for drive_root in target_drives:
        if len(target_drives) > 1:
            console.print()
            header(f"Drive: {drive_root}")

        if all:
            only = None  # None = sync everything
        else:
            only = get_installed_ids(drive_root)
            if not only:
                output_info("No distros installed. Use 'visync install <name>' or 'visync sync --all'.")
                continue

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
    drive: str | None = typer.Option(
        None,
        "--drive",
        "-d",
        help="Ventoy drive path(s), comma-separated for multiple",
    ),
) -> None:
    """Verify integrity of ISOs on the Ventoy drive."""
    from src.verify import UNAVAILABLE

    config_data = load_config(config)
    target_drives = _get_drives(_parse_drives(drive))

    verified = failed = skipped = unavailable = 0
    any_results = False

    for iso_dir in target_drives:
        if len(target_drives) > 1:
            console.print()
            header(f"Drive: {iso_dir}")

        output_info(f"Verifying ISOs in {iso_dir} ...")
        results = run_directory_verify(iso_dir, config_data)

        if not results:
            warn("No ISO files found.")
            continue

        any_results = True
        for iso_path, distro, result in results:
            label = f"{iso_path.name} ({distro})"
            if result is True:
                success(label)
                verified += 1
            elif result is False:
                error(f"{label} — checksum mismatch")
                failed += 1
            elif result == UNAVAILABLE:
                error(f"{label} — checksum could not be obtained (not verified)")
                unavailable += 1
            else:
                output_info(f"{label} — no checksum config")
                skipped += 1

    if not any_results and len(target_drives) == 1:
        return

    console.print()
    summary = f"Done: {verified} verified, {failed} failed"
    if unavailable:
        summary += f", {unavailable} unverified (source unreachable)"
    summary += f", {skipped} skipped (no config)."
    output_info(summary)
    if failed or unavailable:
        raise typer.Exit(1)


@app.command("nuke-metadata")
def nuke_metadata(
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    drive: str | None = typer.Option(
        None, "--drive", "-d", help="Ventoy drive path(s), comma-separated for multiple"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Show what would be deleted without deleting"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation prompt"
    ),
) -> None:
    """Delete all ISO metadata from .visync/metadata/.

    Keeps installed.json and other state. Metadata rebuilds on next sync.
    Only .json metadata files are eligible for deletion.
    """
    from src.finder import _guard_json_only

    target_drives = _get_drives(_parse_drives(drive))

    for ventoy_root in target_drives:
        if len(target_drives) > 1:
            console.print()
            header(f"Drive: {ventoy_root}")

        metadata_dir = ventoy_root / ".visync" / "metadata"

        if not metadata_dir.is_dir():
            output_info("No metadata directory found.")
            continue

        json_files = []
        skipped = []
        for f in sorted(metadata_dir.iterdir()):
            if f.is_file() and f.suffix == ".json":
                json_files.append(f)
            elif f.name != "." and f.is_file():
                skipped.append(f)
        total_size = sum(f.stat().st_size for f in json_files)

        if not json_files:
            output_info("Metadata directory is empty.")
            continue

        if dry_run:
            output_info(f"Would delete {len(json_files)} metadata file(s) ({total_size / 1024:.1f} KiB):")
            for f in json_files:
                console.print(f"    [cyan]→[/cyan] {_esc(f.name)}")
            continue

        if not yes:
            console.print(f"  About to delete {len(json_files)} metadata file(s) from {_esc(str(ventoy_root))}:")
            for f in json_files:
                console.print(f"    [red]×[/red] {_esc(f.name)}")
            try:
                confirmed = typer.confirm("Delete these file(s)?")
            except typer.Abort:
                error("Aborted — nothing deleted.")
                raise typer.Exit(1)
            if not confirmed:
                output_info("Aborted — nothing deleted.")
                continue

        deleted = 0
        for f in json_files:
            try:
                _guard_json_only(f)
                f.unlink()
                deleted += 1
            except ValueError as e:
                warn(str(e))
            except OSError as e:
                warn(f"Could not remove {f.name}: {e}")
        success(f"Deleted {deleted} metadata file(s) ({total_size / 1024:.1f} KiB)")

        for f in skipped:
            warn(f"Not metadata — left in place: {f.name}")
        try:
            metadata_dir.rmdir()
        except OSError:
            pass
        output_info("Metadata will rebuild on next sync.")


@app.command()
def version() -> None:
    """Show the version of Visync."""
    from . import __version__

    typer.echo(f"Visync version: {__version__}")


if __name__ == "__main__":
    app()
