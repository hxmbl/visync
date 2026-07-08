# Visync

Ventoy Package Manager. Install, update, and manage Linux distros on your Ventoy drive.

## Install

```bash
pip install -e .
```

Requires Python 3.11+ and a mounted Ventoy drive.

## Quick Start

```bash
# See what's available
visync search

# Auto-detect distros already on the drive
visync autodetect

# Install a distro
visync install archlinux
visync install nixos-graphical

# Batch install from file
visync install -i packages.txt

# Update all installed distros
visync update

# Update a specific distro
visync update tails

# Check for old versions (dry-run)
visync sync

# Remove old versions
visync sync --clean

# Remove a distro
visync remove tails

# Show distro details
visync info archlinux

# Verify checksums
visync verify
```

## Commands

| Command | Description |
|---|---|
| `visync search [query]` | List available distros (filter by query) |
| `visync install <name>` | Download and register a distro |
| `visync install -i <file>` | Batch install from file (one name per line) |
| `visync remove <name>` | Delete from drive and unregister |
| `visync update [name]` [--no-staging] | Update installed distros (all if no name given) |
| `visync sync` [--no-staging] | Sync installed distros to latest |
| `visync sync --all` [--no-staging] | Sync all configured distros |
| `visync sync --clean` [--no-staging] | Remove old versions of same distro |
| `visync list` | List ISOs on the drive |
| `visync autodetect` | Register existing ISOs as installed |
| `visync verify` | Verify checksums against upstream |
| `visync info <name>` | Show distro details |

## Batch Install File

Create a text file with one distro name per line:

```
# My Ventoy setup
archlinux
nixos-minimal
tails
ubuntu-desktop
ubuntu-server
```

Then run:

```bash
visync install -i packages.txt
```

Blank lines and lines starting with `#` are ignored.

## Configuration

Edit `config.toml` to add or remove distros. Each distro entry defines a scraping strategy, mirror URL, and checksum verification method.

**Built-in strategies:**

| Strategy | Description | Example |
|---|---|---|
| `direct_match` | Flat index page | Arch Linux, Omarchy |
| `fedora_nested` | Version dirs + variant subdirs | Fedora, Fedora KDE |
| `ubuntu_nested` | Version dirs | Ubuntu, Parrot Security |
| `nixos_channel` | Channel page + version parse | NixOS Minimal, NixOS Graphical |
| `popos_api` | JSON API | Pop!_OS |
| `tails_api` | JSON API | Tails |

**Checksum formats:** `gpg_checksum` (Fedora), `sha256sums` (Ubuntu, Arch, NixOS, Tails), `json` (Tails)

## How it works

1. **Detect** — finds mounted Ventoy drives on Windows, macOS, or Linux (with udisksctl automount)
2. **Scrape** — concurrent mirror scraping with TCP pre-flight checks and watchdog timeouts
3. **Compare** — version-aware comparison (semantic or date-based) against local ISOs
4. **Download** — streaming downloads with staging buffer (less drive wear), falls back to direct if staging full. Use `--no-staging` / `--no-buffer` to skip the staging buffer and download directly to the Ventoy drive.
5. **Verify** — optional checksum verification against published hashes
6. **Clean** — `--clean` removes deprecated ISOs of the same distro variant (dry-run by default)
7. **State** — tracks installed distros in `.visync/installed.json`

## Safety

- `--clean` is dry-run by default — shows what would be deleted, requires `--clean` flag to actually delete
- `.visync/` watchdog enforces a 1 GiB ceiling (deep clean orphaned metadata, then wipe)
- Guardrails prevent deletion of `.iso` or `.img` files under any circumstance
- Failed downloads clean up `.part` files automatically
- Install verifies file exists on drive before marking as installed

## Tests

```bash
python3 -m pytest test/ -v
```

## Debug

```bash
VISYNC_DEBUG=1 visync sync
```
