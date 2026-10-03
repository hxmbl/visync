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
| `visync sync --reset-visync` | Allow the watchdog to wipe an over-budget `.visync/` |
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

Config resolution order: explicit `--config` path, then `$VISYNC_CONFIG`, then `~/.config/visync/config.toml`, then the packaged `config.toml`. A `config.toml` in the current directory is only used as a last resort, so planted configs cannot hijack identification.

**Release selection:** `version_filter` restricts a scraper to one release family before the newest match is chosen. Ubuntu entries use `\d*[02468]\.04(\.\d+)*` so they track the current LTS (26.04.1) and ignore interim releases (25.10, 26.10). NixOS resolves the newest stable `YY.MM` channel from the release bucket at scrape time, so it advances to the next stable without a config edit; set `channel = "26.05"` to pin deliberately while that channel is current.

**Built-in strategies:**

| Strategy | Description | Example |
|---|---|---|
| `direct_match` | Flat index page | Arch Linux |
| `fedora_nested` | Version dirs + variant subdirs | Fedora, Fedora KDE |
| `ubuntu_nested` | Version dirs | Ubuntu, Parrot Security |
| `nixos_channel` | Stable-channel lookup + channel page parse | NixOS Minimal, NixOS Graphical |
| `popos_api` | JSON API | Pop!_OS |
| `tails_api` | JSON API | Tails |

**Checksum formats:** `gpg_checksum` (Fedora — inline `SHA256 (file) = hash`), `sha256sums` (Ubuntu, Arch, Parrot, NixOS, Tails), `json` (Tails)

Signature checking is configured separately via `signing_key_url` + `signing_key_fingerprint` and works with any signed layout, so Parrot's sectioned hash list gets both a signature check and a digest check.

## How it works

1. **Detect** — finds mounted Ventoy drives on Windows, macOS, or Linux (with udisksctl automount)
2. **Scrape** — concurrent mirror scraping with TCP pre-flight checks and watchdog timeouts. A distro whose mirror can't be read is reported with the reason and makes the command exit non-zero; it is never silently counted as up to date
3. **Select** — release-family filters keep scrapers on the intended series: Ubuntu tracks the current **LTS** (even-year `.04`, skipping interim releases and beta-only directories), and NixOS resolves the current **stable** channel from the release bucket instead of pinning a version string
4. **Compare** — version-aware comparison (semantic or date-based) against local ISOs
5. **Download** — streaming downloads with staging buffer (less drive wear), falls back to direct if staging full. Use `--no-staging` / `--no-buffer` to skip the staging buffer and download directly to the Ventoy drive.
6. **Verify** — optional checksum verification against published hashes
7. **Clean** — `--clean` removes deprecated ISOs of the same distro variant (dry-run by default)
8. **State** — tracks installed distros in `.visync/installed.json`

## Safety

- `--clean` is dry-run by default, and `--dry-run` never modifies the drive — `sync --clean --dry-run` deletes nothing and does not touch `.visync/`
- `remove` and `nuke-metadata` show exactly what will be deleted and ask for confirmation (`--yes` skips)
- Ambiguous distro queries are refused with candidate lists instead of acting on an arbitrary match
- Distro matching uses whole-token keywords (`pop` does not match `popcorn.iso`)
- `.visync/` watchdog enforces a 1 GiB ceiling by deep-cleaning orphaned metadata. Wiping `.visync/` entirely is **opt-in** via `sync --reset-visync`, because it destroys `installed.json` and every registration
- The watchdog never runs on `--dry-run`
- Guardrails prevent deletion of `.iso` or `.img` files under any circumstance — including inside `.visync/metadata`
- Downloads use parallel range requests with per-chunk HTTP 206 and byte-count validation; truncated or range-ignoring servers fail loudly instead of producing silent corruption
- Checksum mismatch deletes the download; an *unreachable* checksum source keeps the file and warns (`UNVERIFIED`)
- HTTPS is enforced for all mirrors and checksum sources (loopback exempt); https→http redirects are blocked
- GPG signature verification supports fingerprint pinning via `signing_key_fingerprint`, and applies to any signed checksum file regardless of its digest layout (Fedora's inline `SHA256 (file) = hash`, Parrot's sectioned md5/sha256/sha512 list)
- When multiple digests for the same file appear in one signed list, the configured `checksum_algo` selects the section — a first-match parser would compare an MD5 against a SHA-256 and delete a good download as corrupt
- Failed downloads clean up `.part` files automatically
- Install verifies file exists on drive before marking as installed
- State and metadata writes are atomic (tmp file + rename)

## Tests

```bash
python3 -m pytest test/ -v
```

## Debug

```bash
VISYNC_DEBUG=1 visync sync
```
