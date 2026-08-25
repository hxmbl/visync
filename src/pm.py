"""Package manager state and operations for visync.

Tracks which distros are "installed" (wanted) on the Ventoy drive.
State file: .visync/installed.json
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from src.output import warn


def _state_path(drive_root: Path) -> Path:
    """Path to the installed.json state file."""
    return drive_root / ".visync" / "installed.json"


def load_installed(drive_root: Path) -> dict:
    """Load the installed distros state. Returns {entry_id: {installed_at, version}}.

    Corrupt or non-object JSON is treated as empty state (with a warning)
    rather than crashing every subsequent command.
    """
    path = _state_path(drive_root)
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        warn(f"installed.json has unexpected shape ({type(data).__name__}) — ignoring")
        return {}
    return data


def save_installed(drive_root: Path, installed: dict) -> None:
    """Save the installed distros state atomically (tmp file + rename)."""
    path = _state_path(drive_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".json.tmp")
    with open(tmp_path, "w") as f:
        json.dump(installed, f, indent=2)
    os.replace(tmp_path, path)


def mark_installed(drive_root: Path, entry_id: str, version: str = "") -> None:
    """Mark a distro as installed."""
    installed = load_installed(drive_root)
    installed[entry_id] = {
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "version": version,
    }
    save_installed(drive_root, installed)


def mark_removed(drive_root: Path, entry_id: str) -> None:
    """Mark a distro as removed."""
    installed = load_installed(drive_root)
    installed.pop(entry_id, None)
    save_installed(drive_root, installed)


def get_installed_ids(drive_root: Path) -> list[str]:
    """Return list of installed distro entry IDs."""
    return list(load_installed(drive_root).keys())


def matching_distros(query: str, config: dict) -> tuple[str | None, list[str]]:
    """Match a user query to distro entry_ids.

    Returns (exact_entry_id, partial_candidates). *exact_entry_id* is set for
    an unambiguous exact match on entry_id, clean_name, or keyword.
    *partial_candidates* lists every entry_id whose entry_id or clean_name
    contains the query as a substring (possibly empty).
    """
    query_lower = query.lower().strip()
    if not query_lower:
        return None, []
    distros = config.get("distros", {})

    for key in distros:
        if key.lower() == query_lower:
            return key, []

    for entry_id, settings in distros.items():
        if settings.get("clean_name", "").lower() == query_lower:
            return entry_id, []

    keyword_hits = [
        entry_id for entry_id, settings in distros.items()
        if settings.get("keyword", "").lower() == query_lower
    ]
    if len(keyword_hits) == 1:
        return keyword_hits[0], []

    partials = [
        entry_id for entry_id, settings in distros.items()
        if query_lower in settings.get("clean_name", "").lower()
        or query_lower in entry_id.lower()
    ]
    return None, partials


def resolve_distro(query: str, config: dict) -> str | None:
    """Resolve a user query (name, keyword, partial match) to a distro entry_id.

    Exact matches always win. Partial substring matches only resolve when
    they are unique; ambiguous queries return None so callers can refuse
    rather than act on an arbitrary pick.
    """
    exact, partials = matching_distros(query, config)
    if exact:
        return exact
    if len(partials) == 1:
        return partials[0]
    return None
