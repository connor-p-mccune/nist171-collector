"""Reading a saved evidence folder back into Evidence objects.

This is the seam between collection and assessment. Everything downstream of here works
from files on disk, never from a live AWS connection.

Loading re-computes each item's SHA-256 and compares it to the value stored alongside it.
Evidence that does not match what it claims to be is not evidence, so a mismatch is an
error rather than a warning.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from nist171.models import Evidence

MANIFEST_NAME = "manifest.json"


class EvidenceIntegrityError(Exception):
    """Stored evidence does not match its recorded hash."""


def latest_evidence_dir(root: Path | str = "evidence") -> Path:
    """Most recent run folder under ``root``.

    Folder names are UTC timestamps in a format that sorts chronologically as text, so
    the newest is simply the last one alphabetically.
    """
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"No evidence directory at {root}. Run 'nist171 collect' first.")
    runs = sorted(p for p in root.iterdir() if p.is_dir())
    if not runs:
        raise FileNotFoundError(f"No evidence runs inside {root}. Run 'nist171 collect' first.")
    return runs[-1]


def load_manifest(folder: Path | str) -> dict[str, Any]:
    """Read the run manifest. Returns an empty dict if the run predates manifests."""
    path = Path(folder) / MANIFEST_NAME
    if not path.is_file():
        return {}
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def load_evidence(folder: Path | str, *, verify: bool = True) -> dict[str, dict[str, Evidence]]:
    """Load one evidence run.

    Args:
        folder: An ``evidence/<timestamp>/`` directory.
        verify: Re-hash each item and compare against the stored hash. Leave this on
            unless you are deliberately inspecting evidence known to be altered.

    Returns:
        ``{collector_name: {key: Evidence}}`` -- the same shape the collectors produced,
        so a check cannot tell whether it is reading live or saved evidence.
    """
    folder = Path(folder)
    if not folder.is_dir():
        raise FileNotFoundError(f"Evidence folder not found: {folder}")

    evidence: dict[str, dict[str, Evidence]] = {}
    for path in sorted(folder.glob("*.json")):
        if path.name == MANIFEST_NAME:
            continue
        evidence[path.stem] = _load_collector_file(path, verify=verify)

    if not evidence:
        raise FileNotFoundError(f"No evidence files in {folder}")
    return evidence


def _load_collector_file(path: Path, *, verify: bool) -> dict[str, Evidence]:
    entries = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError(f"{path} should contain a JSON list, got {type(entries).__name__}")

    items: dict[str, Evidence] = {}
    for entry in entries:
        key = entry["key"]
        item = Evidence(
            source=entry["source"],
            collected_at=datetime.fromisoformat(entry["collected_at"]),
            collector_version=entry["collector_version"],
            raw=entry["raw"],
        )
        stored = entry.get("sha256")
        if verify and stored and item.sha256 != stored:
            raise EvidenceIntegrityError(
                f"{path.name}:{key} hash mismatch. Stored {stored}, recomputed {item.sha256}. "
                "The evidence file has been modified since collection."
            )
        items[key] = item
    return items


def verify_manifest(folder: Path | str) -> list[str]:
    """Re-hash every file and compare against the manifest.

    Returns a list of problems, empty when the evidence set is intact. This checks the
    set -- missing or added files -- where :func:`load_evidence` checks contents.
    """
    import hashlib

    folder = Path(folder)
    manifest = load_manifest(folder)
    if not manifest:
        return [f"No {MANIFEST_NAME} in {folder}"]

    problems: list[str] = []
    listed = set()
    for record in manifest.get("files", []):
        name = record["name"]
        listed.add(name)
        path = folder / name
        if not path.is_file():
            problems.append(f"{name}: listed in manifest but missing from the folder")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != record["sha256"]:
            problems.append(f"{name}: file hash does not match the manifest")

    for path in folder.glob("*.json"):
        if path.name != MANIFEST_NAME and path.name not in listed:
            problems.append(f"{path.name}: present in the folder but not listed in the manifest")

    return problems
