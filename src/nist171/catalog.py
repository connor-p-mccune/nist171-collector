"""Load the NIST SP 800-171 Rev 2 control catalog and assessment objectives.

The catalog lives in YAML data files rather than in Python so the rules can be read,
reviewed and corrected by someone who does not read code -- and so a change to a point
value is a one-line data edit, not a code change.

    catalog/controls.yaml     all 110 requirements, with DoD point values for the 42 in scope
    catalog/objectives.yaml   SP 800-171A assessment objectives for those 42
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# src/nist171/catalog.py -> parents[0]=nist171, [1]=src, [2]=project root
_DEFAULT_CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"


def catalog_dir() -> Path:
    """Directory holding the catalog YAML files.

    Override with the NIST171_CATALOG_DIR environment variable, which is what the tests
    use to point at a fixture catalog.
    """
    override = os.environ.get("NIST171_CATALOG_DIR")
    return Path(override) if override else _DEFAULT_CATALOG_DIR


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(
            f"Catalog file not found: {path}. Expected it under {catalog_dir()}; "
            "set NIST171_CATALOG_DIR to override."
        )
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path} should parse to a mapping, got {type(data).__name__}")
    return data


def load_catalog() -> list[dict[str, Any]]:
    """Return all 110 requirements as a list of dicts, in NIST order.

    Each dict has: id, family, family_name, title, points, in_scope, nist_800_53_rev4.
    Requirements in the AC, AU and IA families additionally have integer points; the
    other 68 have points of None. Five requirements carry na_if_not_permitted, and
    3.5.3 carries partial_credit.
    """
    data = _load_yaml(catalog_dir() / "controls.yaml")
    controls = data.get("controls")
    if not isinstance(controls, list):
        raise ValueError("controls.yaml must contain a top-level 'controls' list")
    return controls


def load_objectives() -> list[dict[str, Any]]:
    """Return the SP 800-171A assessment objectives for the in-scope requirements.

    Each dict has: id (e.g. "3.1.1[a]"), control_id (e.g. "3.1.1"), and text. Three
    requirements -- 3.5.4, 3.5.9 and 3.5.11 -- have a single unlettered objective in
    800-171A and so use the bare requirement id.
    """
    data = _load_yaml(catalog_dir() / "objectives.yaml")
    objectives = data.get("objectives")
    if not isinstance(objectives, list):
        raise ValueError("objectives.yaml must contain a top-level 'objectives' list")
    return objectives


def objectives_for(control_id: str) -> list[dict[str, Any]]:
    """Return the assessment objectives belonging to one requirement."""
    return [o for o in load_objectives() if o["control_id"] == control_id]
