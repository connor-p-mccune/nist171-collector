"""Plan of Action and Milestones (POA&M) generation.

A POA&M is the to-do list that comes out of an assessment: one row per requirement that
is not met, saying what is wrong, where, what fixing it involves, who owns it and when it
is due. It is the document a contractor hands a contracting officer alongside the score,
and the one an assessor checks progress against later.

Two dates and one flag in here come from regulation rather than preference:

* ``scheduled_completion`` is the collection date plus 180 days -- the window the CMMC
  program rule (32 CFR 170.21) allows for closing out POA&M items after a conditional
  Level 2 status.
* ``conditional_poam_eligible`` records whether the same rule would even permit the item
  on a POA&M. It allows only 1-point requirements, with one narrow exception, and names
  six 1-point requirements that may never be deferred. Everything else has to be fixed
  before assessment, not scheduled for later. That distinction is the most useful thing
  a POA&M can tell its reader, so it is computed rather than left for them to work out.
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nist171.catalog import load_catalog

POAM_WINDOW_DAYS = 180

#: 32 CFR 170.21(a)(2)(iii): never permitted on a POA&M, regardless of point value.
POAM_NEVER_ELIGIBLE = frozenset({"3.1.20", "3.1.22", "3.12.4", "3.10.3", "3.10.4", "3.10.5"})

#: 32 CFR 170.21(a)(2)(ii): the one requirement worth more than 1 point that may be placed
#: on a POA&M, and only when encryption is used but is not FIPS-validated.
POAM_POINT_EXCEPTION = frozenset({"3.13.11"})

#: Column order for the CSV. Matches the key order of each item.
CSV_COLUMNS = (
    "poam_id",
    "control_id",
    "requirement",
    "nist_800_53_rev4",
    "weakness",
    "affected_resources",
    "points",
    "remediation",
    "scheduled_completion",
    "status",
    "point_of_contact",
    "conditional_poam_eligible",
    "eligibility_note",
    "source_checks",
)


class FindingsFileError(ValueError):
    """findings.json is missing something the POA&M needs."""


def load_findings(path: Path | str) -> dict[str, Any]:
    """Read an ``output/findings.json`` written by ``nist171 assess``."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"No findings file at {path}. Run 'nist171 assess' first.")
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if "score" not in data or "findings" not in data:
        raise FindingsFileError(
            f"{path} has no score block. It was written by an older version of the tool; "
            "re-run 'nist171 assess' to regenerate it."
        )
    return data


def _collection_date(data: dict[str, Any]) -> datetime:
    """When the evidence was gathered. The POA&M clock starts there, not at report time."""
    for key in ("collected_at", "assessed_at"):
        value = data.get(key)
        if value:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return datetime.now(UTC)


def conditional_eligibility(control_id: str, points: int) -> tuple[bool, str]:
    """Whether 32 CFR 170.21 would allow this item on a POA&M for conditional status."""
    if control_id in POAM_NEVER_ELIGIBLE:
        return False, (
            "Not eligible: 32 CFR 170.21 lists this requirement as one that can never be "
            "placed on a POA&M. It must be implemented before assessment."
        )
    if points > 1 and control_id not in POAM_POINT_EXCEPTION:
        return False, (
            f"Not eligible: worth {points} points, and 32 CFR 170.21 permits only 1-point "
            "requirements on a POA&M. It must be implemented before assessment."
        )
    return True, (
        f"Eligible: a 1-point requirement may remain on a POA&M for up to "
        f"{POAM_WINDOW_DAYS} days under conditional status."
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def build_poam(
    data: dict[str, Any],
    catalog: list[dict[str, Any]] | None = None,
    *,
    point_of_contact: str = "TBD",
) -> list[dict[str, Any]]:
    """One POA&M item per unmet requirement, in NIST order.

    Only requirements the score recorded as unmet appear. Requirements that were not
    assessed are deliberately absent: a POA&M lists known weaknesses, and an unassessed
    requirement is an unknown, not a weakness. They belong in the scope note instead.
    """
    catalog = catalog if catalog is not None else load_catalog()
    controls = {c["id"]: c for c in catalog}
    due = (_collection_date(data) + timedelta(days=POAM_WINDOW_DAYS)).date().isoformat()

    failing: dict[str, list[dict[str, Any]]] = {}
    for found in data.get("findings", []):
        if found.get("verdict") == "FAIL":
            failing.setdefault(found["control_id"], []).append(found)

    items: list[dict[str, Any]] = []
    for index, unmet in enumerate(data["score"].get("unmet", []), start=1):
        control_id = unmet["control_id"]
        points = int(unmet["points"])
        control = controls.get(control_id, {})
        fails = failing.get(control_id, [])
        eligible, note = conditional_eligibility(control_id, points)

        items.append(
            {
                "poam_id": f"POAM-{index:03d}",
                "control_id": control_id,
                "requirement": control.get("title", ""),
                "nist_800_53_rev4": list(control.get("nist_800_53_rev4", [])),
                "weakness": " ".join(_dedupe([f.get("summary", "") for f in fails])),
                "affected_resources": _dedupe(
                    [r for f in fails for r in f.get("affected_resources", [])]
                ),
                "points": points,
                "remediation": " ".join(_dedupe([f.get("remediation", "") for f in fails])),
                "scheduled_completion": due,
                "status": "Open",
                "point_of_contact": point_of_contact,
                "conditional_poam_eligible": eligible,
                "eligibility_note": note,
                "source_checks": _dedupe([f.get("check_name", "") for f in fails]),
            }
        )
    return items


def write_poam_json(
    path: Path | str, items: list[dict[str, Any]], data: dict[str, Any]
) -> Path:
    """Write the POA&M as JSON, with enough context to stand on its own."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "document": "Plan of Action and Milestones",
        "standard": "NIST SP 800-171 Rev 2",
        "generated_at": datetime.now(UTC).isoformat(),
        "account_id": data.get("account_id"),
        "collected_at": data.get("collected_at"),
        "score": data["score"].get("score"),
        "scope_note": data["score"].get("scope_note"),
        "poam_window_days": POAM_WINDOW_DAYS,
        "item_count": len(items),
        "items": items,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_poam_csv(path: Path | str, items: list[dict[str, Any]]) -> Path:
    """Write the POA&M as CSV.

    Encoded as UTF-8 with a byte-order mark, which is what makes Excel on Windows open it
    with the right encoding instead of mangling any non-ASCII character. List fields are
    flattened with semicolons so each item stays on one row.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for item in items:
            row = dict(item)
            for key in ("nist_800_53_rev4", "affected_resources", "source_checks"):
                row[key] = "; ".join(item.get(key, []))
            row["conditional_poam_eligible"] = "Yes" if item["conditional_poam_eligible"] else "No"
            writer.writerow({col: row.get(col, "") for col in CSV_COLUMNS})
    return path
