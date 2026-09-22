"""Helpers shared by every check module.

A check reads saved evidence and returns exactly one :class:`~nist171.models.Finding`.
It never calls AWS, never raises on missing data, and never guesses. Three rules follow
from that, and these helpers exist to make them easy to obey:

* Evidence that is absent or was refused produces ERROR, never PASS. "We could not look"
  must never be recorded as "nothing wrong here".
* Every FAIL names the specific resources at fault and says what to do about them.
* Every finding cites the SP 800-171A assessment objective it speaks to, so a reader can
  trace the judgment back to the sentence in the standard it came from.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from nist171.models import Evidence, Finding, Verdict

#: Evidence as produced by the collectors and reloaded from disk.
EvidenceMap = dict[str, dict[str, Evidence]]

#: The shape every check function has: saved evidence in, one Finding out.
Check = Callable[[EvidenceMap], Finding]


def get_evidence(evidence: EvidenceMap, collector: str, key: str) -> Evidence | None:
    """The Evidence object at ``collector``/``key``, or None if it was never collected."""
    return evidence.get(collector, {}).get(key)


def raw_value(evidence: EvidenceMap, collector: str, key: str, default: Any = None) -> Any:
    """The raw AWS response at ``collector``/``key``, or ``default`` if absent."""
    item = get_evidence(evidence, collector, key)
    return default if item is None else item.raw


def is_error(value: Any) -> bool:
    """True if a raw value is a recorded failure rather than real data.

    Collectors store ``{"error": "AccessDenied", "operation": ...}`` where a call was
    refused. That is an unknown, and an unknown must not be scored as a pass.
    """
    return isinstance(value, dict) and "error" in value


def error_reason(value: Any) -> str:
    """Human-readable description of a recorded collector failure."""
    if not is_error(value):
        return "evidence missing"
    operation = value.get("operation", "unknown operation")
    return f"{value['error']} calling {operation}"


def used(*items: Evidence | None) -> list[Evidence]:
    """Filter out the ones that were never collected, so a Finding can cite the rest."""
    return [item for item in items if item is not None]


def finding(
    control_id: str,
    objective_id: str | None,
    check_name: str,
    verdict: Verdict,
    summary: str,
    *,
    affected_resources: list[str] | None = None,
    remediation: str = "",
    evidence: list[Evidence] | None = None,
    deduction_override: int | None = None,
) -> Finding:
    """Build a Finding, with the argument order every check uses."""
    return Finding(
        control_id=control_id,
        objective_id=objective_id,
        check_name=check_name,
        verdict=verdict,
        summary=summary,
        affected_resources=affected_resources or [],
        remediation=remediation,
        evidence=evidence or [],
        deduction_override=deduction_override,
    )


def parse_report_date(value: Any) -> datetime | None:
    """Parse a date out of the IAM credential report.

    The report uses several placeholders for "no date here" -- ``N/A``,
    ``no_information``, ``not_supported`` -- and they are not interchangeable with a real
    timestamp. Anything unparseable returns None so callers handle it deliberately.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text in {"N/A", "no_information", "not_supported"}:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def days_since(moment: datetime, *, now: datetime | None = None) -> int:
    """Whole days between ``moment`` and now."""
    return ((now or datetime.now(UTC)) - moment).days


def as_list(value: Any) -> list[Any]:
    """Normalize an IAM policy field that may be a single string or a list of strings."""
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]
