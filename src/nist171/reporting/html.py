"""Self-contained HTML report.

One file, inline CSS, no scripts, no external requests. It has to open from an email
attachment on an air-gapped laptop and look the same as it does here, and it must not
phone home to a CDN from inside a defense contractor's network.

Autoescaping is on for the whole template. Finding summaries embed AWS resource names --
IAM users, bucket names, security group descriptions -- and those are strings anyone with
write access to the account can set. A compliance report that executes a script someone
planted in a security group description would be a remarkable way to fail an audit.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape

from nist171 import __version__
from nist171.reporting.poam import POAM_WINDOW_DAYS

TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_NAME = "report.html.j2"

FAMILY_NAMES = {
    "3.1": ("AC", "Access Control"),
    "3.3": ("AU", "Audit and Accountability"),
    "3.5": ("IA", "Identification and Authentication"),
}

VERDICT_DISPLAY = {
    "PASS": ("PASS", "pass"),
    "FAIL": ("FAIL", "fail"),
    "MANUAL": ("MANUAL", "manual"),
    "NOT_APPLICABLE": ("N/A", "na"),
    "ERROR": ("ERROR", "error"),
}


def manifest_sha256(evidence_dir: Path | str | None) -> str | None:
    """SHA-256 of the evidence run's manifest.json, or None if it cannot be found."""
    if not evidence_dir:
        return None
    path = Path(evidence_dir) / "manifest.json"
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _format_time(value: Any) -> str:
    if not value:
        return "unknown"
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _breakable(name: str) -> Markup:
    """Allow a long snake_case name to wrap at its underscores instead of mid-word.

    Each piece is escaped before the <wbr> tags go in, so this stays safe even if a check
    name ever came from somewhere other than this codebase.
    """
    return Markup("_<wbr>").join(escape(part) for part in name.split("_"))


def _group_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Findings grouped by family, preserving assessment order within each."""
    groups: dict[str, dict[str, Any]] = {}
    for found in findings:
        prefix = ".".join(str(found.get("control_id", "")).split(".")[:2])
        code, name = FAMILY_NAMES.get(prefix, ("--", "Other"))
        verdict = str(found.get("verdict", "ERROR"))
        label, css = VERDICT_DISPLAY.get(verdict, (verdict, "error"))
        groups.setdefault(prefix, {"code": code, "name": name, "findings": []})
        groups[prefix]["findings"].append(
            {
                "control_id": found.get("control_id", ""),
                "objective_id": found.get("objective_id") or "",
                "check_name": found.get("check_name", ""),
                "check_name_html": _breakable(str(found.get("check_name", ""))),
                "verdict_label": label,
                "verdict_class": css,
                "is_manual": verdict == "MANUAL",
                "summary": found.get("summary", ""),
                "affected_resources": found.get("affected_resources", []),
                "deduction_override": found.get("deduction_override"),
            }
        )
    return list(groups.values())


def build_context(
    data: dict[str, Any],
    poam_items: list[dict[str, Any]],
    *,
    manifest_hash: str | None,
) -> dict[str, Any]:
    """Everything the template needs, already formatted. The template does no logic."""
    findings = data.get("findings", [])
    counts: dict[str, int] = {}
    for found in findings:
        label = VERDICT_DISPLAY.get(found.get("verdict", ""), ("ERROR", "error"))[0]
        counts[label] = counts.get(label, 0) + 1

    score = data["score"]
    return {
        "account_id": data.get("account_id") or "unknown",
        "region": data.get("region") or "unknown",
        "collected_at": _format_time(data.get("collected_at")),
        "assessed_at": _format_time(data.get("assessed_at")),
        "generated_at": _format_time(datetime.now(UTC).isoformat()),
        "evidence_dir": data.get("evidence_dir") or "unknown",
        "families": ", ".join(data.get("families", [])),
        "tool_version": data.get("tool_version") or __version__,
        "score": score,
        "points_deducted": score.get("points_deducted", 0),
        "not_assessed_count": len(score.get("not_assessed", [])),
        "unscored_count": score.get("max_score", 110) - score.get("assessed_count", 0),
        "verdict_counts": [
            (label, counts.get(label, 0), css)
            for label, css in (
                ("PASS", "pass"),
                ("FAIL", "fail"),
                ("MANUAL", "manual"),
                ("N/A", "na"),
                ("ERROR", "error"),
            )
        ],
        "finding_groups": _group_findings(findings),
        "poam_items": poam_items,
        "poam_window_days": POAM_WINDOW_DAYS,
        "ineligible_count": sum(1 for i in poam_items if not i["conditional_poam_eligible"]),
        "manifest_hash": manifest_hash,
    }


def render_report(
    data: dict[str, Any],
    poam_items: list[dict[str, Any]],
    *,
    manifest_hash: str | None = None,
) -> str:
    """Render the report to an HTML string."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(TEMPLATE_NAME)
    return template.render(**build_context(data, poam_items, manifest_hash=manifest_hash))


def write_report(
    path: Path | str,
    data: dict[str, Any],
    poam_items: list[dict[str, Any]],
    *,
    manifest_hash: str | None = None,
) -> Path:
    """Render and write the report."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_report(data, poam_items, manifest_hash=manifest_hash), encoding="utf-8"
    )
    return path
