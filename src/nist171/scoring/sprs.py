"""SPRS scoring under the NIST SP 800-171 DoD Assessment Methodology, Version 1.2.1.

The methodology is simple arithmetic with sharp edges:

* Start at 110 -- one point of headroom per requirement, in spirit.
* For every requirement that is NOT implemented, subtract its weight: 5, 3 or 1 points,
  from Annex A. Implemented requirements subtract nothing.
* A handful of requirements have special rules. 3.5.3 (MFA) carries partial credit.
  3.1.12, 3.1.13, 3.1.16, 3.1.17 and 3.1.18 score as not applicable when the organization
  does not permit the capability at all.
* The result can go negative. Nothing is clamped.

What this module adds on top of the arithmetic is a strict line between "not implemented"
and "not assessed". This tool evaluates 15 or so of the 110 requirements automatically; the
rest need a human. A requirement nobody looked at is neither a pass nor a fail, and it is
never allowed to quietly become either.

Resolving gaps in the build specification
-----------------------------------------
The specification's rules do not cover every mix of verdicts. Each gap is resolved in the
direction that cannot overstate compliance:

* Some findings PASS, others ERROR or MANUAL, none FAIL -> NOT ASSESSED. Part of the
  requirement could not be verified, so it cannot be claimed as implemented.
* Several findings FAIL on one requirement -> points are subtracted ONCE, not per finding.
  The methodology scores requirements, not checks.
* Several failing findings disagree on the deduction -> the LARGEST wins. Partial credit on
  one aspect of 3.5.3 must not excuse a full failure on another.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from nist171.catalog import load_catalog
from nist171.models import Finding, Verdict

MAX_SCORE = 110

#: A score at or above this, with a POA&M for the remainder, is the bar for conditional
#: status under the CMMC program rule. 88 is 80% of 110.
CONDITIONAL_THRESHOLD = 88

#: Lowest score possible on the full 110 if every requirement failed: 110 minus the sum of
#: all Annex A weights (313). Quoted for context; this tool cannot reach it.
THEORETICAL_MINIMUM_FULL = -203

#: Which capability each not-applicable-eligible requirement depends on. Declaring the
#: capability not permitted is what makes the requirement score as N/A.
CAPABILITY_FOR_REQUIREMENT = {
    "3.1.12": "remote",   # Monitor and control remote access sessions
    "3.1.13": "remote",   # Cryptographic protection of remote access sessions
    "3.1.16": "wireless",  # Authorize wireless access
    "3.1.17": "wireless",  # Protect wireless access
    "3.1.18": "mobile",    # Control connection of mobile devices
}

CAPABILITIES = frozenset(CAPABILITY_FOR_REQUIREMENT.values())

_ASSESSING_VERDICTS = {Verdict.PASS, Verdict.FAIL, Verdict.NOT_APPLICABLE}


@dataclass
class ScoreResult:
    """The outcome of scoring one assessment.

    ``score`` is only meaningful alongside ``scope_note``. A partial assessment produces an
    upper bound on the full score, not an estimate of it.
    """

    score: int
    max_score: int
    assessed_count: int
    not_assessed: list[str]
    implemented: list[str]
    unmet: list[tuple[str, int]]
    na: list[str]
    conditional_threshold_met: bool
    scope_note: str
    #: Lowest score achievable if every requirement assessed here had failed.
    min_possible: int = MAX_SCORE
    #: True when the threshold verdict cannot change as more requirements are assessed.
    #: Only a "not met" can be conclusive: unassessed requirements can lower a score but
    #: never raise it.
    threshold_conclusive: bool = False
    #: Things a reader must know that do not fit anywhere else -- chiefly a configuration
    #: that contradicts the evidence.
    warnings: list[str] = field(default_factory=list)

    @property
    def points_deducted(self) -> int:
        return sum(points for _, points in self.unmet)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["unmet"] = [{"control_id": cid, "points": pts} for cid, pts in self.unmet]
        data["points_deducted"] = self.points_deducted
        data["methodology"] = "NIST SP 800-171 DoD Assessment Methodology, Version 1.2.1"
        data["conditional_threshold"] = CONDITIONAL_THRESHOLD
        return data


def _normalize_capabilities(value: bool | Iterable[str]) -> frozenset[str]:
    """Accept True (nothing is permitted), False (everything is), or named capabilities."""
    if value is True:
        return CAPABILITIES
    if value is False or value is None:
        return frozenset()
    names = frozenset(str(v).strip().lower() for v in value if str(v).strip())
    unknown = names - CAPABILITIES
    if unknown:
        raise ValueError(
            f"Unknown capability {sorted(unknown)}. Expected any of {sorted(CAPABILITIES)}."
        )
    return names


def compute_score(
    findings: Iterable[Finding],
    catalog: list[dict[str, Any]] | None = None,
    *,
    capability_not_permitted: bool | Iterable[str] = False,
) -> ScoreResult:
    """Score a set of findings against the in-scope catalog.

    Args:
        findings: Output of the checks. Several findings may address one requirement.
        catalog: Control catalog; defaults to ``catalog/controls.yaml``. Injectable so tests
            can use synthetic weights.
        capability_not_permitted: Capabilities the organization does not permit at all --
            any of ``remote``, ``wireless``, ``mobile`` -- or True for all of them. Only the
            five requirements flagged ``na_if_not_permitted`` are affected. Defaults to
            False: nothing is assumed away.
    """
    catalog = catalog if catalog is not None else load_catalog()
    not_permitted = _normalize_capabilities(capability_not_permitted)

    in_scope = [c for c in catalog if c.get("in_scope")]
    known_ids = {c["id"] for c in in_scope}

    by_control: dict[str, list[Finding]] = defaultdict(list)
    warnings: list[str] = []
    for found in findings:
        if found.control_id in known_ids:
            by_control[found.control_id].append(found)
        else:
            warnings.append(
                f"Finding '{found.check_name}' refers to {found.control_id}, which is not an "
                "in-scope requirement in the catalog; it was ignored."
            )

    implemented: list[str] = []
    unmet: list[tuple[str, int]] = []
    na: list[str] = []
    not_assessed: list[str] = []
    assessed_weight = 0

    for control in in_scope:
        cid = control["id"]
        weight = int(control["points"])
        results = by_control.get(cid, [])
        verdicts = {f.verdict for f in results}

        # Nothing automated reached a conclusion. The requirement stays open.
        if not results or not verdicts & _ASSESSING_VERDICTS:
            not_assessed.append(cid)
            continue

        failing = [f for f in results if f.verdict is Verdict.FAIL]

        if failing:
            capability = CAPABILITY_FOR_REQUIREMENT.get(cid)
            if control.get("na_if_not_permitted") and capability in not_permitted:
                na.append(cid)
                assessed_weight += weight
                # Honour the declaration, as the methodology says to -- but say plainly
                # that the evidence argues against it.
                names = ", ".join(sorted({f.check_name for f in failing}))
                warnings.append(
                    f"{cid} scored as not applicable because '{capability}' was declared not "
                    f"permitted, yet {names} found it in use. A capability that exists in "
                    "the environment is permitted in practice. Verify the declaration before "
                    "relying on this score."
                )
                continue

            deduction = max(
                f.deduction_override if f.deduction_override is not None else weight
                for f in failing
            )
            unmet.append((cid, deduction))
            assessed_weight += weight
            continue

        # No FAIL. Implemented only if every finding is a clean determination.
        if verdicts <= {Verdict.PASS, Verdict.NOT_APPLICABLE}:
            if verdicts == {Verdict.NOT_APPLICABLE}:
                na.append(cid)
            else:
                implemented.append(cid)
            assessed_weight += weight
            continue

        # A PASS alongside an ERROR or MANUAL: part of the requirement went unverified.
        not_assessed.append(cid)

    score = MAX_SCORE - sum(points for _, points in unmet)
    assessed_count = len(implemented) + len(unmet) + len(na)
    threshold_met = score >= CONDITIONAL_THRESHOLD

    return ScoreResult(
        score=score,
        max_score=MAX_SCORE,
        assessed_count=assessed_count,
        not_assessed=not_assessed,
        implemented=implemented,
        unmet=unmet,
        na=na,
        conditional_threshold_met=threshold_met,
        scope_note=_scope_note(assessed_count, len(in_scope), len(not_assessed), score),
        min_possible=MAX_SCORE - assessed_weight,
        threshold_conclusive=not threshold_met,
        warnings=warnings,
    )


def _scope_note(assessed: int, in_scope: int, not_assessed: int, score: int) -> str:
    """The sentence that must accompany every score this tool produces."""
    unscored = MAX_SCORE - assessed
    if score >= CONDITIONAL_THRESHOLD:
        threshold = (
            f"Reaching {CONDITIONAL_THRESHOLD} here is not conclusive: the {unscored} "
            "unassessed requirements can only lower the score, never raise it."
        )
    else:
        threshold = (
            f"Falling below {CONDITIONAL_THRESHOLD} here is conclusive: assessing the "
            f"remaining {unscored} requirements can only lower the score further."
        )
    return (
        f"Partial assessment -- only {assessed} of {MAX_SCORE} NIST SP 800-171 Rev 2 "
        f"requirements assessed. {in_scope} are in scope for this tool; {not_assessed} of "
        f"those need human assessment or could not be evaluated. The other {unscored} "
        f"requirements are not scored, so this figure is an upper bound on a full-assessment "
        f"score, not an estimate of it. {threshold} This is not a substitute for a DoD "
        "Assessment Methodology self-assessment."
    )
