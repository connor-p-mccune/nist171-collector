"""Tests for SPRS scoring.

Most tests use the real catalog so point values come from Annex A as transcribed. A few
use a synthetic catalog -- the real 42 in-scope requirements carry only 100 points between
them, so the score cannot go below 10 with real weights, and the no-clamping rule needs a
catalog heavy enough to exercise it.
"""

from __future__ import annotations

import pytest

from nist171.catalog import load_catalog
from nist171.models import Finding, Verdict
from nist171.scoring.sprs import (
    CONDITIONAL_THRESHOLD,
    MAX_SCORE,
    compute_score,
)

CATALOG = load_catalog()
IN_SCOPE = [c for c in CATALOG if c["in_scope"]]
WEIGHT = {c["id"]: c["points"] for c in IN_SCOPE}


def f(control_id: str, verdict: Verdict, *, override: int | None = None, name: str = "") -> Finding:
    return Finding(
        control_id=control_id,
        objective_id=None,
        check_name=name or f"check_{control_id}_{verdict.value.lower()}",
        verdict=verdict,
        summary="test finding",
        deduction_override=override,
    )


def all_passing() -> list[Finding]:
    return [f(c["id"], Verdict.PASS) for c in IN_SCOPE]


# =======================================================================================
# Required by the build spec
# =======================================================================================


def test_fully_passing_scope_scores_110():
    result = compute_score(all_passing(), CATALOG)
    assert result.score == 110
    assert result.unmet == []
    assert result.assessed_count == 42
    assert len(result.implemented) == 42


def test_one_five_point_failure_scores_105():
    findings = all_passing()
    findings[0] = f("3.1.1", Verdict.FAIL)  # 3.1.1 is worth 5
    result = compute_score(findings, CATALOG)
    assert WEIGHT["3.1.1"] == 5
    assert result.score == 105
    assert result.unmet == [("3.1.1", 5)]


def test_mfa_partial_credit_override_of_three_scores_107():
    findings = [x for x in all_passing() if x.control_id != "3.5.3"]
    findings.append(f("3.5.3", Verdict.FAIL, override=3))
    result = compute_score(findings, CATALOG)
    assert result.score == 107
    assert ("3.5.3", 3) in result.unmet


def test_manual_findings_do_not_change_the_score():
    findings = all_passing()
    baseline = compute_score(findings, CATALOG).score
    findings = [x for x in findings if x.control_id != "3.1.4"]
    findings.append(f("3.1.4", Verdict.MANUAL))
    result = compute_score(findings, CATALOG)
    assert result.score == baseline
    assert "3.1.4" in result.not_assessed
    assert "3.1.4" not in result.implemented


def test_na_if_not_permitted_does_not_deduct_when_capability_is_not_permitted():
    findings = [x for x in all_passing() if x.control_id != "3.1.16"]
    findings.append(f("3.1.16", Verdict.FAIL))  # wireless, worth 5
    without = compute_score(findings, CATALOG)
    with_na = compute_score(findings, CATALOG, capability_not_permitted=True)
    assert without.score == 105
    assert with_na.score == 110
    assert "3.1.16" in with_na.na


def test_score_can_go_below_zero():
    heavy = [
        {"id": f"9.9.{n}", "points": 5, "in_scope": True, "family": "XX"} for n in range(1, 26)
    ]  # 25 requirements x 5 points = 125 available
    findings = [f(c["id"], Verdict.FAIL) for c in heavy]
    result = compute_score(findings, heavy)
    assert result.score == 110 - 125 == -15
    assert result.score < 0


# =======================================================================================
# Not assessed is never implemented
# =======================================================================================


def test_no_findings_at_all_is_not_assessed_not_implemented():
    result = compute_score([], CATALOG)
    assert result.score == 110
    assert result.assessed_count == 0
    assert len(result.not_assessed) == 42
    assert result.implemented == []


def test_all_error_is_not_assessed():
    findings = [x for x in all_passing() if x.control_id != "3.1.1"]
    findings.append(f("3.1.1", Verdict.ERROR))
    result = compute_score(findings, CATALOG)
    assert "3.1.1" in result.not_assessed
    assert result.assessed_count == 41


def test_pass_alongside_error_is_not_assessed():
    """Part of the requirement could not be verified, so it cannot be claimed implemented."""
    findings = [x for x in all_passing() if x.control_id != "3.3.8"]
    findings += [f("3.3.8", Verdict.PASS, name="a"), f("3.3.8", Verdict.ERROR, name="b")]
    result = compute_score(findings, CATALOG)
    assert "3.3.8" in result.not_assessed
    assert "3.3.8" not in result.implemented


def test_fail_alongside_error_still_deducts():
    """A confirmed failure is a failure even if another check on it errored."""
    findings = [x for x in all_passing() if x.control_id != "3.1.2"]
    findings += [f("3.1.2", Verdict.FAIL, name="a"), f("3.1.2", Verdict.ERROR, name="b")]
    result = compute_score(findings, CATALOG)
    assert ("3.1.2", 5) in result.unmet


# =======================================================================================
# Multiple findings per requirement
# =======================================================================================


def test_two_failures_on_one_requirement_deduct_once():
    """The methodology scores requirements, not checks."""
    findings = [x for x in all_passing() if x.control_id != "3.1.1"]
    findings += [f("3.1.1", Verdict.FAIL, name="mfa"), f("3.1.1", Verdict.FAIL, name="keys")]
    result = compute_score(findings, CATALOG)
    assert result.score == 105
    assert result.unmet == [("3.1.1", 5)]


def test_pass_and_fail_on_one_requirement_is_a_failure():
    findings = [x for x in all_passing() if x.control_id != "3.3.2"]
    findings += [f("3.3.2", Verdict.PASS, name="a"), f("3.3.2", Verdict.FAIL, name="b")]
    result = compute_score(findings, CATALOG)
    assert ("3.3.2", 3) in result.unmet


def test_conflicting_deductions_take_the_larger():
    """Partial credit on one aspect must not excuse a full failure on another."""
    findings = [x for x in all_passing() if x.control_id != "3.5.3"]
    findings += [
        f("3.5.3", Verdict.FAIL, override=3, name="privileged"),
        f("3.5.3", Verdict.FAIL, name="all_users"),
    ]
    result = compute_score(findings, CATALOG)
    assert ("3.5.3", 5) in result.unmet


# =======================================================================================
# Not-applicable handling
# =======================================================================================


def test_named_capability_only_affects_its_own_requirements():
    findings = [x for x in all_passing() if x.control_id not in {"3.1.12", "3.1.16"}]
    findings += [f("3.1.12", Verdict.FAIL), f("3.1.16", Verdict.FAIL)]
    result = compute_score(findings, CATALOG, capability_not_permitted=["wireless"])
    assert "3.1.16" in result.na
    assert ("3.1.12", 5) in result.unmet


def test_na_contradicted_by_evidence_produces_a_warning():
    findings = [x for x in all_passing() if x.control_id != "3.1.12"]
    findings.append(f("3.1.12", Verdict.FAIL, name="sg_no_unrestricted_admin_ingress"))
    result = compute_score(findings, CATALOG, capability_not_permitted=["remote"])
    assert "3.1.12" in result.na
    assert any("3.1.12" in w and "sg_no_unrestricted_admin_ingress" in w for w in result.warnings)


def test_requirement_without_na_flag_is_unaffected_by_the_config():
    findings = [x for x in all_passing() if x.control_id != "3.1.2"]
    findings.append(f("3.1.2", Verdict.FAIL))
    result = compute_score(findings, CATALOG, capability_not_permitted=True)
    assert ("3.1.2", 5) in result.unmet


def test_unknown_capability_is_rejected():
    with pytest.raises(ValueError, match="Unknown capability"):
        compute_score([], CATALOG, capability_not_permitted=["bluetooth"])


# =======================================================================================
# Threshold, scope note and bounds
# =======================================================================================


def test_scope_note_always_states_the_assessed_count_and_partiality():
    result = compute_score(all_passing()[:15], CATALOG)
    assert "15 of 110" in result.scope_note
    assert "partial" in result.scope_note.lower()


def test_below_threshold_is_conclusive():
    """Unassessed requirements can only lower a score, so a failing partial score stands."""
    five_pointers = ["3.1.1", "3.1.2", "3.1.12", "3.1.13", "3.1.16"]  # 25 points
    findings = [f(cid, Verdict.FAIL) for cid in five_pointers]
    result = compute_score(findings, CATALOG)
    assert result.score == 85
    assert result.score < CONDITIONAL_THRESHOLD
    assert result.conditional_threshold_met is False
    assert result.threshold_conclusive is True
    assert "conclusive" in result.scope_note


def test_above_threshold_is_not_conclusive():
    result = compute_score(all_passing()[:15], CATALOG)
    assert result.conditional_threshold_met is True
    assert result.threshold_conclusive is False
    assert "not conclusive" in result.scope_note


def test_min_possible_reflects_the_assessed_subset():
    subset = IN_SCOPE[:10]
    result = compute_score([f(c["id"], Verdict.PASS) for c in subset], CATALOG)
    assert result.min_possible == MAX_SCORE - sum(c["points"] for c in subset)


def test_finding_for_unknown_requirement_is_ignored_with_a_warning():
    result = compute_score([f("3.13.1", Verdict.FAIL)], CATALOG)
    assert result.score == 110
    assert any("3.13.1" in w for w in result.warnings)


def test_to_dict_is_serializable_and_complete():
    import json

    result = compute_score([f("3.1.1", Verdict.FAIL)], CATALOG)
    data = json.loads(json.dumps(result.to_dict()))
    assert data["score"] == 105
    assert data["unmet"] == [{"control_id": "3.1.1", "points": 5}]
    assert data["points_deducted"] == 5
    assert "Version 1.2.1" in data["methodology"]


# =======================================================================================
# The answer key
# =======================================================================================


def test_reproduces_the_expected_score_for_the_terraform_environment():
    """terraform/EXPECTED.md predicts 84 with 15 of 110 assessed. Hold the engine to it."""
    findings = [
        # Access Control
        f("3.1.1", Verdict.PASS, name="iam_users_have_mfa"),
        f("3.1.1", Verdict.PASS, name="iam_no_stale_access_keys"),
        f("3.1.2", Verdict.FAIL, name="iam_no_wildcard_admin_policies"),
        f("3.1.5", Verdict.FAIL, name="iam_least_privilege_admin"),
        f("3.1.12", Verdict.FAIL, name="sg_no_unrestricted_admin_ingress"),
        f("3.1.13", Verdict.FAIL, name="s3_requires_tls"),
        f("3.1.20", Verdict.PASS, name="s3_public_access_blocked"),
        f("3.1.3", Verdict.MANUAL),
        f("3.1.4", Verdict.MANUAL),
        f("3.1.7", Verdict.MANUAL),
        # Audit and Accountability
        f("3.3.1", Verdict.PASS, name="cloudtrail_enabled_multiregion"),
        f("3.3.2", Verdict.PASS, name="cloudtrail_global_events"),
        f("3.3.2", Verdict.FAIL, name="no_shared_accounts_heuristic"),
        f("3.3.8", Verdict.PASS, name="cloudtrail_log_validation"),
        f("3.3.8", Verdict.PASS, name="cloudtrail_bucket_protected"),
        *[f(c, Verdict.MANUAL) for c in ("3.3.3", "3.3.4", "3.3.5", "3.3.6", "3.3.7", "3.3.9")],
        # Identification and Authentication
        f("3.5.1", Verdict.PASS, name="iam_users_identified"),
        f("3.5.2", Verdict.PASS, name="password_policy_exists"),
        f("3.5.3", Verdict.FAIL, override=3, name="mfa_privileged_users"),
        f("3.5.3", Verdict.PASS, name="mfa_all_users"),
        f("3.5.7", Verdict.FAIL, name="password_complexity"),
        f("3.5.8", Verdict.FAIL, name="password_reuse"),
        f("3.5.10", Verdict.PASS, name="no_root_access_keys"),
        *[f(c, Verdict.MANUAL) for c in ("3.5.4", "3.5.5", "3.5.6", "3.5.9", "3.5.11")],
    ]
    result = compute_score(findings, CATALOG)

    assert result.score == 84
    assert result.assessed_count == 15
    assert result.points_deducted == 26
    assert len(result.unmet) == 8
    assert len(result.implemented) == 7
    assert len(result.not_assessed) == 27
    assert result.min_possible == 55
    assert result.conditional_threshold_met is False
    assert result.threshold_conclusive is True
