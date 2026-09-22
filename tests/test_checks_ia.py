"""Tests for the Identification and Authentication checks.

The credential report evidence is hand-built throughout: moto does not emit the
``<root_account>`` row, and several of these checks are specifically about root.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nist171.checks.ia import (
    CHECKS,
    MIN_PASSWORD_LENGTH,
    MIN_REUSE_PREVENTION,
    iam_users_identified,
    mfa_all_users,
    mfa_privileged_users,
    no_root_access_keys,
    password_complexity,
    password_policy_exists,
    password_reuse,
)
from nist171.models import Evidence, Verdict

NOW = datetime(2026, 9, 22, 12, 0, 0, tzinfo=UTC)

STRONG_POLICY = {
    "MinimumPasswordLength": 14,
    "RequireUppercaseCharacters": True,
    "RequireLowercaseCharacters": True,
    "RequireNumbers": True,
    "RequireSymbols": True,
    "PasswordReusePrevention": 24,
}

WEAK_POLICY = {
    "MinimumPasswordLength": 8,
    "RequireUppercaseCharacters": False,
    "RequireLowercaseCharacters": False,
    "RequireNumbers": False,
    "RequireSymbols": False,
    "PasswordReusePrevention": 1,
}


def ev(collector: str, key: str, raw: object) -> dict[str, dict[str, Evidence]]:
    return {collector: {key: Evidence(f"aws:{collector}:{key}", NOW, "0.1.0", raw)}}


def merge(*maps: dict[str, dict[str, Evidence]]) -> dict[str, dict[str, Evidence]]:
    out: dict[str, dict[str, Evidence]] = {}
    for m in maps:
        for collector, items in m.items():
            out.setdefault(collector, {}).update(items)
    return out


def row(
    user: str,
    *,
    mfa: bool = False,
    console: bool = False,
    keys: tuple[bool, bool] = (False, False),
):
    return {
        "user": user,
        "mfa_active": "true" if mfa else "false",
        "password_enabled": "true" if console else "false",
        "access_key_1_active": "true" if keys[0] else "false",
        "access_key_2_active": "true" if keys[1] else "false",
    }


def admin(*usernames: str) -> dict[str, object]:
    return {"users": {u: [{"PolicyName": "AdministratorAccess"}] for u in usernames}, "roles": {}}


# =======================================================================================
# Shape
# =======================================================================================


def test_every_check_returns_error_or_manual_on_empty_evidence():
    for check in CHECKS:
        found = check({})
        assert found.control_id.startswith("3.5.")
        assert found.summary.strip()
        assert found.verdict in {Verdict.ERROR, Verdict.MANUAL}, found.check_name


def test_every_check_cites_an_objective():
    for check in CHECKS:
        found = check({})
        assert found.objective_id and found.objective_id.startswith(found.control_id)


def test_registry_has_seven_automated_and_five_manual():
    verdicts = [check({}).verdict for check in CHECKS]
    assert verdicts.count(Verdict.MANUAL) == 5
    assert verdicts.count(Verdict.ERROR) == 7


# =======================================================================================
# 3.5.1 -- iam_users_identified
# =======================================================================================


def test_users_identified_passes_and_admits_it_is_weak():
    found = iam_users_identified(ev("iam", "users", [{"UserName": "a"}, {"UserName": "b"}]))
    assert found.verdict is Verdict.PASS
    assert "2 IAM user" in found.summary
    assert "weak check" in found.summary


def test_users_identified_errors_when_the_call_was_denied():
    denied = {"error": "AccessDenied", "operation": "iam:ListUsers"}
    found = iam_users_identified(ev("iam", "users", denied))
    assert found.verdict is Verdict.ERROR


# =======================================================================================
# 3.5.2 -- password_policy_exists
# =======================================================================================


def test_missing_password_policy_fails():
    found = password_policy_exists(ev("iam", "password_policy", None))
    assert found.verdict is Verdict.FAIL
    assert found.remediation


def test_weak_password_policy_still_counts_as_existing():
    found = password_policy_exists(ev("iam", "password_policy", WEAK_POLICY))
    assert found.verdict is Verdict.PASS
    assert "3.5.7" in found.summary


# =======================================================================================
# 3.5.3 -- mfa_privileged_users (partial credit)
# =======================================================================================


def test_privileged_user_without_mfa_deducts_three_when_mfa_exists_elsewhere():
    evidence = merge(
        ev("iam", "credential_report", [row("alice", mfa=True), row("nist171-test-user")]),
        ev("iam", "attached_admin", admin("nist171-test-user")),
    )
    found = mfa_privileged_users(evidence)
    assert found.verdict is Verdict.FAIL
    assert found.deduction_override == 3
    assert found.affected_resources == ["nist171-test-user"]


def test_no_mfa_anywhere_deducts_the_full_five():
    evidence = merge(
        ev("iam", "credential_report", [row("alice"), row("nist171-test-user")]),
        ev("iam", "attached_admin", admin("nist171-test-user")),
    )
    found = mfa_privileged_users(evidence)
    assert found.verdict is Verdict.FAIL
    assert found.deduction_override == 5
    assert "no account in this environment has MFA at all" in found.summary


def test_all_privileged_users_with_mfa_passes():
    evidence = merge(
        ev("iam", "credential_report", [row("admin1", mfa=True)]),
        ev("iam", "attached_admin", admin("admin1")),
    )
    found = mfa_privileged_users(evidence)
    assert found.verdict is Verdict.PASS
    assert found.deduction_override is None


def test_root_counts_as_privileged():
    evidence = merge(
        ev("iam", "credential_report", [row("<root_account>", mfa=False, console=True)]),
        ev("iam", "attached_admin", {"users": {}, "roles": {}}),
    )
    found = mfa_privileged_users(evidence)
    assert found.verdict is Verdict.FAIL
    assert "<root_account>" in found.affected_resources


def test_iam_wildcard_policy_is_surfaced_as_a_caveat():
    policies = [
        {
            "policy": {"PolicyName": "grant-yourself-anything"},
            "document": {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]},
        }
    ]
    evidence = merge(
        ev("iam", "credential_report", [row("alice", mfa=True)]),
        ev("iam", "attached_admin", {"users": {}, "roles": {}}),
        ev("iam", "policies", policies),
    )
    found = mfa_privileged_users(evidence)
    assert "grant-yourself-anything" in found.summary
    assert "cannot list who they are" in found.summary


# =======================================================================================
# 3.5.3 -- mfa_all_users
# =======================================================================================


def test_console_user_without_mfa_fails():
    found = mfa_all_users(ev("iam", "credential_report", [row("bob", console=True)]))
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources == ["bob"]


def test_console_users_all_with_mfa_pass():
    report = [row("bob", console=True, mfa=True), row("ci", console=False)]
    found = mfa_all_users(ev("iam", "credential_report", report))
    assert found.verdict is Verdict.PASS


def test_no_console_users_passes_but_says_it_passed_by_absence():
    found = mfa_all_users(ev("iam", "credential_report", [row("ci")]))
    assert found.verdict is Verdict.PASS
    assert "by absence" in found.summary


# =======================================================================================
# 3.5.7 -- password_complexity
# =======================================================================================


def test_weak_password_policy_fails_complexity():
    found = password_complexity(ev("iam", "password_policy", WEAK_POLICY))
    assert found.verdict is Verdict.FAIL
    assert "minimum length is 8" in found.summary
    for label in ("uppercase letters", "lowercase letters", "numbers", "symbols"):
        assert label in found.summary


def test_strong_password_policy_passes_complexity():
    found = password_complexity(ev("iam", "password_policy", STRONG_POLICY))
    assert found.verdict is Verdict.PASS


def test_length_just_below_threshold_fails():
    policy = dict(STRONG_POLICY, MinimumPasswordLength=MIN_PASSWORD_LENGTH - 1)
    found = password_complexity(ev("iam", "password_policy", policy))
    assert found.verdict is Verdict.FAIL


def test_missing_policy_fails_complexity():
    found = password_complexity(ev("iam", "password_policy", None))
    assert found.verdict is Verdict.FAIL


# =======================================================================================
# 3.5.8 -- password_reuse
# =======================================================================================


def test_short_password_history_fails():
    found = password_reuse(ev("iam", "password_policy", WEAK_POLICY))
    assert found.verdict is Verdict.FAIL
    assert "is 1" in found.summary


def test_adequate_password_history_passes():
    found = password_reuse(ev("iam", "password_policy", STRONG_POLICY))
    assert found.verdict is Verdict.PASS


def test_unset_password_history_fails():
    policy = {k: v for k, v in STRONG_POLICY.items() if k != "PasswordReusePrevention"}
    found = password_reuse(ev("iam", "password_policy", policy))
    assert found.verdict is Verdict.FAIL
    assert "not set" in found.summary


@pytest.mark.parametrize("depth,expected", [(MIN_REUSE_PREVENTION - 1, Verdict.FAIL),
                                            (MIN_REUSE_PREVENTION, Verdict.PASS)])
def test_reuse_threshold_boundary(depth, expected):
    policy = dict(STRONG_POLICY, PasswordReusePrevention=depth)
    assert password_reuse(ev("iam", "password_policy", policy)).verdict is expected


# =======================================================================================
# 3.5.10 -- no_root_access_keys
# =======================================================================================


def test_root_access_key_fails():
    report = [row("<root_account>", keys=(True, False)), row("alice")]
    found = no_root_access_keys(ev("iam", "credential_report", report))
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources == ["<root_account>:access_key_1"]
    assert found.remediation


def test_no_root_access_keys_passes():
    report = [row("<root_account>"), row("alice", keys=(True, False))]
    found = no_root_access_keys(ev("iam", "credential_report", report))
    assert found.verdict is Verdict.PASS


def test_missing_root_row_is_an_error_not_a_pass():
    """moto omits the root row. Reporting PASS there would be a false clean bill."""
    found = no_root_access_keys(ev("iam", "credential_report", [row("alice")]))
    assert found.verdict is Verdict.ERROR
    assert "<root_account>" in found.summary


# =======================================================================================
# Manual checks
# =======================================================================================


@pytest.mark.parametrize("control_id", ["3.5.4", "3.5.5", "3.5.6", "3.5.9", "3.5.11"])
def test_manual_checks_explain_what_a_human_must_do(control_id):
    found = next(c({}) for c in CHECKS if c({}).control_id == control_id)
    assert found.verdict is Verdict.MANUAL
    assert "human assessment" in found.summary.lower()
    assert len(found.summary) > 120
    assert found.affected_resources == []
