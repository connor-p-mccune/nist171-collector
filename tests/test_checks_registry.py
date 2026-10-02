"""Rules every registered check must obey, tested across the whole registry at once.

The per-family test files prove each check reaches PASS and FAIL on the right evidence,
and that empty evidence gives ERROR. These cover the other way a scan comes back empty:
a least-privilege role that was refused every call. Every check, including any added
later without tests of its own, must then report ERROR -- never PASS, never FAIL.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nist171.catalog import load_catalog, load_objectives
from nist171.checks import FAMILY_CHECKS
from nist171.checks.common import Check
from nist171.models import Evidence, Verdict

ALL_CHECKS: list[Check] = [check for checks in FAMILY_CHECKS.values() for check in checks]

#: Every key the five collectors write, as listed in their own tests.
COLLECTOR_KEYS = {
    "iam": [
        "users", "mfa_devices", "credential_report", "policies", "attached_admin",
        "password_policy",
    ],
    "cloudtrail": ["trails", "trail_status"],
    "ec2": ["security_groups", "ebs_encryption_default"],
    "s3": ["buckets", "bucket_config"],
    "kms": ["keys"],
}


def is_manual(check: Check) -> bool:
    return check.__name__.endswith("_manual")


def expected_when_denied(check: Check) -> Verdict:
    """MANUAL checks always say MANUAL; every automated check must say ERROR."""
    return Verdict.MANUAL if is_manual(check) else Verdict.ERROR


def everything_denied() -> dict[str, dict[str, Evidence]]:
    """Evidence where every single AWS call was refused, as the collectors record it."""
    collected = datetime(2026, 9, 1, tzinfo=UTC)
    return {
        collector: {
            key: Evidence(
                source=f"aws:{collector}:{key}",
                collected_at=collected,
                collector_version="0.1.0",
                raw={"error": "AccessDenied", "operation": f"{collector}:{key}"},
            )
            for key in keys
        }
        for collector, keys in COLLECTOR_KEYS.items()
    }


@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
def test_access_denied_everywhere_is_error_never_pass_or_fail(check: Check):
    assert check(everything_denied()).verdict is expected_when_denied(check)


@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
def test_finding_names_the_check_that_made_it(check: Check):
    assert check({}).check_name == check.__name__


@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.__name__)
def test_finding_cites_an_in_scope_requirement_and_a_real_objective(check: Check):
    in_scope = {c["id"] for c in load_catalog() if c["in_scope"]}
    objectives = {o["id"]: o["control_id"] for o in load_objectives()}

    found = check({})
    assert found.control_id in in_scope
    if found.objective_id is not None:
        assert objectives.get(found.objective_id) == found.control_id


def test_check_names_are_unique():
    names = [check.__name__ for check in ALL_CHECKS]
    assert len(names) == len(set(names))

