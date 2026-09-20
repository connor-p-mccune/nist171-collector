"""Tests for the IAM collector, against moto's in-memory AWS."""

from __future__ import annotations

import json

import boto3
import pytest
from moto import mock_aws

from nist171.collectors.aws.iam import IAMCollector
from nist171.models import Evidence

EXPECTED_KEYS = {
    "users",
    "mfa_devices",
    "credential_report",
    "policies",
    "attached_admin",
    "password_policy",
}

OVERLY_PERMISSIVE = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


def build_account(iam) -> None:
    """A small account resembling what the Terraform test environment will create."""
    iam.create_user(UserName="alice")
    iam.create_user(UserName="nist171-test-user")

    iam.create_policy(
        PolicyName="nist171-test-overly-permissive",
        PolicyDocument=json.dumps(OVERLY_PERMISSIVE),
    )
    iam.attach_user_policy(
        UserName="nist171-test-user",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )

    iam.create_role(RoleName="build-role", AssumeRolePolicyDocument=json.dumps({}))
    iam.attach_role_policy(
        RoleName="build-role",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )


@pytest.fixture
def collected():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        build_account(session.client("iam"))
        yield IAMCollector(session).collect()


def test_collect_returns_every_expected_key(collected):
    assert set(collected) == EXPECTED_KEYS


def test_every_item_is_evidence_with_a_hash(collected):
    for key, evidence in collected.items():
        assert isinstance(evidence, Evidence), key
        assert len(evidence.sha256) == 64, key
        assert evidence.collector_version == "0.1.0"
        assert evidence.collected_at.tzinfo is not None


def test_sources_are_namespaced(collected):
    for evidence in collected.values():
        assert evidence.source.startswith("aws:iam:")


def test_users_are_collected(collected):
    names = {u["UserName"] for u in collected["users"].raw}
    assert names == {"alice", "nist171-test-user"}


def test_mfa_devices_keyed_by_username(collected):
    assert set(collected["mfa_devices"].raw) == {"alice", "nist171-test-user"}


def test_customer_managed_policy_document_is_parsed(collected):
    policies = collected["policies"].raw
    names = {p["policy"]["PolicyName"] for p in policies}
    assert "nist171-test-overly-permissive" in names

    entry = next(p for p in policies if p["policy"]["PolicyName"].endswith("permissive"))
    # Parsed into a dict, not left as a URL-encoded string -- the checks read statements.
    assert isinstance(entry["document"], dict)
    assert entry["document"]["Statement"][0]["Action"] == "*"


def test_aws_managed_policies_are_excluded(collected):
    # Scope="Local" -- AdministratorAccess is AWS-managed and must not appear here.
    names = {p["policy"]["PolicyName"] for p in collected["policies"].raw}
    assert "AdministratorAccess" not in names


def test_attached_admin_separates_users_from_roles(collected):
    admin = collected["attached_admin"].raw
    assert set(admin["users"]) == {"nist171-test-user"}
    assert set(admin["roles"]) == {"build-role"}
    assert admin["users"]["nist171-test-user"][0]["PolicyName"] == "AdministratorAccess"


def test_missing_password_policy_is_none_not_a_crash(collected):
    # A brand-new AWS account has no password policy. That is a finding for 3.5.2, and
    # NoSuchEntity must not end the run.
    assert collected["password_policy"].raw is None


def test_password_policy_is_captured_when_present():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        session.client("iam").update_account_password_policy(
            MinimumPasswordLength=8,
            RequireSymbols=False,
            RequireNumbers=False,
            RequireUppercaseCharacters=False,
            RequireLowercaseCharacters=False,
        )
        collected = IAMCollector(session).collect()

    policy = collected["password_policy"].raw
    assert policy is not None
    assert policy["MinimumPasswordLength"] == 8


def test_credential_report_parses_into_rows(collected):
    report = collected["credential_report"].raw
    assert isinstance(report, list), f"credential report came back as {report!r}"
    assert report, "credential report should not be empty"

    users = {row["user"] for row in report}
    assert users == {"alice", "nist171-test-user"}

    # MOTO LIMITATION: moto does not emit the "<root_account>" row that real AWS always
    # includes, so checks that depend on root -- root MFA (3.5.3) and root access keys
    # (3.5.10) -- are tested against hand-built evidence rather than through the
    # collector. The parsing path is what this test covers.


def test_credential_report_has_the_columns_the_checks_need(collected):
    row = collected["credential_report"].raw[0]
    required = {
        "user",
        "mfa_active",
        "password_enabled",
        "access_key_1_active",
        "access_key_1_last_rotated",
        "access_key_1_last_used_date",
        "access_key_2_active",
        "access_key_2_last_rotated",
        "access_key_2_last_used_date",
    }
    assert required <= set(row)


def test_empty_account_collects_without_error():
    with mock_aws():
        collected = IAMCollector(boto3.Session(region_name="us-east-1")).collect()
    assert set(collected) == EXPECTED_KEYS
    assert collected["users"].raw == []
    assert collected["attached_admin"].raw == {"users": {}, "roles": {}}


def test_evidence_survives_to_dict(collected):
    for key, evidence in collected.items():
        as_dict = evidence.to_dict()
        reloaded = json.loads(json.dumps(as_dict, default=str))
        assert reloaded["sha256"] == evidence.sha256, key
