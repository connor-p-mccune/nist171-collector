"""Tests for the Access Control checks.

Every automated check gets a failing case and a passing case. Where the check reads a
live-service structure (security groups, S3 configuration) the evidence is built by
running the real collector against moto, so the test exercises the collector's output
shape too. Where the check reads the IAM credential report, the evidence is hand-built:
moto does not emit the ``<root_account>`` row that real AWS always includes, and several
of these checks are specifically about root.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from moto import mock_aws

from nist171.checks.ac import (
    CHECKS,
    STALE_KEY_DAYS,
    iam_least_privilege_admin,
    iam_no_stale_access_keys,
    iam_no_wildcard_admin_policies,
    iam_users_have_mfa,
    s3_public_access_blocked,
    s3_requires_tls,
    sg_no_unrestricted_admin_ingress,
)
from nist171.collectors.aws.ec2 import EC2Collector
from nist171.collectors.aws.iam import IAMCollector
from nist171.collectors.aws.s3 import S3Collector
from nist171.models import Evidence, Verdict

REGION = "us-east-1"
NOW = datetime.now(UTC)

TLS_DENY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": ["arn:aws:s3:::tls-bucket", "arn:aws:s3:::tls-bucket/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
    ],
}

ALL_BLOCKED = {
    "BlockPublicAcls": True,
    "BlockPublicPolicy": True,
    "IgnorePublicAcls": True,
    "RestrictPublicBuckets": True,
}


def evidence_of(collector: str, key: str, raw: object) -> dict[str, dict[str, Evidence]]:
    """Wrap a hand-built raw value in the evidence map shape checks expect."""
    return {
        collector: {
            key: Evidence(
                source=f"aws:{collector}:{key}",
                collected_at=NOW,
                collector_version="0.1.0",
                raw=raw,
            )
        }
    }


def credential_row(user: str, **overrides: str) -> dict[str, str]:
    """A credential report row with sane defaults, overridable per test."""
    row = {
        "user": user,
        "arn": f"arn:aws:iam::123456789012:user/{user}",
        "password_enabled": "false",
        "mfa_active": "false",
        "access_key_1_active": "false",
        "access_key_1_last_rotated": "N/A",
        "access_key_1_last_used_date": "N/A",
        "access_key_2_active": "false",
        "access_key_2_last_rotated": "N/A",
        "access_key_2_last_used_date": "N/A",
    }
    row.update(overrides)
    return row


def days_ago(days: int) -> str:
    return (NOW - timedelta(days=days)).isoformat()


# =======================================================================================
# Shape of every check
# =======================================================================================


def test_every_check_returns_a_finding_on_empty_evidence():
    """No evidence must never produce a PASS. Silence is not compliance."""
    for check in CHECKS:
        found = check({})
        assert found.control_id.startswith("3.1.")
        assert found.check_name
        assert found.summary.strip()
        assert found.verdict in {Verdict.ERROR, Verdict.MANUAL}, (
            f"{found.check_name} returned {found.verdict} with no evidence at all"
        )


def test_every_check_cites_an_assessment_objective():
    for check in CHECKS:
        found = check({})
        assert found.objective_id, f"{found.check_name} cites no objective"
        assert found.objective_id.startswith(found.control_id)


def test_registry_has_seven_automated_and_three_manual():
    verdicts = [check({}).verdict for check in CHECKS]
    assert verdicts.count(Verdict.MANUAL) == 3
    assert verdicts.count(Verdict.ERROR) == 7


# =======================================================================================
# 3.1.1 -- iam_users_have_mfa
# =======================================================================================


def test_mfa_fails_when_a_console_user_has_no_mfa():
    report = [
        credential_row("<root_account>", mfa_active="true", password_enabled="true"),
        credential_row("alice", password_enabled="true", mfa_active="false"),
    ]
    found = iam_users_have_mfa(evidence_of("iam", "credential_report", report))
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources == ["alice"]
    assert found.remediation


def test_mfa_fails_when_root_has_no_mfa():
    report = [credential_row("<root_account>", password_enabled="true", mfa_active="false")]
    found = iam_users_have_mfa(evidence_of("iam", "credential_report", report))
    assert found.verdict is Verdict.FAIL
    assert "<root_account>" in found.affected_resources


def test_mfa_passes_when_everyone_who_can_sign_in_has_it():
    report = [
        credential_row("<root_account>", password_enabled="true", mfa_active="true"),
        credential_row("alice", password_enabled="true", mfa_active="true"),
        # No console password, so MFA is not required of this one.
        credential_row("ci-bot", password_enabled="false", mfa_active="false"),
    ]
    found = iam_users_have_mfa(evidence_of("iam", "credential_report", report))
    assert found.verdict is Verdict.PASS
    assert found.affected_resources == []


def test_mfa_reports_error_when_the_report_was_refused():
    denied = {"error": "AccessDenied", "operation": "iam:GenerateCredentialReport"}
    found = iam_users_have_mfa(evidence_of("iam", "credential_report", denied))
    assert found.verdict is Verdict.ERROR
    assert "AccessDenied" in found.summary


# =======================================================================================
# 3.1.1 -- iam_no_stale_access_keys
# =======================================================================================


def test_stale_keys_fail_when_a_key_has_not_been_used_in_over_90_days():
    report = [
        credential_row(
            "alice",
            access_key_1_active="true",
            access_key_1_last_rotated=days_ago(400),
            access_key_1_last_used_date=days_ago(STALE_KEY_DAYS + 5),
        )
    ]
    found = iam_no_stale_access_keys(evidence_of("iam", "credential_report", report))
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources == ["alice:access_key_1"]


def test_stale_keys_fail_for_an_old_key_that_was_never_used():
    report = [
        credential_row(
            "ci-bot",
            access_key_1_active="true",
            access_key_1_last_rotated=days_ago(200),
            access_key_1_last_used_date="N/A",
        )
    ]
    found = iam_no_stale_access_keys(evidence_of("iam", "credential_report", report))
    assert found.verdict is Verdict.FAIL
    assert "never used" in found.summary


def test_stale_keys_pass_for_recently_used_and_recently_created_keys():
    report = [
        credential_row(
            "alice",
            access_key_1_active="true",
            access_key_1_last_rotated=days_ago(200),
            access_key_1_last_used_date=days_ago(3),
        ),
        credential_row(
            "bob",
            access_key_1_active="true",
            access_key_1_last_rotated=days_ago(10),
            access_key_1_last_used_date="N/A",
        ),
        # Inactive keys are not the scanner's business however old they are.
        credential_row(
            "carol",
            access_key_1_active="false",
            access_key_1_last_rotated=days_ago(900),
            access_key_1_last_used_date=days_ago(900),
        ),
    ]
    found = iam_no_stale_access_keys(evidence_of("iam", "credential_report", report))
    assert found.verdict is Verdict.PASS


# =======================================================================================
# 3.1.2 -- iam_no_wildcard_admin_policies
# =======================================================================================


@mock_aws
def test_wildcard_policy_fails():
    session = boto3.Session(region_name=REGION)
    session.client("iam").create_policy(
        PolicyName="nist171-test-overly-permissive",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        ),
    )
    found = iam_no_wildcard_admin_policies({"iam": IAMCollector(session).collect()})
    assert found.verdict is Verdict.FAIL
    assert "nist171-test-overly-permissive" in found.affected_resources


@mock_aws
def test_scoped_policy_passes():
    session = boto3.Session(region_name=REGION)
    session.client("iam").create_policy(
        PolicyName="nist171-test-least-privilege",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::example-bucket/*",
                    }
                ],
            }
        ),
    )
    found = iam_no_wildcard_admin_policies({"iam": IAMCollector(session).collect()})
    assert found.verdict is Verdict.PASS


def test_wildcard_action_scoped_to_one_bucket_is_not_flagged():
    """arn:aws:s3:::bucket/* contains a star but is correctly scoped.

    Flagging it would be a false positive, and a scanner people learn to ignore is worse
    than no scanner.
    """
    policies = [
        {
            "policy": {"PolicyName": "bucket-admin"},
            "document": {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*"}
                ]
            },
        }
    ]
    found = iam_no_wildcard_admin_policies(evidence_of("iam", "policies", policies))
    assert found.verdict is Verdict.PASS


def test_wildcard_check_handles_action_and_resource_as_lists():
    policies = [
        {
            "policy": {"PolicyName": "listy"},
            "document": {
                "Statement": [
                    {"Effect": "Allow", "Action": ["iam:*", "s3:*"], "Resource": ["*"]}
                ]
            },
        }
    ]
    found = iam_no_wildcard_admin_policies(evidence_of("iam", "policies", policies))
    assert found.verdict is Verdict.FAIL


def test_wildcard_check_ignores_deny_statements():
    policies = [
        {
            "policy": {"PolicyName": "guardrail"},
            "document": {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
        }
    ]
    found = iam_no_wildcard_admin_policies(evidence_of("iam", "policies", policies))
    assert found.verdict is Verdict.PASS


# =======================================================================================
# 3.1.5 -- iam_least_privilege_admin
# =======================================================================================


@mock_aws
def test_user_with_administrator_access_fails():
    session = boto3.Session(region_name=REGION)
    iam = session.client("iam")
    iam.create_user(UserName="nist171-test-user")
    iam.attach_user_policy(
        UserName="nist171-test-user",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    found = iam_least_privilege_admin({"iam": IAMCollector(session).collect()})
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources == ["nist171-test-user"]
    assert found.remediation


@mock_aws
def test_role_with_administrator_access_passes():
    """Roles are assumed and logged; a user holding admin permanently is the finding."""
    session = boto3.Session(region_name=REGION)
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_role(RoleName="admin-role", AssumeRolePolicyDocument=json.dumps({}))
    iam.attach_role_policy(
        RoleName="admin-role", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    found = iam_least_privilege_admin({"iam": IAMCollector(session).collect()})
    assert found.verdict is Verdict.PASS


# =======================================================================================
# 3.1.12 -- sg_no_unrestricted_admin_ingress
# =======================================================================================


def build_security_group(session, ingress: list[dict]) -> None:
    ec2 = session.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    group = ec2.create_security_group(GroupName="test-sg", Description="test", VpcId=vpc)
    if ingress:
        ec2.authorize_security_group_ingress(GroupId=group["GroupId"], IpPermissions=ingress)


@mock_aws
def test_ssh_open_to_the_world_fails():
    session = boto3.Session(region_name=REGION)
    build_security_group(
        session,
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    found = sg_no_unrestricted_admin_ingress({"ec2": EC2Collector(session).collect()})
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources


@mock_aws
def test_ssh_restricted_to_an_office_range_passes():
    session = boto3.Session(region_name=REGION)
    build_security_group(
        session,
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "203.0.113.0/24"}],
            }
        ],
    )
    found = sg_no_unrestricted_admin_ingress({"ec2": EC2Collector(session).collect()})
    assert found.verdict is Verdict.PASS


def test_wide_port_range_covering_rdp_fails():
    groups = [
        {
            "GroupId": "sg-range",
            "GroupName": "wide",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3000,
                    "ToPort": 4000,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
    ]
    found = sg_no_unrestricted_admin_ingress(evidence_of("ec2", "security_groups", groups))
    assert found.verdict is Verdict.FAIL
    assert "3389" in found.summary


def test_all_protocols_all_ports_fails():
    groups = [
        {
            "GroupId": "sg-all",
            "GroupName": "everything",
            "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        }
    ]
    found = sg_no_unrestricted_admin_ingress(evidence_of("ec2", "security_groups", groups))
    assert found.verdict is Verdict.FAIL


def test_ipv6_open_ssh_fails():
    groups = [
        {
            "GroupId": "sg-v6",
            "GroupName": "v6",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ],
        }
    ]
    found = sg_no_unrestricted_admin_ingress(evidence_of("ec2", "security_groups", groups))
    assert found.verdict is Verdict.FAIL


def test_non_admin_port_open_to_world_passes():
    """Port 443 open to the internet is a web server, not a finding for 3.1.12."""
    groups = [
        {
            "GroupId": "sg-web",
            "GroupName": "web",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
    ]
    found = sg_no_unrestricted_admin_ingress(evidence_of("ec2", "security_groups", groups))
    assert found.verdict is Verdict.PASS


# =======================================================================================
# 3.1.13 -- s3_requires_tls
# =======================================================================================


@mock_aws
def test_bucket_without_tls_policy_fails():
    session = boto3.Session(region_name=REGION)
    session.client("s3").create_bucket(Bucket="no-tls-bucket")
    found = s3_requires_tls({"s3": S3Collector(session).collect()})
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources == ["no-tls-bucket"]
    assert found.remediation


@mock_aws
def test_bucket_with_tls_deny_policy_passes():
    session = boto3.Session(region_name=REGION)
    s3 = session.client("s3")
    s3.create_bucket(Bucket="tls-bucket")
    s3.put_bucket_policy(Bucket="tls-bucket", Policy=json.dumps(TLS_DENY_POLICY))
    found = s3_requires_tls({"s3": S3Collector(session).collect()})
    assert found.verdict is Verdict.PASS


def test_tls_check_is_case_insensitive_about_the_condition_key():
    configs = {
        "tls-bucket": {
            "policy": {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Condition": {"bool": {"AWS:SecureTransport": "false"}},
                    }
                ]
            }
        }
    }
    found = s3_requires_tls(evidence_of("s3", "bucket_config", configs))
    assert found.verdict is Verdict.PASS


def test_tls_check_reports_error_when_the_policy_could_not_be_read():
    denied = {"error": "AccessDenied", "operation": "s3:GetBucketPolicy"}
    configs = {"denied-bucket": {"policy": denied}}
    found = s3_requires_tls(evidence_of("s3", "bucket_config", configs))
    assert found.verdict is Verdict.ERROR
    assert "denied-bucket" in found.affected_resources


def test_tls_check_passes_on_an_account_with_no_buckets():
    found = s3_requires_tls(evidence_of("s3", "bucket_config", {}))
    assert found.verdict is Verdict.PASS


# =======================================================================================
# 3.1.20 -- s3_public_access_blocked
# =======================================================================================


@mock_aws
def test_bucket_without_public_access_block_fails():
    """MOTO DIVERGENCE: real AWS has enabled Block Public Access on new buckets by
    default since April 2023, so this condition no longer arises from simply creating a
    bucket -- against a real account the same setup produces PASS. moto does not emulate
    the default, which is what lets this test still exercise the FAIL path. The check
    itself is correct either way; only the way the condition is reached differs.
    """
    session = boto3.Session(region_name=REGION)
    session.client("s3").create_bucket(Bucket="open-bucket")
    found = s3_public_access_blocked({"s3": S3Collector(session).collect()})
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources == ["open-bucket"]


@mock_aws
def test_bucket_with_all_four_settings_passes():
    session = boto3.Session(region_name=REGION)
    s3 = session.client("s3")
    s3.create_bucket(Bucket="locked-bucket")
    s3.put_public_access_block(
        Bucket="locked-bucket", PublicAccessBlockConfiguration=dict(ALL_BLOCKED)
    )
    found = s3_public_access_blocked({"s3": S3Collector(session).collect()})
    assert found.verdict is Verdict.PASS


def test_partial_public_access_block_fails():
    """Three of four is not compliance."""
    partial = dict(ALL_BLOCKED, RestrictPublicBuckets=False)
    configs = {"half-open": {"public_access_block": partial}}
    found = s3_public_access_blocked(evidence_of("s3", "bucket_config", configs))
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources == ["half-open"]


def test_public_access_block_names_only_the_offending_buckets():
    configs = {
        "good": {"public_access_block": dict(ALL_BLOCKED)},
        "bad": {"public_access_block": None},
    }
    found = s3_public_access_blocked(evidence_of("s3", "bucket_config", configs))
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources == ["bad"]


# =======================================================================================
# Manual checks
# =======================================================================================


@pytest.mark.parametrize("control_id", ["3.1.3", "3.1.4", "3.1.7"])
def test_manual_checks_explain_what_a_human_must_do(control_id):
    found = next(c({}) for c in CHECKS if c({}).control_id == control_id)
    assert found.verdict is Verdict.MANUAL
    assert "human assessment" in found.summary.lower()
    assert len(found.summary) > 120, "a MANUAL finding must say what to review, not just punt"
    assert found.affected_resources == []
