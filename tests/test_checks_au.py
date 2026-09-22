"""Tests for the Audit and Accountability checks."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import boto3
import pytest
from moto import mock_aws

from nist171.checks.au import (
    CHECKS,
    cloudtrail_bucket_protected,
    cloudtrail_enabled_multiregion,
    cloudtrail_global_events,
    cloudtrail_log_validation,
    no_shared_accounts_heuristic,
)
from nist171.collectors.aws.cloudtrail import CloudTrailCollector
from nist171.collectors.aws.s3 import S3Collector
from nist171.models import Evidence, Verdict

REGION = "us-east-1"
NOW = datetime(2026, 9, 22, 12, 0, 0, tzinfo=UTC)

ALL_BLOCKED = {
    "BlockPublicAcls": True,
    "BlockPublicPolicy": True,
    "IgnorePublicAcls": True,
    "RestrictPublicBuckets": True,
}

TRAIL_BUCKET_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": ["s3:GetBucketAcl", "s3:PutObject"],
            "Resource": ["arn:aws:s3:::trail-bucket", "arn:aws:s3:::trail-bucket/*"],
        }
    ],
}


def ev(collector: str, key: str, raw: object) -> dict[str, dict[str, Evidence]]:
    return {
        collector: {
            key: Evidence(f"aws:{collector}:{key}", NOW, "0.1.0", raw),
        }
    }


def merge(*maps: dict[str, dict[str, Evidence]]) -> dict[str, dict[str, Evidence]]:
    out: dict[str, dict[str, Evidence]] = {}
    for m in maps:
        for collector, items in m.items():
            out.setdefault(collector, {}).update(items)
    return out


def trail(**overrides: object) -> dict[str, object]:
    base = {
        "Name": "main",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main",
        "S3BucketName": "trail-bucket",
        "IsMultiRegionTrail": True,
        "LogFileValidationEnabled": True,
        "IncludeGlobalServiceEvents": True,
        "KmsKeyId": None,
        "HomeRegion": REGION,
    }
    base.update(overrides)
    return base


def status_for(t: dict[str, object], logging: bool = True) -> dict[str, object]:
    return {t["TrailARN"]: {"IsLogging": logging, "LatestDeliveryTime": None}}


def build_compliant_account(session) -> None:
    s3 = session.client("s3")
    s3.create_bucket(Bucket="trail-bucket")
    s3.put_bucket_versioning(Bucket="trail-bucket", VersioningConfiguration={"Status": "Enabled"})
    s3.put_public_access_block(
        Bucket="trail-bucket", PublicAccessBlockConfiguration=dict(ALL_BLOCKED)
    )
    s3.put_bucket_policy(Bucket="trail-bucket", Policy=json.dumps(TRAIL_BUCKET_POLICY))
    ct = session.client("cloudtrail")
    ct.create_trail(
        Name="main",
        S3BucketName="trail-bucket",
        IsMultiRegionTrail=True,
        IncludeGlobalServiceEvents=True,
        EnableLogFileValidation=True,
    )
    ct.start_logging(Name="main")


# =======================================================================================
# Shape
# =======================================================================================


def test_every_check_returns_error_or_manual_on_empty_evidence():
    for check in CHECKS:
        found = check({})
        assert found.control_id.startswith("3.3.")
        assert found.summary.strip()
        assert found.verdict in {Verdict.ERROR, Verdict.MANUAL}, found.check_name


def test_every_check_cites_an_objective():
    for check in CHECKS:
        found = check({})
        assert found.objective_id and found.objective_id.startswith(found.control_id)


def test_registry_has_five_automated_and_six_manual():
    verdicts = [check({}).verdict for check in CHECKS]
    assert verdicts.count(Verdict.MANUAL) == 6
    assert verdicts.count(Verdict.ERROR) == 5


# =======================================================================================
# 3.3.1 -- cloudtrail_enabled_multiregion
# =======================================================================================


@mock_aws
def test_multiregion_trail_logging_passes():
    session = boto3.Session(region_name=REGION)
    build_compliant_account(session)
    found = cloudtrail_enabled_multiregion({"cloudtrail": CloudTrailCollector(session).collect()})
    assert found.verdict is Verdict.PASS


@mock_aws
def test_no_trail_at_all_fails():
    session = boto3.Session(region_name=REGION)
    found = cloudtrail_enabled_multiregion({"cloudtrail": CloudTrailCollector(session).collect()})
    assert found.verdict is Verdict.FAIL
    assert "No CloudTrail trail exists" in found.summary
    assert found.remediation


def test_trail_that_is_not_logging_fails():
    t = trail()
    evidence = merge(
        ev("cloudtrail", "trails", [t]),
        ev("cloudtrail", "trail_status", status_for(t, logging=False)),
    )
    found = cloudtrail_enabled_multiregion(evidence)
    assert found.verdict is Verdict.FAIL
    assert "none is both" in found.summary


def test_single_region_trail_fails():
    t = trail(IsMultiRegionTrail=False)
    evidence = merge(
        ev("cloudtrail", "trails", [t]),
        ev("cloudtrail", "trail_status", status_for(t)),
    )
    found = cloudtrail_enabled_multiregion(evidence)
    assert found.verdict is Verdict.FAIL


# =======================================================================================
# 3.3.2 -- cloudtrail_global_events
# =======================================================================================


@mock_aws
def test_global_events_enabled_passes():
    session = boto3.Session(region_name=REGION)
    build_compliant_account(session)
    found = cloudtrail_global_events({"cloudtrail": CloudTrailCollector(session).collect()})
    assert found.verdict is Verdict.PASS


def test_global_events_disabled_fails():
    found = cloudtrail_global_events(
        ev("cloudtrail", "trails", [trail(IncludeGlobalServiceEvents=False)])
    )
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources == ["main"]
    assert found.remediation


# =======================================================================================
# 3.3.2 -- no_shared_accounts_heuristic
# =======================================================================================


def users(*names: str) -> list[dict[str, str]]:
    return [{"UserName": n} for n in names]


def report(*rows: tuple[str, bool]) -> list[dict[str, str]]:
    return [
        {"user": name, "password_enabled": "true" if console else "false", "mfa_active": "false"}
        for name, console in rows
    ]


@pytest.mark.parametrize(
    "name", ["shared-ops", "team-account", "nist-admin", "prod-administrator"]
)
def test_shared_looking_names_are_flagged(name):
    found = no_shared_accounts_heuristic(ev("iam", "users", users(name)))
    assert found.verdict is Verdict.FAIL
    assert name in found.affected_resources


@pytest.mark.parametrize("name", ["jsmith", "alice.chen", "jsmith-admin", "mpollock"])
def test_individual_looking_names_pass(name):
    found = no_shared_accounts_heuristic(ev("iam", "users", users(name)))
    assert found.verdict is Verdict.PASS


def test_service_account_with_console_password_is_flagged():
    evidence = merge(
        ev("iam", "users", users("svc-deploy")),
        ev("iam", "credential_report", report(("svc-deploy", True))),
    )
    found = no_shared_accounts_heuristic(evidence)
    assert found.verdict is Verdict.FAIL
    assert "console access" in found.summary


def test_service_account_without_console_password_passes():
    evidence = merge(
        ev("iam", "users", users("svc-deploy")),
        ev("iam", "credential_report", report(("svc-deploy", False))),
    )
    found = no_shared_accounts_heuristic(evidence)
    assert found.verdict is Verdict.PASS


def test_heuristic_says_it_is_a_heuristic_either_way():
    flagged = no_shared_accounts_heuristic(ev("iam", "users", users("team-x")))
    clean = no_shared_accounts_heuristic(ev("iam", "users", users("jsmith")))
    for found in (flagged, clean):
        assert "heuristic" in found.summary.lower()


# =======================================================================================
# 3.3.8 -- cloudtrail_log_validation
# =======================================================================================


@mock_aws
def test_log_validation_enabled_passes():
    session = boto3.Session(region_name=REGION)
    build_compliant_account(session)
    found = cloudtrail_log_validation({"cloudtrail": CloudTrailCollector(session).collect()})
    assert found.verdict is Verdict.PASS


def test_log_validation_disabled_fails():
    found = cloudtrail_log_validation(
        ev("cloudtrail", "trails", [trail(LogFileValidationEnabled=False)])
    )
    assert found.verdict is Verdict.FAIL
    assert found.affected_resources == ["main"]


# =======================================================================================
# 3.3.8 -- cloudtrail_bucket_protected
# =======================================================================================


@mock_aws
def test_protected_trail_bucket_passes():
    session = boto3.Session(region_name=REGION)
    build_compliant_account(session)
    evidence = {
        "cloudtrail": CloudTrailCollector(session).collect(),
        "s3": S3Collector(session).collect(),
    }
    found = cloudtrail_bucket_protected(evidence)
    assert found.verdict is Verdict.PASS


def test_trail_bucket_without_versioning_fails():
    configs = {"trail-bucket": {"versioning": None, "public_access_block": dict(ALL_BLOCKED)}}
    evidence = merge(ev("cloudtrail", "trails", [trail()]), ev("s3", "bucket_config", configs))
    found = cloudtrail_bucket_protected(evidence)
    assert found.verdict is Verdict.FAIL
    assert "versioning not enabled" in found.summary
    assert found.affected_resources == ["trail-bucket"]


def test_trail_bucket_without_full_public_access_block_fails():
    partial = dict(ALL_BLOCKED, RestrictPublicBuckets=False)
    configs = {"trail-bucket": {"versioning": "Enabled", "public_access_block": partial}}
    evidence = merge(ev("cloudtrail", "trails", [trail()]), ev("s3", "bucket_config", configs))
    found = cloudtrail_bucket_protected(evidence)
    assert found.verdict is Verdict.FAIL
    assert "public access not fully blocked" in found.summary


def test_trail_bucket_in_another_account_reports_error_not_pass():
    evidence = merge(ev("cloudtrail", "trails", [trail()]), ev("s3", "bucket_config", {}))
    found = cloudtrail_bucket_protected(evidence)
    assert found.verdict is Verdict.ERROR
    assert "trail-bucket" in found.affected_resources
