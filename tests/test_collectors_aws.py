"""Tests for the CloudTrail, EC2, S3 and KMS collectors, against moto's in-memory AWS."""

from __future__ import annotations

import json

import boto3
import pytest
from moto import mock_aws

from nist171.collectors.aws.cloudtrail import CloudTrailCollector
from nist171.collectors.aws.ec2 import EC2Collector
from nist171.collectors.aws.kms import KMSCollector
from nist171.collectors.aws.s3 import S3Collector
from nist171.models import Evidence

REGION = "us-east-1"

TLS_ONLY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": ["arn:aws:s3:::compliant-bucket", "arn:aws:s3:::compliant-bucket/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
    ],
}

TRAIL_BUCKET_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::trail-bucket",
        },
        {
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::trail-bucket/*",
        },
    ],
}


def assert_is_hashed_evidence(items: dict[str, Evidence]) -> None:
    for key, evidence in items.items():
        assert isinstance(evidence, Evidence), key
        assert len(evidence.sha256) == 64, key
        assert evidence.collector_version == "0.1.0", key
        assert evidence.collected_at.tzinfo is not None, key
        json.dumps(evidence.to_dict(), default=str)


# --------------------------------------------------------------------------------------
# CloudTrail
# --------------------------------------------------------------------------------------


@pytest.fixture
def cloudtrail_collected():
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")
        s3.create_bucket(Bucket="trail-bucket")
        s3.put_bucket_policy(Bucket="trail-bucket", Policy=json.dumps(TRAIL_BUCKET_POLICY))

        trail = session.client("cloudtrail")
        trail.create_trail(
            Name="main",
            S3BucketName="trail-bucket",
            IsMultiRegionTrail=True,
            IncludeGlobalServiceEvents=True,
            EnableLogFileValidation=True,
        )
        trail.start_logging(Name="main")
        yield CloudTrailCollector(session).collect()


def test_cloudtrail_keys_and_hashes(cloudtrail_collected):
    assert set(cloudtrail_collected) == {"trails", "trail_status"}
    assert_is_hashed_evidence(cloudtrail_collected)


def test_cloudtrail_keeps_the_fields_the_checks_need(cloudtrail_collected):
    trails = cloudtrail_collected["trails"].raw
    assert len(trails) == 1
    trail = trails[0]
    assert trail["IsMultiRegionTrail"] is True
    assert trail["LogFileValidationEnabled"] is True
    assert trail["IncludeGlobalServiceEvents"] is True
    assert trail["S3BucketName"] == "trail-bucket"
    assert trail["TrailARN"].startswith("arn:aws:cloudtrail:")
    assert trail["HomeRegion"] == REGION
    assert "KmsKeyId" in trail


def test_cloudtrail_status_keyed_by_arn_and_reports_logging(cloudtrail_collected):
    arn = cloudtrail_collected["trails"].raw[0]["TrailARN"]
    status = cloudtrail_collected["trail_status"].raw
    assert set(status) == {arn}
    assert status[arn]["IsLogging"] is True
    assert "LatestDeliveryTime" in status[arn]


def test_cloudtrail_with_no_trails_is_empty_not_an_error():
    with mock_aws():
        collected = CloudTrailCollector(boto3.Session(region_name=REGION)).collect()
    assert collected["trails"].raw == []
    assert collected["trail_status"].raw == {}


# --------------------------------------------------------------------------------------
# EC2
# --------------------------------------------------------------------------------------


@pytest.fixture
def ec2_collected():
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        group = ec2.create_security_group(
            GroupName="open-ssh", Description="Deliberately non-compliant", VpcId=vpc
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=group,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )
        yield EC2Collector(session).collect()


def test_ec2_keys_and_hashes(ec2_collected):
    assert set(ec2_collected) == {"security_groups", "ebs_encryption_default"}
    assert_is_hashed_evidence(ec2_collected)


def test_ec2_security_group_ingress_detail_is_preserved(ec2_collected):
    groups = ec2_collected["security_groups"].raw
    open_ssh = next(g for g in groups if g["GroupName"] == "open-ssh")
    ports = {
        (perm["FromPort"], perm["ToPort"], perm["IpProtocol"])
        for perm in open_ssh["IpPermissions"]
    }
    assert (22, 22, "tcp") in ports
    assert (3389, 3389, "tcp") in ports

    ssh = next(p for p in open_ssh["IpPermissions"] if p["FromPort"] == 22)
    assert {r["CidrIp"] for r in ssh["IpRanges"]} == {"0.0.0.0/0"}
    assert "Ipv6Ranges" in ssh


def test_ec2_default_ebs_encryption_is_a_boolean(ec2_collected):
    assert ec2_collected["ebs_encryption_default"].raw is False


# --------------------------------------------------------------------------------------
# S3
# --------------------------------------------------------------------------------------


@pytest.fixture
def s3_collected():
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        s3 = session.client("s3")

        s3.create_bucket(Bucket="compliant-bucket")
        s3.put_bucket_encryption(
            Bucket="compliant-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}
                ]
            },
        )
        s3.put_bucket_versioning(
            Bucket="compliant-bucket", VersioningConfiguration={"Status": "Enabled"}
        )
        s3.put_public_access_block(
            Bucket="compliant-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3.put_bucket_policy(Bucket="compliant-bucket", Policy=json.dumps(TLS_ONLY_POLICY))

        s3.create_bucket(Bucket="noncompliant-bucket")
        yield S3Collector(session).collect()


def test_s3_keys_and_hashes(s3_collected):
    assert set(s3_collected) == {"buckets", "bucket_config"}
    assert_is_hashed_evidence(s3_collected)


def test_s3_lists_bucket_names(s3_collected):
    assert set(s3_collected["buckets"].raw) == {"compliant-bucket", "noncompliant-bucket"}


def test_s3_compliant_bucket_config_is_fully_populated(s3_collected):
    config = s3_collected["bucket_config"].raw["compliant-bucket"]

    pab = config["public_access_block"]
    assert all(
        pab[flag]
        for flag in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    )
    rule = config["encryption"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]
    assert rule["SSEAlgorithm"] == "aws:kms"
    assert config["versioning"] == "Enabled"
    # The policy is parsed into a dict, not left as a JSON string.
    assert isinstance(config["policy"], dict)
    assert config["policy"]["Statement"][0]["Effect"] == "Deny"


def test_s3_unconfigured_settings_are_none_not_crashes(s3_collected):
    config = s3_collected["bucket_config"].raw["noncompliant-bucket"]
    assert config["public_access_block"] is None
    assert config["encryption"] is None
    assert config["versioning"] is None
    assert config["policy"] is None
    assert config["object_lock"] is None


def test_s3_every_bucket_has_all_five_settings(s3_collected):
    for bucket, config in s3_collected["bucket_config"].raw.items():
        assert set(config) == {
            "public_access_block",
            "encryption",
            "versioning",
            "policy",
            "object_lock",
        }, bucket


def test_s3_with_no_buckets():
    with mock_aws():
        collected = S3Collector(boto3.Session(region_name=REGION)).collect()
    assert collected["buckets"].raw == []
    assert collected["bucket_config"].raw == {}


# --------------------------------------------------------------------------------------
# KMS
# --------------------------------------------------------------------------------------


@pytest.fixture
def kms_collected():
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        session.client("kms").create_key(Description="nist171 test key")
        yield KMSCollector(session).collect()


def test_kms_keys_and_hashes(kms_collected):
    assert set(kms_collected) == {"keys"}
    assert_is_hashed_evidence(kms_collected)


def test_kms_key_metadata_fields(kms_collected):
    keys = kms_collected["keys"].raw
    assert len(keys) == 1
    key = keys[0]
    assert key["KeyId"]
    assert key["Arn"].startswith("arn:aws:kms:")
    assert key["KeyManager"] in {"CUSTOMER", "AWS"}
    assert key["KeyState"] == "Enabled"
    assert key["Origin"]


def test_kms_with_no_keys():
    with mock_aws():
        collected = KMSCollector(boto3.Session(region_name=REGION)).collect()
    assert collected["keys"].raw == []
