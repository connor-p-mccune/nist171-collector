"""Build the hand-made evidence set in tests/fixtures/sample_evidence/.

The CLI tests run ``nist171 assess`` against this folder, so they need neither moto nor an
AWS account. Every value below was written by hand to describe one small, deliberately
imperfect account:

* IAM: one user, ``alice``, with MFA and no access keys. The root account has MFA and no
  access keys. No account password policy.
* CloudTrail: one multi-region trail, logging, with log file validation, delivering to the
  compliant bucket.
* EC2: the default security group (no inbound rules) and one security group open to the
  internet on SSH (port 22).
* S3: one compliant bucket (all four Block Public Access settings on, TLS required,
  encrypted, versioned) and one non-compliant bucket (none of those).
* KMS: no customer-managed keys.

The JSON files are the committed fixture; this script is how they were made. Evidence
files carry per-item SHA-256 hashes and the manifest carries per-file hashes, so the files
cannot be edited by hand without breaking verification. To change the fixture, edit the
values here and re-run from the project root:

    python tests/fixtures/build_sample_evidence.py

Timestamps are fixed, so re-running without changes reproduces the files byte for byte.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nist171.evidence_io import MANIFEST_NAME, file_sha256, write_evidence_file
from nist171.models import Evidence

ACCOUNT = "111122223333"  # AWS's documentation example account ID, not a real account
REGION = "us-east-1"
COLLECTED_AT = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)
RUN_DIR = Path(__file__).parent / "sample_evidence" / COLLECTED_AT.strftime("%Y%m%dT%H%M%SZ")

SECURE_BUCKET = "nist171-fixture-secure"
OPEN_BUCKET = "nist171-fixture-open"
OPEN_SG = "sg-0f1x7ure0pen0022"
DEFAULT_SG = "sg-0f1x7uredefau1t0"
TRAIL_ARN = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/org-trail"


def credential_report_row(user: str, arn: str, *, password: str, mfa: str) -> dict[str, str]:
    """One row of the IAM credential report, with every column the real CSV has."""
    return {
        "user": user,
        "arn": arn,
        "user_creation_time": "2026-08-03T14:20:00+00:00",
        "password_enabled": password,
        "password_last_used": "2026-08-31T09:15:00+00:00",
        "password_last_changed": "2026-08-03T14:20:00+00:00",
        "password_next_rotation": "N/A",
        "mfa_active": mfa,
        "access_key_1_active": "false",
        "access_key_1_last_rotated": "N/A",
        "access_key_1_last_used_date": "N/A",
        "access_key_1_last_used_region": "N/A",
        "access_key_1_last_used_service": "N/A",
        "access_key_2_active": "false",
        "access_key_2_last_rotated": "N/A",
        "access_key_2_last_used_date": "N/A",
        "access_key_2_last_used_region": "N/A",
        "access_key_2_last_used_service": "N/A",
        "cert_1_active": "false",
        "cert_1_last_rotated": "N/A",
        "cert_2_active": "false",
        "cert_2_last_rotated": "N/A",
    }


IAM: dict[str, tuple[str, Any]] = {
    "users": (
        "aws:iam:list_users",
        [
            {
                "Path": "/",
                "UserName": "alice",
                "UserId": "AIDAFIXTUREALICE0001",
                "Arn": f"arn:aws:iam::{ACCOUNT}:user/alice",
                "CreateDate": "2026-08-03 14:20:00+00:00",
            }
        ],
    ),
    "mfa_devices": (
        "aws:iam:list_mfa_devices",
        {
            "alice": [
                {
                    "UserName": "alice",
                    "SerialNumber": f"arn:aws:iam::{ACCOUNT}:mfa/alice",
                    "EnableDate": "2026-08-03 14:25:00+00:00",
                }
            ]
        },
    ),
    "credential_report": (
        "aws:iam:get_credential_report",
        [
            credential_report_row(
                "<root_account>", f"arn:aws:iam::{ACCOUNT}:root", password="not_supported",
                mfa="true",
            ),
            credential_report_row(
                "alice", f"arn:aws:iam::{ACCOUNT}:user/alice", password="true", mfa="true"
            ),
        ],
    ),
    "policies": ("aws:iam:list_policies", []),
    "attached_admin": ("aws:iam:list_attached_policies", {"users": {}, "roles": {}}),
    # None is how the collector records AWS's NoSuchEntity: the account has no policy.
    "password_policy": ("aws:iam:get_account_password_policy", None),
}

CLOUDTRAIL: dict[str, tuple[str, Any]] = {
    "trails": (
        "aws:cloudtrail:describe_trails",
        [
            {
                "Name": "org-trail",
                "TrailARN": TRAIL_ARN,
                "S3BucketName": SECURE_BUCKET,
                "IsMultiRegionTrail": True,
                "LogFileValidationEnabled": True,
                "IncludeGlobalServiceEvents": True,
                "KmsKeyId": None,
                "HomeRegion": REGION,
            }
        ],
    ),
    "trail_status": (
        "aws:cloudtrail:get_trail_status",
        {TRAIL_ARN: {"IsLogging": True, "LatestDeliveryTime": "2026-09-01 11:55:00+00:00"}},
    ),
}


def security_group(group_id: str, name: str, ingress: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "GroupId": group_id,
        "GroupName": name,
        "Description": name,
        "VpcId": "vpc-0f1x7ure00000001",
        "OwnerId": ACCOUNT,
        "IpPermissions": ingress,
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
            }
        ],
        "Tags": [],
    }


EC2: dict[str, tuple[str, Any]] = {
    "security_groups": (
        "aws:ec2:describe_security_groups",
        [
            security_group(DEFAULT_SG, "default", []),
            security_group(
                OPEN_SG,
                "fixture-open-ssh",
                [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "UserIdGroupPairs": [],
                    }
                ],
            ),
        ],
    ),
    "ebs_encryption_default": ("aws:ec2:get_ebs_encryption_by_default", True),
}

SECURE_BUCKET_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{SECURE_BUCKET}", f"arn:aws:s3:::{SECURE_BUCKET}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        },
        {
            "Sid": "CloudTrailWrite",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{SECURE_BUCKET}/AWSLogs/{ACCOUNT}/*",
        },
    ],
}

S3: dict[str, tuple[str, Any]] = {
    "buckets": ("aws:s3:list_buckets", [OPEN_BUCKET, SECURE_BUCKET]),
    "bucket_config": (
        "aws:s3:bucket_config",
        {
            OPEN_BUCKET: {
                "public_access_block": None,
                "encryption": None,
                "versioning": None,
                "policy": None,
                "object_lock": None,
            },
            SECURE_BUCKET: {
                "public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "encryption": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"},
                            "BucketKeyEnabled": True,
                        }
                    ]
                },
                "versioning": "Enabled",
                "policy": SECURE_BUCKET_POLICY,
                "object_lock": None,
            },
        },
    ),
}

KMS: dict[str, tuple[str, Any]] = {
    "keys": ("aws:kms:describe_key", []),
}

COLLECTORS = {"iam": IAM, "cloudtrail": CLOUDTRAIL, "ec2": EC2, "s3": S3, "kms": KMS}


def build(run_dir: Path = RUN_DIR) -> Path:
    """Write every evidence file and the manifest into ``run_dir``."""
    run_dir.mkdir(parents=True, exist_ok=True)
    files = []
    for name, entries in COLLECTORS.items():
        items = {
            key: Evidence(
                source=source, collected_at=COLLECTED_AT, collector_version="0.1.0", raw=raw
            )
            for key, (source, raw) in entries.items()
        }
        path = write_evidence_file(run_dir / f"{name}.json", items)
        files.append(
            {
                "name": path.name,
                "sha256": file_sha256(path),
                "bytes": path.stat().st_size,
                "items": len(items),
                "keys": list(items),
            }
        )

    manifest = {
        "tool": "nist171-collector",
        "tool_version": "0.1.0",
        "collector_version": "0.1.0",
        "account_id": ACCOUNT,
        "region": REGION,
        "collection_started_at": COLLECTED_AT.isoformat(),
        "collection_completed_at": COLLECTED_AT.isoformat(),
        "files": files,
        "failed_collectors": [],
    }
    (run_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2), encoding="utf-8", newline="\n"
    )
    return run_dir


if __name__ == "__main__":
    print(f"Wrote {build()}")
