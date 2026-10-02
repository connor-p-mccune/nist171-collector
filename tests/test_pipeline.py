"""The whole pipeline, collect -> assess -> report, run through the CLI against moto.

test_cli.py covers assess and report from a fixed evidence set. This covers the one
command it cannot: collect, which talks to AWS. moto stands in for AWS, so the evidence
folder and manifest here are written by the real collection code, then assessed and
reported on exactly as a live run would be.
"""

from __future__ import annotations

import json
from pathlib import Path

import boto3
import pytest
from click.testing import CliRunner, Result
from moto import mock_aws

from nist171.cli import cli
from nist171.collectors.aws.kms import KMSCollector
from nist171.evidence_io import load_manifest, verify_manifest


def run(*args: str) -> Result:
    return CliRunner().invoke(cli, list(args), catch_exceptions=False)


def build_account() -> None:
    """A small account: one user without MFA, one open security group, one bucket."""
    session = boto3.Session(region_name="us-east-1")
    session.client("iam").create_user(UserName="alice")
    session.client("s3").create_bucket(Bucket="pipeline-bucket")
    ec2 = session.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    group = ec2.create_security_group(GroupName="open-rdp", Description="test", VpcId=vpc)
    ec2.authorize_security_group_ingress(
        GroupId=group["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )


@pytest.fixture
def collected(tmp_path: Path):
    """Run ``nist171 collect`` against a mocked account; yield (result, run folder)."""
    with mock_aws():
        build_account()
        result = run("collect", "--out", str(tmp_path / "evidence"))
        runs = sorted((tmp_path / "evidence").iterdir())
        yield result, runs[-1]


def test_collect_writes_one_file_per_collector_and_a_manifest(collected):
    result, run_dir = collected
    assert result.exit_code == 0, result.output
    names = sorted(p.name for p in run_dir.iterdir())
    assert names == [
        "cloudtrail.json", "ec2.json", "iam.json", "kms.json", "manifest.json", "s3.json"
    ]


def test_collect_manifest_verifies_and_records_the_account(collected):
    _, run_dir = collected
    assert verify_manifest(run_dir) == []
    manifest = load_manifest(run_dir)
    assert manifest["account_id"] == "123456789012"  # moto's default account
    assert manifest["region"] == "us-east-1"
    assert manifest["failed_collectors"] == []


def test_collect_prints_what_each_collector_found(collected):
    result, _ = collected
    assert "1 user" in result.output
    assert "no password policy" in result.output
    assert "Evidence written to" in result.output


def test_collected_evidence_flows_through_assess_and_report(collected, tmp_path: Path):
    _, run_dir = collected
    out = tmp_path / "output"

    assessed = run("assess", "--evidence", str(run_dir), "--out", str(out))
    assert assessed.exit_code == 0, assessed.output
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert findings["account_id"] == "123456789012"
    fails = {f["check_name"] for f in findings["findings"] if f["verdict"] == "FAIL"}
    assert {"sg_no_unrestricted_admin_ingress", "password_policy_exists"} <= fails

    reported = run(
        "report", "--findings", str(out / "findings.json"), "--format", "all", "--out", str(out)
    )
    assert reported.exit_code == 0, reported.output
    assert (out / "oscal-assessment-results.json").is_file()


def test_a_crashing_collector_is_recorded_and_the_rest_still_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def explode(self):
        raise RuntimeError("simulated KMS outage")

    monkeypatch.setattr(KMSCollector, "collect", explode)
    with mock_aws():
        build_account()
        result = run("collect", "--out", str(tmp_path / "evidence"))

    assert result.exit_code == 0, result.output
    assert "kms" in result.output and "FAILED" in result.output
    run_dir = next((tmp_path / "evidence").iterdir())
    assert not (run_dir / "kms.json").exists()
    assert (run_dir / "iam.json").exists()

    manifest = load_manifest(run_dir)
    assert manifest["failed_collectors"] == [
        {"collector": "kms", "error_type": "RuntimeError", "error": "simulated KMS outage"}
    ]
    assert verify_manifest(run_dir) == []
