"""Tests for the command-line interface, run through click's CliRunner.

These drive the real commands end to end against the hand-made evidence set in
tests/fixtures/sample_evidence/, so they need neither moto nor an AWS account. That
fixture describes one account with exactly four problems: an S3 bucket that is neither
private nor TLS-only, a security group open to the internet on SSH, and no password
policy (which fails three requirements). Everything else in it is compliant.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from nist171.checks import checks_for
from nist171.cli import cli
from nist171.evidence_io import verify_manifest

FIXTURE_RUN = Path(__file__).parent / "fixtures" / "sample_evidence" / "20260901T120000Z"
ALL_CHECKS = len(checks_for(["AC", "AU", "IA"]))

#: The only FAILs the fixture should produce: check name -> resources at fault.
EXPECTED_FAILS = {
    "sg_no_unrestricted_admin_ingress": ["sg-0f1x7ure0pen0022"],
    "s3_requires_tls": ["nist171-fixture-open"],
    "s3_public_access_blocked": ["nist171-fixture-open"],
    "password_policy_exists": ["account"],
    "password_complexity": ["account"],
    "password_reuse": ["account"],
}


def run(*args: str) -> Result:
    """Invoke the CLI. Unexpected exceptions propagate so a crash fails loudly."""
    return CliRunner().invoke(cli, list(args), catch_exceptions=False)


def assess(out_dir: Path, *extra: str, evidence: Path = FIXTURE_RUN) -> Result:
    return run("assess", "--evidence", str(evidence), "--out", str(out_dir), *extra)


def findings_file(out_dir: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((out_dir / "findings.json").read_text(encoding="utf-8"))
    return data


@pytest.fixture
def assessed(tmp_path: Path) -> Path:
    """An output folder holding findings.json from assessing the fixture."""
    out = tmp_path / "output"
    result = assess(out)
    assert result.exit_code == 0, result.output
    return out


# --------------------------------------------------------------------------------------
# The fixture itself
# --------------------------------------------------------------------------------------


def test_fixture_evidence_is_intact():
    # If this fails, the fixture was edited by hand. Edit build_sample_evidence.py instead
    # and re-run it, which rewrites the files with fresh hashes.
    assert verify_manifest(FIXTURE_RUN) == []


# --------------------------------------------------------------------------------------
# Help and version
# --------------------------------------------------------------------------------------


def test_help_lists_every_command():
    result = run("--help")
    assert result.exit_code == 0
    for command in ("collect", "assess", "report"):
        assert command in result.output


@pytest.mark.parametrize("command", ["collect", "assess", "report"])
def test_every_command_has_help(command: str):
    result = run(command, "--help")
    assert result.exit_code == 0
    assert "Usage:" in result.output


def test_version():
    result = run("--version")
    assert result.exit_code == 0
    assert "nist171, version" in result.output


# --------------------------------------------------------------------------------------
# assess
# --------------------------------------------------------------------------------------


def test_assess_writes_findings_json(assessed: Path):
    data = findings_file(assessed)
    assert data["account_id"] == "111122223333"
    assert data["region"] == "us-east-1"
    assert data["families"] == ["AC", "AU", "IA"]
    assert data["evidence_dir"] == str(FIXTURE_RUN)
    assert len(data["findings"]) == ALL_CHECKS


def test_assess_fails_exactly_the_planted_problems(assessed: Path):
    findings = findings_file(assessed)["findings"]
    fails = {f["check_name"]: f["affected_resources"] for f in findings if f["verdict"] == "FAIL"}
    assert fails == EXPECTED_FAILS


def test_assess_passes_the_compliant_resources(assessed: Path):
    findings = findings_file(assessed)["findings"]
    flagged = {r for f in findings for r in f["affected_resources"]}
    assert "nist171-fixture-secure" not in flagged
    assert "sg-0f1x7uredefau1t0" not in flagged

    verdicts = {f["check_name"]: f["verdict"] for f in findings}
    assert verdicts["cloudtrail_enabled_multiregion"] == "PASS"
    assert verdicts["cloudtrail_bucket_protected"] == "PASS"
    assert verdicts["iam_users_have_mfa"] == "PASS"


def test_assess_complete_evidence_produces_no_errors(assessed: Path):
    findings = findings_file(assessed)["findings"]
    assert [f["check_name"] for f in findings if f["verdict"] == "ERROR"] == []


def test_assess_scores_the_fixture(assessed: Path):
    score = findings_file(assessed)["score"]
    # 110 - 5 (3.1.12) - 5 (3.1.13) - 1 (3.1.20) - 5 (3.5.2) - 1 (3.5.7) - 1 (3.5.8)
    assert score["score"] == 92
    assert score["assessed_count"] == 15
    assert [u["control_id"] for u in score["unmet"]] == [
        "3.1.12", "3.1.13", "3.1.20", "3.5.2", "3.5.7", "3.5.8",
    ]


def test_assess_prints_the_score_with_its_caveat(tmp_path: Path):
    result = assess(tmp_path)
    assert "Score: 92 / 110" in result.output
    assert "partial - 15 of 110 assessed" in result.output
    assert f"Findings and score written to {tmp_path / 'findings.json'}" in result.output


def test_assess_one_family(tmp_path: Path):
    result = assess(tmp_path, "--families", "ac")
    assert result.exit_code == 0, result.output
    data = findings_file(tmp_path)
    assert data["families"] == ["AC"]
    assert {f["control_id"].rsplit(".", 1)[0] for f in data["findings"]} == {"3.1"}


def test_assess_unknown_family_is_a_clean_error(tmp_path: Path):
    result = assess(tmp_path, "--families", "AC,XX")
    assert result.exit_code == 1
    assert "Unknown family 'XX'" in result.output
    assert not (tmp_path / "findings.json").exists()


def test_assess_unknown_capability_is_a_clean_error(tmp_path: Path):
    result = assess(tmp_path, "--capability-not-permitted", "teleportation")
    assert result.exit_code == 1
    assert "Unknown capability" in result.output


def test_assess_refuses_evidence_edited_to_hide_a_finding(tmp_path: Path):
    run_dir = tmp_path / "evidence" / FIXTURE_RUN.name
    shutil.copytree(FIXTURE_RUN, run_dir)

    # Make the open bucket look private without updating the stored hash.
    path = run_dir / "s3.json"
    entries = json.loads(path.read_text(encoding="utf-8"))
    config = next(e for e in entries if e["key"] == "bucket_config")
    config["raw"]["nist171-fixture-open"]["public_access_block"] = {
        flag: True
        for flag in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
        )
    }
    path.write_text(json.dumps(entries, indent=2), encoding="utf-8")

    out = tmp_path / "output"
    result = assess(out, evidence=run_dir)
    assert result.exit_code == 1
    assert "s3.json:bucket_config hash mismatch" in result.output
    assert not (out / "findings.json").exists()


def test_assess_defaults_to_the_newest_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "evidence" / "20250101T000000Z").mkdir(parents=True)
    shutil.copytree(FIXTURE_RUN, tmp_path / "evidence" / FIXTURE_RUN.name)
    monkeypatch.chdir(tmp_path)

    result = run("assess")
    assert result.exit_code == 0, result.output
    data = findings_file(tmp_path / "output")
    assert Path(data["evidence_dir"]).name == FIXTURE_RUN.name


def test_assess_with_no_evidence_says_to_collect_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.chdir(tmp_path)
    result = run("assess")
    assert result.exit_code == 1
    assert "Run 'nist171 collect' first" in result.output


# --------------------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------------------


def test_report_all_writes_every_format(assessed: Path):
    result = run(
        "report", "--findings", str(assessed / "findings.json"),
        "--format", "all", "--out", str(assessed),
    )
    assert result.exit_code == 0, result.output
    for name in ("report.html", "poam.csv", "poam.json", "oscal-assessment-results.json"):
        assert (assessed / name).is_file(), name
        assert f"Wrote {assessed / name}" in result.output


def test_report_summarizes_the_poam(assessed: Path):
    result = run(
        "report", "--findings", str(assessed / "findings.json"),
        "--format", "json", "--out", str(assessed),
    )
    assert result.exit_code == 0, result.output
    # Only 1-point requirements may be deferred to a POA&M, and 3.1.20 never may, so of
    # the six unmet requirements just 3.5.7 and 3.5.8 are deferrable.
    assert "POA&M: 6 items, 4 must be fixed before assessment" in result.output
    assert "Score 92/110" in result.output


def test_report_without_findings_is_a_clean_error(tmp_path: Path):
    result = run("report", "--findings", str(tmp_path / "missing.json"))
    assert result.exit_code == 1
    assert "Error:" in result.output


# --------------------------------------------------------------------------------------
# collect
# --------------------------------------------------------------------------------------


def test_collect_with_an_unknown_profile_fails_before_touching_aws(tmp_path: Path):
    # conftest.py points boto3 at credential files that do not exist, so the profile
    # lookup fails locally and no network call is attempted.
    out = tmp_path / "evidence"
    result = run("collect", "--profile", "does-not-exist", "--out", str(out))
    assert result.exit_code == 1
    assert "aws configure --profile does-not-exist" in result.output
    assert not out.exists()
