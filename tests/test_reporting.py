"""Tests for the POA&M, the HTML report, and the report command."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nist171.cli import cli
from nist171.models import Finding, Verdict
from nist171.reporting.html import manifest_sha256, render_report
from nist171.reporting.poam import (
    CSV_COLUMNS,
    FindingsFileError,
    build_poam,
    conditional_eligibility,
    load_findings,
    write_poam_csv,
    write_poam_json,
)
from nist171.scoring.sprs import compute_score

COLLECTED_AT = "2026-09-21T21:48:40+00:00"


def f(cid: str, verdict: Verdict, **kw) -> Finding:
    return Finding(
        control_id=cid,
        objective_id=kw.pop("objective_id", None),
        check_name=kw.pop("name", f"check_{cid}"),
        verdict=verdict,
        summary=kw.pop("summary", f"summary for {cid}"),
        affected_resources=kw.pop("affected", []),
        remediation=kw.pop("remediation", f"fix {cid}"),
        deduction_override=kw.pop("override", None),
    )


def findings_data(findings: list[Finding], evidence_dir: str = "evidence/run") -> dict:
    """Build a findings.json payload the way 'nist171 assess' does."""
    return {
        "tool": "nist171-collector",
        "tool_version": "0.1.0",
        "assessed_at": "2026-09-21T22:00:00+00:00",
        "evidence_dir": evidence_dir,
        "account_id": "123456789012",
        "region": "us-east-1",
        "collected_at": COLLECTED_AT,
        "families": ["AC", "AU", "IA"],
        "capability_not_permitted": [],
        "score": compute_score(findings).to_dict(),
        "findings": [x.to_dict() for x in findings],
    }


@pytest.fixture
def expected_env_findings() -> list[Finding]:
    """Verdicts matching terraform/EXPECTED.md against the real account."""
    return [
        f("3.1.1", Verdict.PASS, name="iam_users_have_mfa"),
        f("3.1.2", Verdict.FAIL, name="iam_no_wildcard_admin_policies",
          affected=["nist171-test-overly-permissive"]),
        f("3.1.5", Verdict.FAIL, name="iam_least_privilege_admin",
          affected=["nist-admin", "nist171-test-user"]),
        f("3.1.12", Verdict.FAIL, name="sg_no_unrestricted_admin_ingress", affected=["sg-0abc"]),
        f("3.1.13", Verdict.FAIL, name="s3_requires_tls", affected=["nist171-test-noncompliant"]),
        f("3.1.20", Verdict.PASS, name="s3_public_access_blocked"),
        f("3.1.4", Verdict.MANUAL, name="separation_of_duties_manual"),
        f("3.3.1", Verdict.PASS, name="cloudtrail_enabled_multiregion"),
        f("3.3.2", Verdict.PASS, name="cloudtrail_global_events"),
        f("3.3.2", Verdict.FAIL, name="no_shared_accounts_heuristic", affected=["nist-admin"]),
        f("3.3.8", Verdict.PASS, name="cloudtrail_log_validation"),
        f("3.5.1", Verdict.PASS, name="iam_users_identified"),
        f("3.5.2", Verdict.PASS, name="password_policy_exists"),
        f("3.5.3", Verdict.FAIL, name="mfa_privileged_users", override=3,
          affected=["nist-admin", "nist171-test-user"]),
        f("3.5.3", Verdict.PASS, name="mfa_all_users"),
        f("3.5.7", Verdict.FAIL, name="password_complexity", affected=["account"]),
        f("3.5.8", Verdict.FAIL, name="password_reuse", affected=["account"]),
        f("3.5.10", Verdict.PASS, name="no_root_access_keys"),
    ]


# =======================================================================================
# POA&M
# =======================================================================================


def test_one_poam_item_per_unmet_requirement(expected_env_findings):
    data = findings_data(expected_env_findings)
    items = build_poam(data)
    assert [i["control_id"] for i in items] == [
        "3.1.2", "3.1.5", "3.1.12", "3.1.13", "3.3.2", "3.5.3", "3.5.7", "3.5.8",
    ]
    assert [i["poam_id"] for i in items][:2] == ["POAM-001", "POAM-002"]


def test_poam_points_respect_partial_credit(expected_env_findings):
    items = {i["control_id"]: i for i in build_poam(findings_data(expected_env_findings))}
    assert items["3.5.3"]["points"] == 3
    assert items["3.1.2"]["points"] == 5


def test_poam_due_date_is_180_days_after_collection(expected_env_findings):
    items = build_poam(findings_data(expected_env_findings))
    assert {i["scheduled_completion"] for i in items} == {"2027-03-20"}


def test_poam_carries_800_53_mapping_and_requirement_text(expected_env_findings):
    items = {i["control_id"]: i for i in build_poam(findings_data(expected_env_findings))}
    assert items["3.1.12"]["nist_800_53_rev4"] == ["AC-17(1)"]
    assert items["3.1.12"]["requirement"].startswith("Monitor and control remote access")


def test_poam_weakness_uses_only_failing_findings(expected_env_findings):
    """3.3.2 has a PASS and a FAIL; only the FAIL describes the weakness."""
    items = {i["control_id"]: i for i in build_poam(findings_data(expected_env_findings))}
    assert items["3.3.2"]["source_checks"] == ["no_shared_accounts_heuristic"]
    assert "cloudtrail_global_events" not in items["3.3.2"]["weakness"]


def test_poam_defaults_and_poc(expected_env_findings):
    data = findings_data(expected_env_findings)
    assert {i["point_of_contact"] for i in build_poam(data)} == {"TBD"}
    assert {i["status"] for i in build_poam(data)} == {"Open"}
    named = build_poam(data, point_of_contact="Jane Smith")
    assert {i["point_of_contact"] for i in named} == {"Jane Smith"}


def test_poam_is_empty_when_nothing_is_unmet():
    data = findings_data([f("3.1.1", Verdict.PASS), f("3.1.4", Verdict.MANUAL)])
    assert build_poam(data) == []


def test_unassessed_requirements_are_not_poam_items():
    """A POA&M lists known weaknesses. An unassessed requirement is an unknown."""
    data = findings_data([f("3.1.4", Verdict.MANUAL), f("3.1.1", Verdict.ERROR)])
    assert build_poam(data) == []


@pytest.mark.parametrize(
    "control_id, points, eligible",
    [
        ("3.5.7", 1, True),       # 1-point requirement
        ("3.1.2", 5, False),      # worth more than 1
        ("3.5.3", 3, False),      # partial credit still worth more than 1
        ("3.1.20", 1, False),     # 1-point but on the never-eligible list
        ("3.1.22", 1, False),     # same
        ("3.13.11", 3, True),     # the one named exception
    ],
)
def test_conditional_poam_eligibility(control_id, points, eligible):
    assert conditional_eligibility(control_id, points)[0] is eligible


def test_expected_environment_has_six_fix_first_items(expected_env_findings):
    items = build_poam(findings_data(expected_env_findings))
    assert sum(1 for i in items if not i["conditional_poam_eligible"]) == 6
    eligible = {i["control_id"] for i in items if i["conditional_poam_eligible"]}
    assert eligible == {"3.5.7", "3.5.8"}


def test_poam_csv_has_every_column_and_flat_lists(tmp_path, expected_env_findings):
    items = build_poam(findings_data(expected_env_findings))
    path = write_poam_csv(tmp_path / "poam.csv", items)
    with path.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert tuple(rows[0]) == CSV_COLUMNS
    assert len(rows) == len(items)
    row = next(r for r in rows if r["control_id"] == "3.1.5")
    assert row["affected_resources"] == "nist-admin; nist171-test-user"
    assert row["conditional_poam_eligible"] == "No"


def test_poam_csv_opens_cleanly_in_excel(tmp_path, expected_env_findings):
    """A UTF-8 byte-order mark is what makes Excel on Windows pick the right encoding."""
    path = write_poam_csv(tmp_path / "poam.csv", build_poam(findings_data(expected_env_findings)))
    assert path.read_bytes().startswith(b"\xef\xbb\xbf")


def test_poam_json_is_self_describing(tmp_path, expected_env_findings):
    data = findings_data(expected_env_findings)
    items = build_poam(data)
    payload = json.loads(write_poam_json(tmp_path / "poam.json", items, data).read_text())
    assert payload["item_count"] == 8
    assert payload["score"] == 84
    assert payload["poam_window_days"] == 180
    assert "partial" in payload["scope_note"].lower()


def test_load_findings_rejects_a_file_without_a_score(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps({"findings": []}))
    with pytest.raises(FindingsFileError, match="re-run"):
        load_findings(path)


# =======================================================================================
# HTML report
# =======================================================================================


def test_report_contains_the_essentials(expected_env_findings):
    data = findings_data(expected_env_findings)
    html = render_report(data, build_poam(data), manifest_hash="a" * 64)
    assert "123456789012" in html
    assert ">84<" in html
    assert "15 of 110" in html
    assert data["score"]["scope_note"].split(" -- ")[0] in html
    assert "Evidence manifest sha256:" in html
    assert "a" * 64 in html
    assert "POAM-001" in html


@pytest.mark.parametrize("css", ["pass", "fail", "manual"])
def test_report_renders_verdict_badges(css, expected_env_findings):
    data = findings_data(expected_env_findings)
    html = render_report(data, build_poam(data))
    assert f'class="badge {css}"' in html


def test_report_renders_na_and_error_badges():
    findings = [f("3.1.16", Verdict.NOT_APPLICABLE), f("3.1.1", Verdict.ERROR)]
    data = findings_data(findings)
    html = render_report(data, build_poam(data))
    assert 'class="badge na">N/A<' in html
    assert 'class="badge error">ERROR<' in html


def test_report_is_self_contained(expected_env_findings):
    """No external requests: it must open offline and must not call out from a network."""
    data = findings_data(expected_env_findings)
    html = render_report(data, build_poam(data)).lower()
    assert "<script" not in html
    assert "<link" not in html
    assert "http://" not in html
    assert "https://" not in html
    assert "<style>" in html


def test_report_escapes_attacker_controlled_resource_names():
    """Resource names come from the scanned account. They must never become markup."""
    evil = '<script>alert("pwned")</script>'
    findings = [f("3.1.5", Verdict.FAIL, affected=[evil], summary=f"user {evil} is admin")]
    data = findings_data(findings)
    html = render_report(data, build_poam(data))
    assert evil not in html
    assert "&lt;script&gt;" in html


def test_report_says_so_when_the_manifest_is_missing(expected_env_findings):
    data = findings_data(expected_env_findings)
    html = render_report(data, build_poam(data), manifest_hash=None)
    assert "not available" in html


def test_manifest_sha256_hashes_the_file_bytes(tmp_path):
    (tmp_path / "manifest.json").write_bytes(b'{"files": []}')
    assert manifest_sha256(tmp_path) == hashlib.sha256(b'{"files": []}').hexdigest()
    assert manifest_sha256(tmp_path / "nowhere") is None


# =======================================================================================
# report command
# =======================================================================================


def test_report_command_writes_every_format(tmp_path, expected_env_findings):
    evidence = tmp_path / "evidence" / "run"
    evidence.mkdir(parents=True)
    (evidence / "manifest.json").write_text('{"files": []}')
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(findings_data(expected_env_findings, str(evidence))))

    out = tmp_path / "output"
    result = CliRunner().invoke(
        cli,
        ["report", "--findings", str(findings_path), "--format", "all",
         "--poc", "Jane Smith", "--out", str(out)],
    )
    assert result.exit_code == 0, result.output
    for name in ("report.html", "poam.csv", "poam.json"):
        assert (out / name).is_file(), name
        assert f"Wrote {out / name}" in result.output
    assert "6 must be fixed before assessment" in result.output
    assert "Jane Smith" in (out / "poam.csv").read_text(encoding="utf-8-sig")
    expected_hash = hashlib.sha256((evidence / "manifest.json").read_bytes()).hexdigest()
    assert expected_hash in (out / "report.html").read_text(encoding="utf-8")


def test_report_command_explains_a_missing_findings_file(tmp_path):
    result = CliRunner().invoke(cli, ["report", "--findings", str(tmp_path / "nope.json")])
    assert result.exit_code != 0
    assert "nist171 assess" in result.output


def test_version_flag():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "nist171, version" in result.output


def test_run_all_script_is_ascii_only():
    """Windows PowerShell 5.1 reads BOM-less UTF-8 as ANSI; non-ASCII would corrupt it."""
    script = Path(__file__).resolve().parents[1] / "run-all.ps1"
    script.read_bytes().decode("ascii")
