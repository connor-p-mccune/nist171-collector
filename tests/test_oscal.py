"""Tests for OSCAL assessment-results output.

The central test validates every generated document against the official NIST OSCAL 1.1.3
JSON schema, vendored in tests/fixtures/oscal/. "Valid OSCAL" is therefore a claim this
suite proves on every run, not one it assumes.

The JSON schema cannot check references between parts of a document, so separate tests
confirm that every finding's observation, every subject's inventory item, and the
import-ap link all resolve.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import jsonschema
import pytest
from click.testing import CliRunner

from nist171.cli import cli
from nist171.models import Evidence, Finding, Verdict
from nist171.reporting.oscal import (
    OSCAL_VERSION,
    TOKEN_RE,
    build_assessment_results,
    control_token,
    objective_token,
)
from nist171.scoring.sprs import compute_score

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "oscal" / "oscal_assessment-results_schema.json"
MANIFEST_HASH = "a" * 64
COLLECTED = "2026-09-21T21:48:40+00:00"


@pytest.fixture(scope="module")
def validator() -> jsonschema.Draft7Validator:
    """The official OSCAL schema, with \\p{L}/\\p{N} rewritten for Python's re module."""
    raw = SCHEMA_PATH.read_text(encoding="utf-8")
    schema = json.loads(raw.replace(r"\\p{L}", r"[^\\W\\d_]").replace(r"\\p{N}", r"\\d"))
    jsonschema.Draft7Validator.check_schema(schema)
    return jsonschema.Draft7Validator(schema)


def evidence(source: str) -> Evidence:
    return Evidence(
        source=source,
        collected_at=datetime.fromisoformat(COLLECTED),
        collector_version="0.1.0",
        raw={"source": source},
    )


def f(cid: str, verdict: Verdict, **kw) -> Finding:
    return Finding(
        control_id=cid,
        objective_id=kw.pop("objective_id", f"{cid}[a]"),
        check_name=kw.pop("name", f"check_{cid.replace('.', '_')}"),
        verdict=verdict,
        summary=kw.pop("summary", f"Summary for {cid}."),
        affected_resources=kw.pop("affected", []),
        remediation=kw.pop("remediation", f"Fix {cid}."),
        evidence=kw.pop("evidence", []),
        deduction_override=kw.pop("override", None),
    )


def payload(findings: list[Finding]) -> dict:
    return {
        "tool_version": "0.1.0",
        "assessed_at": "2026-09-21T22:00:00+00:00",
        "evidence_dir": "evidence/20260921T214840Z",
        "account_id": "123456789012",
        "region": "us-east-1",
        "collected_at": COLLECTED,
        "families": ["AC", "AU", "IA"],
        "score": compute_score(findings).to_dict(),
        "findings": [x.to_dict() for x in findings],
    }


MANIFEST = {
    "files": [
        {"name": "iam.json", "sha256": "c" * 64},
        {"name": "ec2.json", "sha256": "d" * 64},
    ]
}


@pytest.fixture
def sample() -> list[Finding]:
    return [
        f("3.1.1", Verdict.PASS, evidence=[evidence("aws:iam:get_credential_report")]),
        f("3.1.2", Verdict.FAIL, name="iam_no_wildcard_admin_policies",
          affected=["nist171-test-overly-permissive"],
          evidence=[evidence("aws:iam:list_policies")]),
        f("3.1.12", Verdict.FAIL, name="sg_no_unrestricted_admin_ingress", objective_id="3.1.12[c]",
          affected=["sg-0abc123"], evidence=[evidence("aws:ec2:describe_security_groups")]),
        f("3.1.4", Verdict.MANUAL, name="separation_of_duties_manual"),
        f("3.5.3", Verdict.FAIL, name="mfa_privileged_users", objective_id="3.5.3[b]", override=3,
          affected=["nist-admin", "nist171-test-user"]),
        f("3.5.7", Verdict.FAIL, name="password_complexity", objective_id="3.5.7[c]",
          affected=["account"]),
        f("3.5.4", Verdict.MANUAL, name="replay_resistant_auth_manual", objective_id="3.5.4"),
    ]


@pytest.fixture
def doc(sample) -> dict:
    return build_assessment_results(payload(sample), manifest=MANIFEST, manifest_hash=MANIFEST_HASH)


def result_of(document: dict) -> dict:
    return document["assessment-results"]["results"][0]


# =======================================================================================
# Required by the build spec
# =======================================================================================


def test_required_top_level_fields_exist(doc):
    ar = doc["assessment-results"]
    for key in ("uuid", "metadata", "import-ap", "results"):
        assert key in ar, key
    meta = ar["metadata"]
    for key in ("title", "last-modified", "version", "oscal-version", "roles", "parties"):
        assert key in meta, key
    assert meta["oscal-version"] == OSCAL_VERSION == "1.1.3"
    assert meta["roles"] == [{"id": "assessor", "title": "Automated Assessment Tool"}]
    assert "123456789012" in meta["title"]
    result = result_of(doc)
    required = ("uuid", "title", "description", "start", "end", "reviewed-controls")
    for key in (*required, "observations"):
        assert key in result, key


def test_every_finding_references_a_real_observation(doc):
    result = result_of(doc)
    observation_ids = {o["uuid"] for o in result["observations"]}
    assert result["findings"], "the sample has failures, so there must be findings"
    for finding in result["findings"]:
        for ref in finding["related-observations"]:
            assert ref["observation-uuid"] in observation_ids


def test_output_is_json_that_round_trips(doc):
    text = json.dumps(doc, indent=2, ensure_ascii=False)
    assert json.loads(text) == doc


# =======================================================================================
# Validity against the official schema
# =======================================================================================


def test_validates_against_the_official_oscal_1_1_3_schema(doc, validator):
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, "\n".join(
        f"{'/'.join(map(str, e.path))}: {e.message}" for e in errors[:10]
    )


def test_validates_with_no_findings_and_no_manifest(validator):
    document = build_assessment_results(payload([f("3.1.1", Verdict.PASS)]))
    assert not list(validator.iter_errors(document))
    assert "findings" not in result_of(document)


def test_validates_when_nothing_could_be_assessed(validator):
    document = build_assessment_results(payload([f("3.1.4", Verdict.MANUAL)]))
    assert not list(validator.iter_errors(document))


def test_schema_rejects_the_raw_nist_identifiers(doc, validator):
    """Why the token mapping exists: '3.1.1' is not a valid OSCAL control-id."""
    broken = json.loads(json.dumps(doc))
    broken["assessment-results"]["results"][0]["reviewed-controls"]["control-selections"][0][
        "include-controls"
    ][0]["control-id"] = "3.1.1"
    assert list(validator.iter_errors(broken))


# =======================================================================================
# Identifiers
# =======================================================================================


@pytest.mark.parametrize(
    "objective, control, expected",
    [
        ("3.1.1[d]", "3.1.1", "sp800-171_3.1.1_obj.d"),
        ("3.1.12[c]", "3.1.12", "sp800-171_3.1.12_obj.c"),
        ("3.5.4", "3.5.4", "sp800-171_3.5.4_obj"),
        (None, "3.1.3", "sp800-171_3.1.3_obj"),
    ],
)
def test_objective_tokens(objective, control, expected):
    assert objective_token(objective, control) == expected
    assert TOKEN_RE.match(expected)


def test_control_tokens_are_valid_oscal_tokens():
    for cid in ("3.1.1", "3.1.22", "3.5.11"):
        assert TOKEN_RE.match(control_token(cid))
    assert not TOKEN_RE.match("3.1.1")
    assert not TOKEN_RE.match("3.1.1[d]")


def test_same_evidence_produces_identical_documents(sample):
    a = build_assessment_results(payload(sample), manifest=MANIFEST, manifest_hash=MANIFEST_HASH)
    b = build_assessment_results(payload(sample), manifest=MANIFEST, manifest_hash=MANIFEST_HASH)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_different_evidence_produces_different_ids(sample):
    a = build_assessment_results(payload(sample), manifest_hash="a" * 64)
    b = build_assessment_results(payload(sample), manifest_hash="f" * 64)
    assert a["assessment-results"]["uuid"] != b["assessment-results"]["uuid"]
    obs_a = {o["uuid"] for o in result_of(a)["observations"]}
    obs_b = {o["uuid"] for o in result_of(b)["observations"]}
    assert not obs_a & obs_b


def test_resources_keep_the_same_uuid_across_assessments(sample):
    """Same bucket, different month: same inventory UUID, so runs can be compared."""
    a = build_assessment_results(payload(sample), manifest_hash="a" * 64)
    b = build_assessment_results(payload(sample), manifest_hash="f" * 64)
    def by_asset(document: dict) -> dict[str, str]:
        items = result_of(document)["local-definitions"]["inventory-items"]
        return {i["props"][0]["value"]: i["uuid"] for i in items}

    assert by_asset(a) == by_asset(b)


def test_uuids_are_unique_within_a_document(doc):
    seen: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "uuid":
                    seen.append(value)
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(doc)
    assert len(seen) == len(set(seen))


# =======================================================================================
# Content and references
# =======================================================================================


def test_one_observation_per_finding_and_one_oscal_finding_per_fail(sample, doc):
    result = result_of(doc)
    assert len(result["observations"]) == len(sample)
    assert len(result["findings"]) == sum(1 for x in sample if x.verdict is Verdict.FAIL)


def test_methods_distinguish_automated_from_manual(doc):
    by_title = {o["title"]: o for o in result_of(doc)["observations"]}
    assert by_title["iam_no_wildcard_admin_policies"]["methods"] == ["TEST"]
    assert by_title["separation_of_duties_manual"]["methods"] == ["EXAMINE"]


def test_findings_target_objectives_as_not_satisfied(doc):
    for finding in result_of(doc)["findings"]:
        target = finding["target"]
        assert target["type"] == "objective-id"
        assert target["status"]["state"] == "not-satisfied"
        assert TOKEN_RE.match(target["target-id"])
    titles = {f["title"] for f in result_of(doc)["findings"]}
    assert "3.1.2 not implemented" in titles


def test_reviewed_controls_list_only_assessed_requirements(doc):
    included = {
        c["control-id"]
        for c in result_of(doc)["reviewed-controls"]["control-selections"][0]["include-controls"]
    }
    assert control_token("3.1.2") in included
    assert control_token("3.1.4") not in included  # MANUAL: never assessed
    assert control_token("3.5.4") not in included


def test_not_assessed_requirements_are_named_in_remarks(doc):
    remarks = result_of(doc)["remarks"]
    assert "3.1.4" in remarks and "3.5.4" in remarks


def test_every_subject_resolves_to_an_inventory_item(doc):
    result = result_of(doc)
    inventory = {i["uuid"] for i in result["local-definitions"]["inventory-items"]}
    subjects = [s for o in result["observations"] for s in o.get("subjects", [])]
    assert subjects
    for subject in subjects:
        assert subject["type"] == "inventory-item"
        assert subject["subject-uuid"] in inventory


def test_import_ap_resolves_to_a_back_matter_resource(doc):
    ar = doc["assessment-results"]
    target = ar["import-ap"]["href"].removeprefix("#")
    assert target in {r["uuid"] for r in ar["back-matter"]["resources"]}


def test_evidence_files_carry_native_sha256_hashes(doc):
    resources = doc["assessment-results"]["back-matter"]["resources"]
    hashed = {
        r["rlinks"][0]["href"]: r["rlinks"][0]["hashes"][0]
        for r in resources
        if r.get("rlinks")
    }
    assert hashed["evidence/20260921T214840Z/manifest.json"] == {
        "algorithm": "SHA-256",
        "value": MANIFEST_HASH,
    }
    assert hashed["evidence/20260921T214840Z/iam.json"]["value"] == "c" * 64


def test_relevant_evidence_points_at_the_file_and_item_hash(doc):
    observations = result_of(doc)["observations"]
    obs = next(o for o in observations if o["title"] == "iam_no_wildcard_admin_policies")
    href = obs["relevant-evidence"][0]["href"]
    assert href.startswith("evidence/20260921T214840Z/iam.json#")
    assert len(href.split("#")[1]) == 64
    assert obs["relevant-evidence"][0]["description"] == "aws:iam:list_policies"


def test_windows_paths_become_forward_slashes(sample):
    data = payload(sample)
    data["evidence_dir"] = "evidence\\20260921T214840Z"
    document = build_assessment_results(data, manifest=MANIFEST, manifest_hash=MANIFEST_HASH)
    text = json.dumps(document)
    assert "\\\\" not in text


def test_score_travels_as_properties(doc):
    props = {p["name"]: p["value"] for p in result_of(doc)["props"]}
    assert props["sprs-max-score"] == "110"
    assert "sprs-score" in props
    assert props["scoring-methodology"].endswith("v1.2.1")


# =======================================================================================
# report --format oscal
# =======================================================================================


def test_report_command_writes_oscal(tmp_path, sample, validator):
    evidence_dir = tmp_path / "evidence" / "run"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "manifest.json").write_text(json.dumps(MANIFEST))
    data = payload(sample)
    data["evidence_dir"] = str(evidence_dir)
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(data))

    out = tmp_path / "output"
    result = CliRunner().invoke(
        cli, ["report", "--findings", str(findings_path), "--format", "oscal", "--out", str(out)]
    )
    assert result.exit_code == 0, result.output
    path = out / "oscal-assessment-results.json"
    assert f"Wrote {path}" in result.output
    written = json.loads(path.read_text(encoding="utf-8"))
    assert not list(validator.iter_errors(written))
