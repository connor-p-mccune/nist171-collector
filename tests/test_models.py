"""Tests for the Evidence and Finding data shapes.

The hash tests are the important ones. Everything the tool claims about tamper-evidence
rests on two properties: the same response always hashes to the same value, and any change
to the response changes the hash.
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone

import pytest

from nist171.models import Evidence, Finding, Verdict

COLLECTED_AT = datetime(2026, 9, 19, 14, 2, 31, tzinfo=UTC)

SAMPLE_RAW = {
    "Users": [
        {"UserName": "nist-scanner", "UserId": "AIDAEXAMPLE1", "Arn": "arn:aws:iam::123:user/a"},
        {"UserName": "nist171-test-user", "UserId": "AIDAEXAMPLE2", "Arn": "arn:aws:iam::123:u/b"},
    ],
    "IsTruncated": False,
}


def make_evidence(raw: object = None, source: str = "aws:iam:list_users") -> Evidence:
    return Evidence(
        source=source,
        collected_at=COLLECTED_AT,
        collector_version="0.1.0",
        raw=SAMPLE_RAW if raw is None else raw,
    )


# --------------------------------------------------------------------------------------
# Hashing: determinism and sensitivity
# --------------------------------------------------------------------------------------


def test_same_raw_data_always_produces_the_same_hash():
    assert make_evidence().sha256 == make_evidence().sha256


def test_hash_is_stable_across_separately_built_equal_structures():
    # Same data, built independently -- not the same object in memory.
    a = Evidence("aws:iam:x", COLLECTED_AT, "0.1.0", {"b": 2, "a": [1, {"z": None}]})
    b = Evidence("aws:iam:x", COLLECTED_AT, "0.1.0", {"a": [1, {"z": None}], "b": 2})
    assert a.sha256 == b.sha256


def test_hash_ignores_dict_key_order():
    ordered = Evidence("aws:iam:x", COLLECTED_AT, "0.1.0", {"alpha": 1, "beta": 2})
    shuffled = Evidence("aws:iam:x", COLLECTED_AT, "0.1.0", {"beta": 2, "alpha": 1})
    assert ordered.sha256 == shuffled.sha256


def test_changing_one_character_in_raw_changes_the_hash():
    original = make_evidence()
    tampered_raw = json.loads(json.dumps(SAMPLE_RAW))
    tampered_raw["Users"][0]["UserName"] = "nist-scanner "  # one trailing space
    tampered = make_evidence(raw=tampered_raw)
    assert tampered.sha256 != original.sha256


def test_changing_a_boolean_changes_the_hash():
    flipped = json.loads(json.dumps(SAMPLE_RAW))
    flipped["IsTruncated"] = True
    assert make_evidence(raw=flipped).sha256 != make_evidence().sha256


def test_removing_an_item_changes_the_hash():
    shorter = json.loads(json.dumps(SAMPLE_RAW))
    shorter["Users"].pop()
    assert make_evidence(raw=shorter).sha256 != make_evidence().sha256


def test_hash_does_not_depend_on_source_or_timestamp():
    # The hash covers the AWS response only. Two collectors seeing the same response at
    # different times agree on the hash -- that is what makes it comparable across runs.
    later = Evidence("aws:iam:other", COLLECTED_AT + timedelta(days=5), "9.9.9", SAMPLE_RAW)
    assert later.sha256 == make_evidence().sha256


def test_hash_is_64_hex_characters():
    digest = make_evidence().sha256
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_canonical_is_compact_and_sorted():
    ev = Evidence("aws:iam:x", COLLECTED_AT, "0.1.0", {"b": 1, "a": 2})
    assert ev.canonical == '{"a":2,"b":1}'


def test_canonical_handles_datetimes_that_json_cannot():
    # boto3 returns datetime objects inside responses; default=str keeps them hashable
    # instead of raising TypeError.
    ev = Evidence("aws:iam:x", COLLECTED_AT, "0.1.0", {"CreateDate": COLLECTED_AT})
    assert "2026-09-19" in ev.canonical
    assert ev.sha256


# --------------------------------------------------------------------------------------
# Evidence: immutability and validation
# --------------------------------------------------------------------------------------


def test_evidence_is_frozen():
    ev = make_evidence()
    with pytest.raises(FrozenInstanceError):
        ev.source = "aws:iam:tampered"  # type: ignore[misc]


def test_evidence_raw_cannot_be_swapped_out():
    ev = make_evidence()
    with pytest.raises(FrozenInstanceError):
        ev.raw = {"Users": []}  # type: ignore[misc]


def test_evidence_rejects_a_naive_timestamp():
    with pytest.raises(ValueError, match="timezone-aware"):
        Evidence("aws:iam:x", datetime(2026, 9, 19, 14, 2, 31), "0.1.0", {})


def test_evidence_accepts_a_non_utc_timezone():
    eastern = timezone(timedelta(hours=-4))
    ev = Evidence("aws:iam:x", datetime(2026, 9, 19, 10, 2, 31, tzinfo=eastern), "0.1.0", {})
    assert ev.collected_at.utcoffset() is not None


def test_evidence_to_dict_includes_the_hash():
    d = make_evidence().to_dict()
    assert d["sha256"] == make_evidence().sha256
    assert set(d) == {"source", "collected_at", "collector_version", "sha256", "raw"}


def test_evidence_to_dict_is_json_serializable():
    d = make_evidence().to_dict()
    reloaded = json.loads(json.dumps(d, default=str))
    assert reloaded["source"] == "aws:iam:list_users"
    assert reloaded["collected_at"] == "2026-09-19T14:02:31+00:00"
    assert reloaded["raw"] == SAMPLE_RAW


def test_hash_survives_a_json_round_trip():
    # Write evidence, read it back, recompute: the hash must still match. This is the
    # property that lets someone verify a report months after the scan.
    original = make_evidence()
    on_disk = json.loads(json.dumps(original.to_dict(), default=str))
    rebuilt = Evidence(
        source=on_disk["source"],
        collected_at=datetime.fromisoformat(on_disk["collected_at"]),
        collector_version=on_disk["collector_version"],
        raw=on_disk["raw"],
    )
    assert rebuilt.sha256 == on_disk["sha256"] == original.sha256


# --------------------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------------------


def test_finding_defaults_are_empty_and_not_shared():
    a = Finding("3.1.1", None, "check_a", Verdict.PASS, "fine")
    b = Finding("3.1.2", None, "check_b", Verdict.PASS, "fine")
    a.affected_resources.append("user/alice")
    assert b.affected_resources == []
    assert a.remediation == ""
    assert b.evidence == []


def test_finding_to_dict_round_trips():
    finding = Finding(
        control_id="3.5.2",
        objective_id="3.5.2[b]",
        check_name="password_policy_exists",
        verdict=Verdict.FAIL,
        summary="No IAM account password policy is set.",
        affected_resources=["account:123456789012"],
        remediation="Create an IAM account password policy requiring 14+ characters.",
        evidence=[make_evidence(raw={"PasswordPolicy": None}, source="aws:iam:get_policy")],
    )

    as_dict = finding.to_dict()
    reloaded = json.loads(json.dumps(as_dict, default=str))

    assert reloaded == as_dict
    assert reloaded["control_id"] == "3.5.2"
    assert reloaded["objective_id"] == "3.5.2[b]"
    assert reloaded["check_name"] == "password_policy_exists"
    assert reloaded["verdict"] == "FAIL"
    assert reloaded["affected_resources"] == ["account:123456789012"]
    assert reloaded["remediation"].startswith("Create an IAM account password policy")
    assert len(reloaded["evidence"]) == 1
    assert reloaded["evidence"][0]["sha256"] == finding.evidence[0].sha256

    # Rebuilding from the dict gives back an equal Finding.
    rebuilt = Finding(
        control_id=reloaded["control_id"],
        objective_id=reloaded["objective_id"],
        check_name=reloaded["check_name"],
        verdict=Verdict(reloaded["verdict"]),
        summary=reloaded["summary"],
        affected_resources=reloaded["affected_resources"],
        remediation=reloaded["remediation"],
        evidence=finding.evidence,
    )
    assert rebuilt == finding


def test_finding_to_dict_keeps_verdict_as_a_plain_string():
    d = Finding("3.1.1", None, "c", Verdict.MANUAL, "human review required").to_dict()
    assert d["verdict"] == "MANUAL"
    assert isinstance(d["verdict"], str)


def test_finding_to_dict_copies_affected_resources():
    finding = Finding("3.1.1", None, "c", Verdict.FAIL, "bad", affected_resources=["sg-123"])
    d = finding.to_dict()
    finding.affected_resources.append("sg-456")
    assert d["affected_resources"] == ["sg-123"]


# --------------------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------------------


def test_verdict_has_exactly_five_values():
    assert {v.value for v in Verdict} == {"PASS", "FAIL", "NOT_APPLICABLE", "MANUAL", "ERROR"}


def test_verdict_round_trips_through_its_string_value():
    for verdict in Verdict:
        assert Verdict(verdict.value) is verdict
