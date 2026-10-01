"""Tests for writing evidence to disk and reading it back.

The property everything else depends on: evidence read back from disk is the same evidence
that was collected, and any change to it in between is caught rather than assessed.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nist171.evidence_io import (
    MANIFEST_NAME,
    EvidenceIntegrityError,
    file_sha256,
    latest_evidence_dir,
    load_evidence,
    load_manifest,
    verify_manifest,
    write_evidence_file,
)
from nist171.models import Evidence

COLLECTED = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)


def item(source: str, raw: object) -> Evidence:
    return Evidence(source=source, collected_at=COLLECTED, collector_version="0.1.0", raw=raw)


IAM_ITEMS = {
    "users": item("aws:iam:list_users", [{"UserName": "alice"}, {"UserName": "bob"}]),
    "password_policy": item("aws:iam:get_account_password_policy", None),
    # boto3 returns datetime objects; they must survive the trip to disk with the same hash.
    "credential_report": item(
        "aws:iam:get_credential_report",
        [{"user": "alice", "created": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)}],
    ),
}

S3_ITEMS = {
    "buckets": item("aws:s3:list_buckets", ["bucket-a", "bucket-b"]),
}


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """An evidence run folder with two collector files and a manifest, as collect writes."""
    folder = tmp_path / "20260901T120000Z"
    folder.mkdir()
    files = []
    for name, items in (("iam", IAM_ITEMS), ("s3", S3_ITEMS)):
        path = write_evidence_file(folder / f"{name}.json", items)
        files.append({"name": path.name, "sha256": file_sha256(path)})
    (folder / MANIFEST_NAME).write_text(
        json.dumps({"account_id": "111122223333", "files": files}), encoding="utf-8"
    )
    return folder


# --------------------------------------------------------------------------------------
# Round trip
# --------------------------------------------------------------------------------------


def test_written_evidence_reads_back_with_matching_hashes(run_dir: Path):
    loaded = load_evidence(run_dir)

    assert set(loaded) == {"iam", "s3"}
    for collector, originals in (("iam", IAM_ITEMS), ("s3", S3_ITEMS)):
        assert set(loaded[collector]) == set(originals)
        for key, original in originals.items():
            assert loaded[collector][key].sha256 == original.sha256, f"{collector}/{key}"


def test_provenance_survives_the_round_trip(run_dir: Path):
    users = load_evidence(run_dir)["iam"]["users"]

    assert users.source == "aws:iam:list_users"
    assert users.collected_at == COLLECTED
    assert users.collector_version == "0.1.0"
    assert users.raw == [{"UserName": "alice"}, {"UserName": "bob"}]


def test_none_is_preserved_rather_than_dropped(run_dir: Path):
    # "No password policy" is a finding; losing the key on the way to disk would turn it
    # into "evidence missing", which is a different verdict.
    loaded = load_evidence(run_dir)["iam"]
    assert "password_policy" in loaded
    assert loaded["password_policy"].raw is None


def test_datetimes_keep_their_hash_after_becoming_strings(run_dir: Path):
    report = load_evidence(run_dir)["iam"]["credential_report"]
    assert isinstance(report.raw[0]["created"], str)
    assert report.sha256 == IAM_ITEMS["credential_report"].sha256


def test_file_records_the_hash_and_key_of_every_item(run_dir: Path):
    entries = json.loads((run_dir / "iam.json").read_text(encoding="utf-8"))
    assert [e["key"] for e in entries] == list(IAM_ITEMS)
    for entry in entries:
        assert entry["sha256"] == IAM_ITEMS[entry["key"]].sha256


def test_writing_is_deterministic(tmp_path: Path):
    first = write_evidence_file(tmp_path / "a.json", IAM_ITEMS)
    second = write_evidence_file(tmp_path / "b.json", IAM_ITEMS)
    assert first.read_bytes() == second.read_bytes()


def test_files_use_lf_line_endings_on_every_platform(run_dir: Path):
    data = (run_dir / "iam.json").read_bytes()
    assert b"\n" in data
    assert b"\r" not in data


# --------------------------------------------------------------------------------------
# Tampering
# --------------------------------------------------------------------------------------


def tamper(path: Path) -> None:
    """Change one value in an evidence file while leaving its stored hash alone."""
    entries = json.loads(path.read_text(encoding="utf-8"))
    entries[0]["raw"] = [{"UserName": "mallory"}]
    path.write_text(json.dumps(entries, indent=2), encoding="utf-8")


def test_an_edited_value_is_rejected_on_load(run_dir: Path):
    tamper(run_dir / "iam.json")
    with pytest.raises(EvidenceIntegrityError, match="iam.json:users hash mismatch"):
        load_evidence(run_dir)


def test_verification_can_be_turned_off_deliberately(run_dir: Path):
    tamper(run_dir / "iam.json")
    loaded = load_evidence(run_dir, verify=False)
    assert loaded["iam"]["users"].raw == [{"UserName": "mallory"}]


def test_intact_run_passes_manifest_verification(run_dir: Path):
    assert verify_manifest(run_dir) == []


def test_manifest_catches_a_modified_file(run_dir: Path):
    tamper(run_dir / "iam.json")
    assert verify_manifest(run_dir) == ["iam.json: file hash does not match the manifest"]


def test_manifest_catches_a_missing_file(run_dir: Path):
    (run_dir / "s3.json").unlink()
    assert verify_manifest(run_dir) == ["s3.json: listed in manifest but missing from the folder"]


def test_manifest_catches_an_added_file(run_dir: Path):
    write_evidence_file(run_dir / "extra.json", S3_ITEMS)
    assert verify_manifest(run_dir) == [
        "extra.json: present in the folder but not listed in the manifest"
    ]


def test_manifest_verification_requires_a_manifest(tmp_path: Path):
    write_evidence_file(tmp_path / "iam.json", IAM_ITEMS)
    assert verify_manifest(tmp_path) == [f"No {MANIFEST_NAME} in {tmp_path}"]


# --------------------------------------------------------------------------------------
# Finding and reading runs
# --------------------------------------------------------------------------------------


def test_manifest_is_read(run_dir: Path):
    assert load_manifest(run_dir)["account_id"] == "111122223333"


def test_missing_manifest_reads_as_empty(tmp_path: Path):
    assert load_manifest(tmp_path) == {}


def test_latest_run_is_the_newest_timestamp(tmp_path: Path):
    for stamp in ("20260901T120000Z", "20260915T080000Z", "20260910T235959Z"):
        (tmp_path / stamp).mkdir()
    assert latest_evidence_dir(tmp_path).name == "20260915T080000Z"


def test_latest_run_errors_when_there_is_no_evidence_directory(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="nist171 collect"):
        latest_evidence_dir(tmp_path / "evidence")


def test_latest_run_errors_when_the_directory_is_empty(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="No evidence runs"):
        latest_evidence_dir(tmp_path)


def test_loading_a_missing_folder_errors(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="not found"):
        load_evidence(tmp_path / "nope")


def test_loading_a_folder_with_only_a_manifest_errors(tmp_path: Path):
    (tmp_path / MANIFEST_NAME).write_text("{}", encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="No evidence files"):
        load_evidence(tmp_path)


def test_a_file_that_is_not_a_list_is_rejected(tmp_path: Path):
    (tmp_path / "iam.json").write_text('{"users": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="should contain a JSON list"):
        load_evidence(tmp_path)
