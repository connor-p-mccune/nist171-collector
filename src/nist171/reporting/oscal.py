"""OSCAL 1.1.3 assessment-results output.

OSCAL is NIST's machine-readable format for security and compliance documents. This module
turns ``findings.json`` into an ``assessment-results`` document that validates against the
official OSCAL 1.1.3 JSON schema (``tests/fixtures/oscal/`` holds a copy, and the tests
validate every build against it).

Where the build specification and the schema disagree, the schema wins. Each case is
listed here and in ``docs/oscal.md``:

* **Control and objective IDs are OSCAL tokens**, which must begin with a letter or an
  underscore. ``3.1.1`` does not, and ``3.1.1[d]`` also contains brackets. They are
  written as ``sp800-171_3.1.1`` and ``sp800-171_3.1.1_obj.d`` -- the objective form
  mirrors NIST's own OSCAL catalogs (``ac-2_obj.a``). The original identifiers are kept in
  titles and properties so nothing is lost.
* **Observation methods use the SP 800-53A vocabulary**: ``TEST`` for automated checks,
  ``EXAMINE`` for requirements needing human review. ``AUTOMATED`` is not one of the
  standard methods; how a method was carried out is recorded in a property instead.
* **AWS resources are inventory items**, declared in the result's ``local-definitions``.
  In OSCAL a subject of type ``resource`` means a back-matter document, not a cloud
  asset, and a subject UUID should resolve to something in the document.
* **The placeholder assessment plan is a real back-matter resource**, so ``import-ap``'s
  ``#uuid`` reference resolves instead of dangling.

UUIDs are deterministic. See :class:`_Ids`.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nist171 import __version__

OSCAL_VERSION = "1.1.3"

#: Root of every UUID this tool generates. Fixed forever: changing it would change every
#: identifier in every document ever produced.
PROJECT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "urn:nist171-collector")

#: Namespace for properties this tool defines. OSCAL requires one for any property name
#: that is not part of the OSCAL core vocabulary.
PROP_NS = "urn:nist171-collector:oscal"

CONTROL_PREFIX = "sp800-171_"

#: OSCAL TokenDatatype, with \p{L} and \p{N} spelled the way Python's re understands.
TOKEN_RE = re.compile(r"^([^\W\d_]|_)([^\W\d_]|\d|[.\-_])*$")

_OBJECTIVE_RE = re.compile(r"^(?P<control>\d+(?:\.\d+)+)(?:\[(?P<letter>[0-9a-z]+)\])?$")


# =======================================================================================
# Identifiers
# =======================================================================================


def control_token(control_id: str) -> str:
    """``3.1.1`` -> ``sp800-171_3.1.1``: a valid OSCAL token naming the requirement."""
    return f"{CONTROL_PREFIX}{control_id}"


def objective_token(objective_id: str | None, control_id: str) -> str:
    """``3.1.1[d]`` -> ``sp800-171_3.1.1_obj.d``; a bare ``3.5.4`` -> ``sp800-171_3.5.4_obj``."""
    match = _OBJECTIVE_RE.match(objective_id or "")
    if not match:
        return f"{control_token(control_id)}_obj"
    base = f"{control_token(match['control'])}_obj"
    return f"{base}.{match['letter']}" if match["letter"] else base


class _Ids:
    """Deterministic UUIDs, in two scopes.

    *Run-scoped* identifiers are derived from a fingerprint of the evidence set -- the
    manifest's SHA-256. Regenerating from the same evidence reproduces them exactly, and
    two different assessments can never collide. Documents, results, observations and
    findings are run-scoped: an observation made in September is a different observation
    from one made in October, even if nothing changed.

    *Stable* identifiers are derived from what a thing is, not when it was seen. The same
    S3 bucket in the same account gets the same inventory-item UUID in every assessment,
    which is what lets two documents be compared resource by resource.
    """

    def __init__(self, fingerprint: str) -> None:
        self.run_namespace = uuid.uuid5(PROJECT_NAMESPACE, f"run:{fingerprint}")

    def run(self, *parts: str) -> str:
        return str(uuid.uuid5(self.run_namespace, "|".join(parts)))

    @staticmethod
    def stable(*parts: str) -> str:
        return str(uuid.uuid5(PROJECT_NAMESPACE, "|".join(parts)))


def evidence_fingerprint(data: dict[str, Any], manifest_hash: str | None) -> str:
    """What identifies an evidence set. The manifest hash when there is one."""
    if manifest_hash:
        return f"manifest:{manifest_hash}"
    return f"run:{data.get('account_id')}|{data.get('collected_at')}|{data.get('evidence_dir')}"


# =======================================================================================
# Helpers
# =======================================================================================


def _timestamp(value: Any, fallback: str) -> str:
    """An ISO 8601 timestamp with a timezone, as OSCAL requires."""
    text = str(value or fallback)
    moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.isoformat()


def _prop(name: str, value: Any) -> dict[str, str]:
    return {"name": name, "ns": PROP_NS, "value": str(value)}


def _uri_path(*parts: str) -> str:
    """Join path pieces as a URI reference -- forward slashes even on Windows."""
    return "/".join(p.replace("\\", "/").strip("/") for p in parts if p)


def _collector_file(source: str) -> str:
    """``aws:iam:list_users`` -> ``iam.json``, the file that evidence item was written to."""
    pieces = source.split(":")
    return f"{pieces[1]}.json" if len(pieces) > 1 and pieces[1] else "unknown.json"


def _clean(text: str, fallback: str) -> str:
    """OSCAL string fields may not be empty or begin or end with whitespace."""
    cleaned = " ".join(str(text or "").split())
    return cleaned or fallback


# =======================================================================================
# Document
# =======================================================================================


def build_assessment_results(
    data: dict[str, Any],
    *,
    manifest: dict[str, Any] | None = None,
    manifest_hash: str | None = None,
) -> dict[str, Any]:
    """Build an OSCAL 1.1.3 assessment-results document from a findings.json payload.

    Args:
        data: The parsed findings.json.
        manifest: The evidence run's manifest.json, if available. Its per-file hashes
            become back-matter resources.
        manifest_hash: SHA-256 of manifest.json. Seeds the deterministic UUIDs; without
            it they are seeded from the account and collection time instead.
    """
    ids = _Ids(evidence_fingerprint(data, manifest_hash))
    score = data["score"]
    account_id = str(data.get("account_id") or "unknown")
    evidence_dir = str(data.get("evidence_dir") or "evidence")
    assessed_at = _timestamp(data.get("assessed_at"), datetime.now(UTC).isoformat())
    collected_at = _timestamp(data.get("collected_at"), assessed_at)
    families = data.get("families") or ["AC", "AU", "IA"]

    party_uuid = _Ids.stable("party", "nist171-collector")
    plan_uuid = ids.run("assessment-plan-placeholder")

    inventory: dict[str, dict[str, Any]] = {}
    observations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for found in data.get("findings", []):
        control_id = str(found["control_id"])
        check_name = str(found["check_name"])
        verdict = str(found["verdict"])
        manual = verdict == "MANUAL"

        subjects = []
        for resource in found.get("affected_resources", []):
            item = inventory.setdefault(resource, _inventory_item(resource, account_id))
            subjects.append(
                {"subject-uuid": item["uuid"], "type": "inventory-item", "title": resource}
            )

        evidence = found.get("evidence", [])
        observation_uuid = ids.run("observation", control_id, check_name)
        observation: dict[str, Any] = {
            "uuid": observation_uuid,
            "title": check_name,
            "description": _clean(found.get("summary", ""), f"{check_name} result"),
            "props": [
                _prop("control-id", control_id),
                _prop("verdict", verdict),
                _prop("assessment-mode", "manual" if manual else "automated"),
            ]
            + ([_prop("objective-id", found["objective_id"])] if found.get("objective_id") else []),
            "methods": ["EXAMINE"] if manual else ["TEST"],
            "types": ["control-objective"],
            "collected": _timestamp(
                min((e["collected_at"] for e in evidence if e.get("collected_at")), default=None),
                collected_at,
            ),
        }
        if subjects:
            observation["subjects"] = subjects
        if evidence:
            observation["relevant-evidence"] = [
                {
                    "href": _uri_path(
                        evidence_dir, f"{_collector_file(e['source'])}#{e['sha256']}"
                    ),
                    "description": _clean(e.get("source", ""), "evidence item"),
                }
                for e in evidence
                if e.get("sha256")
            ]
        observations.append(observation)

        if verdict == "FAIL":
            findings.append(
                {
                    "uuid": ids.run("finding", control_id, check_name),
                    "title": f"{control_id} not implemented",
                    "description": _clean(
                        found.get("remediation", ""), _clean(found.get("summary", ""), "")
                    ),
                    "props": [_prop("control-id", control_id), _prop("check-name", check_name)],
                    "target": {
                        "type": "objective-id",
                        "target-id": objective_token(found.get("objective_id"), control_id),
                        "status": {"state": "not-satisfied"},
                    },
                    "related-observations": [{"observation-uuid": observation_uuid}],
                }
            )

    result: dict[str, Any] = {
        "uuid": ids.run("result"),
        "title": f"Automated {'/'.join(families)} assessment",
        "description": _clean(score.get("scope_note", ""), "Partial automated assessment."),
        "start": collected_at,
        "end": assessed_at,
        "props": [
            _prop("sprs-score", score.get("score")),
            _prop("sprs-max-score", score.get("max_score", 110)),
            _prop("requirements-assessed", score.get("assessed_count", 0)),
            _prop("conditional-threshold-met", str(score.get("conditional_threshold_met")).lower()),
            _prop("scoring-methodology", "NIST SP 800-171 DoD Assessment Methodology v1.2.1"),
        ],
        "reviewed-controls": _reviewed_controls(score),
        "observations": observations,
    }
    if inventory:
        result["local-definitions"] = {"inventory-items": list(inventory.values())}
    if findings:
        result["findings"] = findings
    not_assessed = score.get("not_assessed", [])
    if not_assessed:
        result["remarks"] = (
            f"{len(not_assessed)} in-scope requirements were not assessed because they need "
            f"human review or could not be evaluated automatically, and are deliberately "
            f"absent from reviewed-controls: {', '.join(not_assessed)}."
        )

    return {
        "assessment-results": {
            "uuid": ids.run("assessment-results"),
            "metadata": {
                "title": f"NIST SP 800-171 Rev 2 Partial Automated Assessment — {account_id}",
                # The assessment time, not the time this file was written: the document's
                # content is fixed by the assessment, so regenerating it is byte-identical.
                "last-modified": assessed_at,
                "version": str(data.get("tool_version") or __version__),
                "oscal-version": OSCAL_VERSION,
                "roles": [{"id": "assessor", "title": "Automated Assessment Tool"}],
                "parties": [
                    {"uuid": party_uuid, "type": "organization", "name": "nist171-collector"}
                ],
                "responsible-parties": [{"role-id": "assessor", "party-uuids": [party_uuid]}],
            },
            "import-ap": {
                "href": f"#{plan_uuid}",
                "remarks": "No formal assessment plan; this is an automated partial assessment.",
            },
            "results": [result],
            "back-matter": {
                "resources": _back_matter(ids, plan_uuid, evidence_dir, manifest, manifest_hash)
            },
        }
    }


def _inventory_item(resource: str, account_id: str) -> dict[str, Any]:
    description = (
        f"The AWS account {account_id} as a whole."
        if resource == "account"
        else f"AWS resource {resource} in account {account_id}."
    )
    return {
        "uuid": _Ids.stable("inventory-item", account_id, resource),
        "description": description,
        "props": [{"name": "asset-id", "value": resource}],
    }


def _reviewed_controls(score: dict[str, Any]) -> dict[str, Any]:
    """Only requirements that were actually assessed. Unassessed ones stay out."""
    assessed = [
        *score.get("implemented", []),
        *[u["control_id"] if isinstance(u, dict) else u[0] for u in score.get("unmet", [])],
        *score.get("na", []),
    ]
    ordered = sorted(set(assessed), key=lambda c: tuple(int(p) for p in c.split(".")))
    if not ordered:
        return {
            "control-selections": [
                {"description": "No requirements could be assessed automatically in this run."}
            ]
        }
    return {
        "control-selections": [
            {"include-controls": [{"control-id": control_token(c)} for c in ordered]}
        ]
    }


def _back_matter(
    ids: _Ids,
    plan_uuid: str,
    evidence_dir: str,
    manifest: dict[str, Any] | None,
    manifest_hash: str | None,
) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = [
        {
            "uuid": plan_uuid,
            "title": "Placeholder assessment plan",
            "description": (
                "No formal OSCAL assessment plan exists for this run. The tool assessed the "
                "AC, AU and IA requirements it can evaluate automatically."
            ),
        }
    ]
    if manifest_hash:
        resources.append(
            {
                "uuid": ids.run("evidence-manifest"),
                "title": "Evidence manifest",
                "description": "Index of every evidence file in this run, with its SHA-256.",
                "rlinks": [
                    {
                        "href": _uri_path(evidence_dir, "manifest.json"),
                        "media-type": "application/json",
                        "hashes": [{"algorithm": "SHA-256", "value": manifest_hash}],
                    }
                ],
            }
        )
    for record in (manifest or {}).get("files", []):
        if not record.get("name") or not record.get("sha256"):
            continue
        resources.append(
            {
                "uuid": ids.run("evidence-file", record["name"]),
                "title": f"Evidence file {record['name']}",
                "description": (
                    f"Raw AWS responses from the {record['name'].removesuffix('.json')} "
                    "collector, one hashed item per API call."
                ),
                "rlinks": [
                    {
                        "href": _uri_path(evidence_dir, record["name"]),
                        "media-type": "application/json",
                        "hashes": [{"algorithm": "SHA-256", "value": record["sha256"]}],
                    }
                ],
            }
        )
    return resources


def write_oscal(path: Path | str, document: dict[str, Any]) -> Path:
    """Write the document as indented UTF-8 JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
