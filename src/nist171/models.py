"""Core data shapes: what the tool records when it looks at something.

Two objects carry everything the rest of the tool works with.

``Evidence`` is one raw answer from AWS, stamped with when it was collected and
fingerprinted so it can be shown to have not changed since. Collectors produce it;
nothing else does.

``Finding`` is one judgment about one requirement, carrying the evidence it was based on.
Checks produce it; the scoring engine, the POA&M and the OSCAL writer all read it.

Keeping these separate is the point of the whole design: evidence is fact, findings are
opinion about that fact, and the opinion can be recomputed from the fact at any time.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    """The outcome of running one check against one requirement.

    Five values rather than two, because "we did not check this" and "we checked this and
    it failed" are different facts and must never be collapsed into each other.
    """

    PASS = "PASS"
    """The check ran and the requirement is met."""

    FAIL = "FAIL"
    """The check ran and the requirement is not met. Deducts points."""

    NOT_APPLICABLE = "NOT_APPLICABLE"
    """The requirement genuinely does not apply to this environment."""

    MANUAL = "MANUAL"
    """No automated check exists. A human assessor must evaluate this requirement."""

    ERROR = "ERROR"
    """The check could not run -- permission denied, API error, malformed evidence."""


@dataclass(frozen=True)
class Evidence:
    """One raw response from AWS, with the provenance needed to defend it later.

    Args:
        source: Where it came from, as ``aws:<service>:<operation>``, e.g.
            ``"aws:iam:list_users"``.
        collected_at: When it was collected. Must be timezone-aware; UTC by convention.
        collector_version: Version of the collector that produced it, so a finding can be
            traced back to the code that gathered its evidence.
        raw: The response itself. Any JSON-able structure.
    """

    source: str
    collected_at: datetime
    collector_version: str
    raw: Any

    def __post_init__(self) -> None:
        # A naive timestamp is ambiguous -- it could be any of 24 moments. Evidence whose
        # collection time cannot be pinned down is not evidence, so refuse it at creation
        # rather than discovering the problem in a report months later.
        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError(
                f"collected_at must be timezone-aware, got naive datetime {self.collected_at!r}. "
                "Use datetime.now(timezone.utc)."
            )

    @property
    def canonical(self) -> str:
        """The raw data as one deterministic JSON string.

        Deterministic is the whole requirement: the same data must produce byte-identical
        output every time, or the hash below is worthless. Hence sorted keys (dict order
        must not matter), no whitespace (formatting must not matter), and ``default=str``
        so values json cannot handle natively -- boto3 hands back ``datetime`` objects --
        become a stable string instead of raising.
        """
        return json.dumps(
            self.raw,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
            ensure_ascii=True,
        )

    @property
    def sha256(self) -> str:
        """SHA-256 of :attr:`canonical`, as lowercase hex.

        Covers the AWS response only -- not the timestamp, source or collector version.
        Those live beside it in :meth:`to_dict`, and the evidence manifest hashes the
        whole file. So this answers exactly one question: is this the same response AWS
        returned, byte for byte?
        """
        return hashlib.sha256(self.canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serializable form, with the hash included so it survives the trip to disk."""
        return {
            "source": self.source,
            "collected_at": self.collected_at.isoformat(),
            "collector_version": self.collector_version,
            "sha256": self.sha256,
            "raw": self.raw,
        }


@dataclass
class Finding:
    """One check's judgment about one requirement.

    Args:
        control_id: The requirement assessed, e.g. ``"3.1.1"``.
        objective_id: The SP 800-171A assessment objective addressed, e.g. ``"3.1.1[d]"``.
            None when the check speaks to the requirement as a whole.
        check_name: Name of the function that produced this, e.g. ``"iam_users_have_mfa"``.
        verdict: The outcome. See :class:`Verdict`.
        summary: One or two plain sentences a non-engineer can act on.
        affected_resources: Identifiers of the specific things at fault -- usernames, ARNs,
            bucket names, security group IDs. Empty on PASS.
        remediation: What to do about it. Required in practice on every FAIL; it becomes
            the POA&M's remediation column.
        evidence: The evidence this judgment rests on.
    """

    control_id: str
    objective_id: str | None
    check_name: str
    verdict: Verdict
    summary: str
    affected_resources: list[str] = field(default_factory=list)
    remediation: str = ""
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serializable form. ``verdict`` becomes its string value, evidence recurses."""
        return {
            "control_id": self.control_id,
            "objective_id": self.objective_id,
            "check_name": self.check_name,
            "verdict": self.verdict.value,
            "summary": self.summary,
            "affected_resources": list(self.affected_resources),
            "remediation": self.remediation,
            "evidence": [e.to_dict() for e in self.evidence],
        }
