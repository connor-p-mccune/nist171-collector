"""CloudTrail evidence collection.

CloudTrail is the audit log. Almost everything in the Audit and Accountability family
(3.3.x) comes down to two questions this collector answers: is a trail actually recording,
and can the recording be shown not to have been altered.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from nist171.collectors.base import ACCESS_DENIED_CODES, Collector, error_code
from nist171.models import Evidence

#: Fields kept from each trail. A projection rather than the whole response, so the
#: evidence file stays readable and the hash is not churned by unrelated AWS additions.
#: ``Name`` is kept beyond the required set because findings need something to name.
TRAIL_FIELDS = (
    "Name",
    "TrailARN",
    "S3BucketName",
    "IsMultiRegionTrail",
    "LogFileValidationEnabled",
    "IncludeGlobalServiceEvents",
    "KmsKeyId",
    "HomeRegion",
)

STATUS_FIELDS = ("IsLogging", "LatestDeliveryTime")


class CloudTrailCollector(Collector):
    """Collects trail configuration and whether each trail is currently logging."""

    name = "cloudtrail"

    def collect(self) -> dict[str, Evidence]:
        client = self.session.client("cloudtrail")
        evidence: dict[str, Evidence] = {}

        evidence["trails"] = self._guard(
            "aws:cloudtrail:describe_trails",
            "cloudtrail:DescribeTrails",
            lambda: self._trails(client),
        )
        trails = evidence["trails"].raw if isinstance(evidence["trails"].raw, list) else []
        arns = [t["TrailARN"] for t in trails if isinstance(t, dict) and t.get("TrailARN")]

        evidence["trail_status"] = self._guard(
            "aws:cloudtrail:get_trail_status",
            "cloudtrail:GetTrailStatus",
            lambda: self._trail_status(client, arns),
        )
        return evidence

    def _trails(self, client: Any) -> list[dict[str, Any]]:
        trail_list = client.describe_trails().get("trailList", [])
        return [{field: trail.get(field) for field in TRAIL_FIELDS} for trail in trail_list]

    def _trail_status(self, client: Any, arns: list[str]) -> dict[str, Any]:
        """Logging status per trail ARN.

        Each trail is probed separately. A multi-region trail shows up as a shadow copy in
        other regions and ``get_trail_status`` refuses those from outside the home region,
        so one failure must not take the rest of the statuses with it.
        """
        statuses: dict[str, Any] = {}
        for arn in arns:
            try:
                status = client.get_trail_status(Name=arn)
                statuses[arn] = {field: status.get(field) for field in STATUS_FIELDS}
            except ClientError as exc:
                code = error_code(exc)
                statuses[arn] = {
                    "error": "AccessDenied" if code in ACCESS_DENIED_CODES else code,
                    "operation": "cloudtrail:GetTrailStatus",
                }
        return statuses
