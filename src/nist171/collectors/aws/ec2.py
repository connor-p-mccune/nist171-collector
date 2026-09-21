"""EC2 evidence collection.

Security groups are the network boundary, which is what 3.1.12 (monitor and control
remote access) is assessed against in a cloud account. Default EBS encryption is kept
alongside them as supporting evidence.
"""

from __future__ import annotations

from typing import Any

from nist171.collectors.base import Collector
from nist171.models import Evidence


class EC2Collector(Collector):
    """Collects security groups and the account's default EBS encryption setting."""

    name = "ec2"

    def collect(self) -> dict[str, Evidence]:
        client = self.session.client("ec2")
        evidence: dict[str, Evidence] = {}

        # Stored whole, not projected: the checks need the full IpPermissions structure
        # (FromPort, ToPort, IpProtocol, IpRanges, Ipv6Ranges) and dropping a field here
        # would silently narrow what the rules can see.
        evidence["security_groups"] = self._guard(
            "aws:ec2:describe_security_groups",
            "ec2:DescribeSecurityGroups",
            lambda: self._security_groups(client),
        )
        evidence["ebs_encryption_default"] = self._guard(
            "aws:ec2:get_ebs_encryption_by_default",
            "ec2:GetEbsEncryptionByDefault",
            lambda: client.get_ebs_encryption_by_default()["EbsEncryptionByDefault"],
        )
        return evidence

    def _security_groups(self, client: Any) -> list[dict[str, Any]]:
        groups: list[dict[str, Any]] = []
        for page in client.get_paginator("describe_security_groups").paginate():
            groups.extend(page.get("SecurityGroups", []))
        return groups
