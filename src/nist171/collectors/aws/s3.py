"""S3 evidence collection.

Five separate settings decide whether a bucket is defensible, and AWS exposes each through
its own API call that raises a different error when the setting was never configured. This
collector turns all of that into one flat per-bucket dict the checks can read.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from botocore.exceptions import ClientError

from nist171.collectors.base import ACCESS_DENIED_CODES, Collector, error_code
from nist171.models import Evidence


class S3Collector(Collector):
    """Collects bucket names and, per bucket, the five settings the checks care about."""

    name = "s3"

    def collect(self) -> dict[str, Evidence]:
        client = self.session.client("s3")
        evidence: dict[str, Evidence] = {}

        evidence["buckets"] = self._guard(
            "aws:s3:list_buckets", "s3:ListAllMyBuckets", lambda: self._bucket_names(client)
        )
        names = evidence["buckets"].raw if isinstance(evidence["buckets"].raw, list) else []

        evidence["bucket_config"] = self._guard(
            "aws:s3:bucket_config",
            "s3:GetBucketConfiguration",
            lambda: {name: self._bucket_config(client, name) for name in names},
        )
        return evidence

    def _bucket_names(self, client: Any) -> list[str]:
        return [b["Name"] for b in client.list_buckets().get("Buckets", [])]

    def _probe(self, operation: str, call: Callable[[], Any], absent: frozenset[str]) -> Any:
        """Run one per-bucket call, turning "never configured" into None.

        Anything else that goes wrong is recorded as an error value rather than raised.
        One unusual bucket -- wrong region, a policy the audit role cannot read -- must not
        cost us the evidence for every other bucket in the account.
        """
        try:
            return call()
        except ClientError as exc:
            code = error_code(exc)
            if code in absent:
                return None
            if code in ACCESS_DENIED_CODES:
                return {"error": "AccessDenied", "operation": operation}
            return {"error": code, "operation": operation}

    def _bucket_config(self, client: Any, bucket: str) -> dict[str, Any]:
        return {
            "public_access_block": self._probe(
                "s3:GetPublicAccessBlock",
                lambda: client.get_public_access_block(Bucket=bucket)[
                    "PublicAccessBlockConfiguration"
                ],
                frozenset({"NoSuchPublicAccessBlockConfiguration"}),
            ),
            "encryption": self._probe(
                "s3:GetEncryptionConfiguration",
                lambda: client.get_bucket_encryption(Bucket=bucket)[
                    "ServerSideEncryptionConfiguration"
                ],
                frozenset({"ServerSideEncryptionConfigurationNotFoundError"}),
            ),
            # Versioning has no "not configured" error: AWS returns a response with no
            # Status key at all, so absence shows up as a missing field rather than a raise.
            "versioning": self._probe(
                "s3:GetBucketVersioning",
                lambda: client.get_bucket_versioning(Bucket=bucket).get("Status"),
                frozenset(),
            ),
            # The policy arrives as a JSON string, not a structure. Parsed here so the
            # checks read statements instead of doing string matching on JSON.
            "policy": self._probe(
                "s3:GetBucketPolicy",
                lambda: json.loads(client.get_bucket_policy(Bucket=bucket)["Policy"]),
                frozenset({"NoSuchBucketPolicy"}),
            ),
            "object_lock": self._probe(
                "s3:GetBucketObjectLockConfiguration",
                lambda: client.get_object_lock_configuration(Bucket=bucket)[
                    "ObjectLockConfiguration"
                ],
                frozenset({"ObjectLockConfigurationNotFoundError"}),
            ),
        }
