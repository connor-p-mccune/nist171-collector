"""KMS evidence collection.

Supporting evidence for the encryption-related requirements: which keys exist, whether the
customer manages them or AWS does, and whether they are enabled.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from nist171.collectors.base import ACCESS_DENIED_CODES, Collector, error_code
from nist171.models import Evidence

#: Fields kept from KeyMetadata. KeyId and Arn are identifiers -- a finding has to be able
#: to name the key it is about -- and the other three describe how the key is managed.
KEY_FIELDS = ("KeyId", "Arn", "KeyManager", "KeyState", "Origin")


class KMSCollector(Collector):
    """Collects KMS key metadata."""

    name = "kms"

    def collect(self) -> dict[str, Evidence]:
        client = self.session.client("kms")
        return {
            "keys": self._guard(
                "aws:kms:describe_key", "kms:ListKeys", lambda: self._keys(client)
            )
        }

    def _keys(self, client: Any) -> list[dict[str, Any]]:
        keys: list[dict[str, Any]] = []
        for page in client.get_paginator("list_keys").paginate():
            for entry in page.get("Keys", []):
                key_id = entry.get("KeyId")
                try:
                    metadata = client.describe_key(KeyId=key_id)["KeyMetadata"]
                    keys.append({field: metadata.get(field) for field in KEY_FIELDS})
                except ClientError as exc:
                    # AWS-managed keys in some states cannot be described by an audit
                    # role. Record the gap against the key id and carry on.
                    code = error_code(exc)
                    keys.append(
                        {
                            "KeyId": key_id,
                            "error": "AccessDenied" if code in ACCESS_DENIED_CODES else code,
                            "operation": "kms:DescribeKey",
                        }
                    )
        return keys
