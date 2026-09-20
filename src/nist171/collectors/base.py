"""Base class shared by every collector.

A collector asks AWS questions and writes the answers down. It makes no judgments: it
does not decide whether a password policy is strong enough, only that this is the policy
AWS reported at this moment. That separation is what lets the same evidence be re-assessed
later, and what lets checks be tested without an AWS account.

Two rules every collector follows:

1. Every answer is wrapped in an :class:`~nist171.models.Evidence` object, so it carries a
   timestamp, a source and a hash.
2. A permission failure is recorded, not raised. A scanner that dies on the first
   AccessDenied is useless against a least-privilege role, and "we could not look" is
   itself a finding an assessor needs to see.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from nist171.models import Evidence

VERSION = "0.1.0"
"""Collector schema version, stamped onto every piece of evidence.

Deliberately separate from the package version in ``nist171.__init__``. This says which
collection logic produced a given record, so evidence gathered a year ago can be read
correctly even after the collectors have changed shape.
"""

ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",  # EC2's spelling
        "AuthorizationError",
    }
)
"""Error codes that all mean the same thing: the credentials are not allowed to look."""


def error_code(exc: ClientError) -> str:
    """Pull the AWS error code (e.g. ``"NoSuchEntity"``) out of a ClientError."""
    return str(exc.response.get("Error", {}).get("Code", ""))


class Collector(ABC):
    """Gathers evidence from one AWS service.

    Args:
        session: A configured boto3 Session. The collector makes clients from it rather
            than creating its own, so credentials and region are decided in exactly one
            place and tests can hand in a session pointed at a mock.
    """

    #: Short name used for this collector's evidence file, e.g. ``iam`` -> ``iam.json``.
    name: str = "collector"

    def __init__(self, session: boto3.Session) -> None:
        self.session = session

    @abstractmethod
    def collect(self) -> dict[str, Evidence]:
        """Gather this service's evidence, keyed by a short stable name."""
        raise NotImplementedError

    # -- helpers ------------------------------------------------------------------------

    def _evidence(self, source: str, raw: Any) -> Evidence:
        """Wrap a raw AWS response as Evidence, stamped with the current UTC time."""
        return Evidence(
            source=source,
            collected_at=datetime.now(UTC),
            collector_version=VERSION,
            raw=raw,
        )

    def _denied(self, source: str, operation: str) -> Evidence:
        """Evidence recording that the credentials were not permitted to make a call."""
        return self._evidence(source, {"error": "AccessDenied", "operation": operation})

    def _guard(
        self,
        source: str,
        operation: str,
        call: Callable[[], Any],
        *,
        none_on: Iterable[str] = (),
    ) -> Evidence:
        """Run ``call`` and wrap the result, converting expected failures into evidence.

        Args:
            source: Evidence source string, e.g. ``"aws:iam:list_users"``.
            operation: IAM-style operation name used in an AccessDenied record, e.g.
                ``"iam:ListUsers"``.
            call: Zero-argument callable that performs the AWS work.
            none_on: Error codes meaning "this thing does not exist", which is a finding
                rather than a failure -- the raw value becomes ``None``.

        Anything not listed is re-raised. An unexpected error should stop the run loudly
        rather than producing evidence that quietly says nothing is wrong.
        """
        try:
            return self._evidence(source, call())
        except ClientError as exc:
            code = error_code(exc)
            if code in set(none_on):
                return self._evidence(source, None)
            if code in ACCESS_DENIED_CODES:
                return self._denied(source, operation)
            raise
