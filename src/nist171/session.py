"""Building the boto3 Session.

One function, in one place, so there is exactly one answer to "which credentials is this
tool using?" -- which matters when the whole point of the design is that the scanner runs
with read-only keys.
"""

from __future__ import annotations

import os

import boto3

DEFAULT_REGION = "us-east-1"


def make_session(profile: str | None = None, region: str = DEFAULT_REGION) -> boto3.Session:
    """Return a boto3 Session for the given profile and region.

    Args:
        profile: Named profile from ``~/.aws/credentials``, e.g. ``nist-scanner``. When
            None, falls back to the ``AWS_PROFILE`` environment variable, and then to
            boto3's default credential chain.
        region: AWS region. IAM is global, but a region must still be set for the
            regional services (EC2, S3, KMS, CloudTrail) collected later.

    The tool never takes an access key or secret as an argument, and never reads the
    credentials file itself. Credentials stay in ``~/.aws/credentials``, outside the
    project folder, and boto3 is the only thing that touches them.
    """
    profile = profile or os.environ.get("AWS_PROFILE") or None
    return boto3.Session(profile_name=profile, region_name=region or DEFAULT_REGION)
