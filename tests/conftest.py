"""Shared test setup.

The single most important thing here is that no test can reach real AWS. Fake credentials
are forced into the environment and the real credentials file is pointed somewhere that
does not exist, so a test that forgets ``@mock_aws`` fails to authenticate instead of
quietly scanning a live account.
"""

from __future__ import annotations

import pytest

FAKE_CREDENTIALS = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SECURITY_TOKEN": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_REGION": "us-east-1",
}


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory):
    """Force fake AWS credentials and block access to the real ones."""
    for key, value in FAKE_CREDENTIALS.items():
        monkeypatch.setenv(key, value)

    # A named profile in the developer's shell must not leak into a test run.
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    # Point boto3 at credential and config files that do not exist.
    nowhere = tmp_path_factory.mktemp("no-aws")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(nowhere / "credentials"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(nowhere / "config"))

    # moto 5 does not populate the AWS-managed policies (AdministratorAccess,
    # SecurityAudit, ...) unless asked, because loading them is slow. Without this,
    # attaching arn:aws:iam::aws:policy/AdministratorAccess fails with NoSuchEntity and
    # the least-privilege tests cannot be set up at all.
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
    yield
