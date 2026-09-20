"""IAM evidence collection.

IAM is where most of the Access Control and Identification and Authentication evidence
lives: who the users are, whether they have MFA, how old their access keys are, what the
password policy requires, and who holds administrator rights.

Every call here is read-only and covered by the AWS managed ``SecurityAudit`` policy.
"""

from __future__ import annotations

import csv
import io
import json
import time
import urllib.parse
from typing import Any

from botocore.exceptions import ClientError

from nist171.collectors.base import ACCESS_DENIED_CODES, Collector, error_code
from nist171.models import Evidence

ADMIN_POLICY_NAME = "AdministratorAccess"

#: The credential report is generated asynchronously; AWS usually has it within seconds.
CREDENTIAL_REPORT_MAX_ATTEMPTS = 10
CREDENTIAL_REPORT_POLL_SECONDS = 2.0

#: Codes meaning "the report is not ready yet", as opposed to a real failure.
_REPORT_PENDING_CODES = frozenset({"ReportNotPresent", "ReportInProgress", "ReportExpired"})


def _normalize_policy_document(document: Any) -> Any:
    """Return an IAM policy document as a dict.

    botocore normally URL-decodes and parses these for us, but not on every path, so
    accept a string too rather than handing the checks two different shapes.
    """
    if isinstance(document, str):
        return json.loads(urllib.parse.unquote(document))
    return document


class IAMCollector(Collector):
    """Collects IAM users, MFA devices, credential report, policies and password policy."""

    name = "iam"

    def collect(self) -> dict[str, Evidence]:
        iam = self.session.client("iam")
        evidence: dict[str, Evidence] = {}

        evidence["users"] = self._guard(
            "aws:iam:list_users", "iam:ListUsers", lambda: self._list_users(iam)
        )
        usernames = [
            u["UserName"] for u in evidence["users"].raw if isinstance(u, dict) and "UserName" in u
        ] if isinstance(evidence["users"].raw, list) else []

        evidence["mfa_devices"] = self._guard(
            "aws:iam:list_mfa_devices",
            "iam:ListMFADevices",
            lambda: self._mfa_devices(iam, usernames),
        )
        evidence["credential_report"] = self._guard(
            "aws:iam:get_credential_report",
            "iam:GenerateCredentialReport",
            lambda: self._credential_report(iam),
        )
        evidence["policies"] = self._guard(
            "aws:iam:list_policies", "iam:ListPolicies", lambda: self._policies(iam)
        )
        evidence["attached_admin"] = self._guard(
            "aws:iam:list_attached_policies",
            "iam:ListAttachedUserPolicies",
            lambda: self._attached_admin(iam),
        )
        # No password policy is a legitimate state of an AWS account -- and a finding for
        # 3.5.2 -- so NoSuchEntity becomes None rather than an exception.
        evidence["password_policy"] = self._guard(
            "aws:iam:get_account_password_policy",
            "iam:GetAccountPasswordPolicy",
            lambda: iam.get_account_password_policy()["PasswordPolicy"],
            none_on=("NoSuchEntity",),
        )
        return evidence

    # -- individual collections ---------------------------------------------------------

    def _list_users(self, iam: Any) -> list[dict[str, Any]]:
        users: list[dict[str, Any]] = []
        for page in iam.get_paginator("list_users").paginate():
            users.extend(page.get("Users", []))
        return users

    def _mfa_devices(self, iam: Any, usernames: list[str]) -> dict[str, list[dict[str, Any]]]:
        return {
            username: iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            for username in usernames
        }

    def _credential_report(self, iam: Any) -> list[dict[str, str]] | dict[str, Any]:
        """Request the credential report, wait for it, and parse it into rows.

        The report is a CSV covering every user plus the root account (the row where
        ``user`` is ``<root_account>``). It is the only place AWS exposes some facts we
        need -- notably whether the root account has MFA and when each access key was
        last used.
        """
        iam.generate_credential_report()

        for attempt in range(1, CREDENTIAL_REPORT_MAX_ATTEMPTS + 1):
            try:
                response = iam.get_credential_report()
            except ClientError as exc:
                if error_code(exc) not in _REPORT_PENDING_CODES:
                    raise
            else:
                content = response["Content"]
                if isinstance(content, bytes):
                    content = content.decode("utf-8")
                return list(csv.DictReader(io.StringIO(content)))

            if attempt < CREDENTIAL_REPORT_MAX_ATTEMPTS:
                time.sleep(CREDENTIAL_REPORT_POLL_SECONDS)

        # Recorded rather than raised: the rest of the evidence is still worth having,
        # and the checks that need this will report ERROR instead of a false PASS.
        return {
            "error": "ReportNotReady",
            "operation": "iam:GetCredentialReport",
            "attempts": CREDENTIAL_REPORT_MAX_ATTEMPTS,
        }

    def _policies(self, iam: Any) -> list[dict[str, Any]]:
        """Customer-managed policies with their active document.

        ``Scope="Local"`` excludes the hundreds of AWS-managed policies. Only policies
        this account wrote are interesting -- an overly permissive one is the account
        owner's doing.
        """
        policies: list[dict[str, Any]] = []
        for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                entry: dict[str, Any] = {"policy": policy, "document": None}
                try:
                    version = iam.get_policy_version(
                        PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
                    )
                    entry["document"] = _normalize_policy_document(
                        version["PolicyVersion"]["Document"]
                    )
                except ClientError as exc:
                    if error_code(exc) not in ACCESS_DENIED_CODES:
                        raise
                    entry["document_error"] = {
                        "error": "AccessDenied",
                        "operation": "iam:GetPolicyVersion",
                    }
                policies.append(entry)
        return policies

    def _attached_admin(self, iam: Any) -> dict[str, dict[str, list[dict[str, Any]]]]:
        """Principals with AdministratorAccess attached directly.

        Users and roles are kept apart on purpose. A role holding AdministratorAccess is
        normal practice -- it is assumed temporarily and the assumption is logged. A user
        holding it permanently is what 3.1.5 (least privilege) is about.
        """
        users: dict[str, list[dict[str, Any]]] = {}
        for page in iam.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                name = user["UserName"]
                attached = iam.list_attached_user_policies(UserName=name).get(
                    "AttachedPolicies", []
                )
                admin = [p for p in attached if p.get("PolicyName") == ADMIN_POLICY_NAME]
                if admin:
                    users[name] = admin

        roles: dict[str, list[dict[str, Any]]] = {}
        for page in iam.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                name = role["RoleName"]
                attached = iam.list_attached_role_policies(RoleName=name).get(
                    "AttachedPolicies", []
                )
                admin = [p for p in attached if p.get("PolicyName") == ADMIN_POLICY_NAME]
                if admin:
                    roles[name] = admin

        return {"users": users, "roles": roles}
