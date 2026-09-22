"""Identification and Authentication (3.5.x) checks.

Seven automated checks and five that no API can answer.

This family carries the only partial-credit rule in the DoD methodology. Missing MFA on
privileged accounts (3.5.3) costs five points when there is no MFA anywhere, and three
when MFA exists for some accounts but not all -- so the check sets
``deduction_override`` rather than letting the scoring engine apply the flat catalog value.
"""

from __future__ import annotations

from typing import Any

from nist171.checks.common import (
    Check,
    EvidenceMap,
    as_list,
    error_reason,
    finding,
    get_evidence,
    is_error,
    raw_value,
    used,
)
from nist171.models import Finding, Verdict

ROOT_USER = "<root_account>"

#: NIST SP 800-63B and the DoD baseline both land here for password length.
MIN_PASSWORD_LENGTH = 14

#: Password history depth expected by the CIS AWS Foundations Benchmark.
MIN_REUSE_PREVENTION = 24

#: Password policy fields that must be switched on, with readable names for the summary.
COMPLEXITY_FLAGS = {
    "RequireUppercaseCharacters": "uppercase letters",
    "RequireLowercaseCharacters": "lowercase letters",
    "RequireNumbers": "numbers",
    "RequireSymbols": "symbols",
}


def _grants_iam_wildcard(document: Any) -> bool:
    """True if a policy document hands out iam:* -- the ability to grant oneself more."""
    if not isinstance(document, dict):
        return False
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        for action in as_list(statement.get("Action")):
            text = str(action).lower()
            if text in {"*", "iam:*"} or text.startswith("iam:*"):
                return True
    return False


# =======================================================================================
# 3.5.1 -- Identify system users and processes
# =======================================================================================


def iam_users_identified(evidence: EvidenceMap) -> Finding:
    """Confirm the account's identities can be enumerated at all.

    A deliberately weak check, and the summary says so. Being able to list users is not
    the same as knowing each one corresponds to a real, authorized person -- that is what
    3.5.1's other objectives ask, and nothing in AWS answers them.
    """
    control, objective, name = "3.5.1", "3.5.1[a]", "iam_users_identified"
    users = raw_value(evidence, "iam", "users")
    cited = used(get_evidence(evidence, "iam", "users"))

    if not isinstance(users, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not enumerate IAM users: {error_reason(users)}.",
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"{len(users)} IAM user(s) are enumerable and uniquely named. This is a weak check: "
        "it confirms identities exist and can be listed, not that each belongs to an "
        "authorized individual or that the list is complete for the system in scope. "
        "Federated users who sign in through an identity provider have no IAM user and do "
        "not appear here at all.",
        evidence=cited,
    )


# =======================================================================================
# 3.5.2 -- Authenticate identities
# =======================================================================================


def password_policy_exists(evidence: EvidenceMap) -> Finding:
    """An account password policy must exist. Whether it is any good is 3.5.7 and 3.5.8."""
    control, objective, name = "3.5.2", "3.5.2[b]", "password_policy_exists"
    item = get_evidence(evidence, "iam", "password_policy")
    cited = used(item)

    if item is None:
        return finding(
            control, objective, name, Verdict.ERROR,
            "Could not evaluate the password policy: evidence missing.",
            evidence=cited,
        )
    policy = item.raw
    if is_error(policy):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate the password policy: {error_reason(policy)}.",
            evidence=cited,
        )

    if policy is None:
        return finding(
            control, objective, name, Verdict.FAIL,
            "This AWS account has no IAM password policy. Console passwords are therefore "
            "subject only to the AWS minimum, and the organization has set no requirement "
            "of its own.",
            affected_resources=["account"],
            remediation=(
                "Create an account password policy in IAM > Account settings. Set a minimum "
                "length of at least 14, require all four character classes, and set password "
                "reuse prevention to 24 -- that satisfies 3.5.2, 3.5.7 and 3.5.8 together."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        "An IAM account password policy is configured. Its strength is assessed separately "
        "under 3.5.7 and 3.5.8.",
        evidence=cited,
    )


# =======================================================================================
# 3.5.3 -- Multifactor authentication
# =======================================================================================


def mfa_privileged_users(evidence: EvidenceMap) -> Finding:
    """Privileged accounts must have MFA. Carries the methodology's partial-credit rule."""
    control, objective, name = "3.5.3", "3.5.3[b]", "mfa_privileged_users"
    report = raw_value(evidence, "iam", "credential_report")
    attached = raw_value(evidence, "iam", "attached_admin")
    policies = raw_value(evidence, "iam", "policies")
    cited = used(
        get_evidence(evidence, "iam", "credential_report"),
        get_evidence(evidence, "iam", "attached_admin"),
        get_evidence(evidence, "iam", "policies"),
    )

    if not isinstance(report, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate privileged MFA: {error_reason(report)}.",
            evidence=cited,
        )
    if not isinstance(attached, dict) or "users" not in attached:
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not determine which users are privileged: {error_reason(attached)}.",
            evidence=cited,
        )

    privileged = set(attached.get("users", {}))
    mfa_by_user = {r.get("user", ""): r.get("mfa_active") == "true" for r in report}

    # Root is privileged by definition.
    if ROOT_USER in mfa_by_user:
        privileged.add(ROOT_USER)

    without_mfa = sorted(u for u in privileged if not mfa_by_user.get(u, False))
    with_mfa = sorted(u for u in privileged if mfa_by_user.get(u, False))

    # A customer policy granting iam:* confers privilege too, but the collector records
    # only AdministratorAccess attachments, so we cannot tell who holds such a policy.
    # Name the policies so an assessor can follow up by hand rather than assume coverage.
    iam_wildcard_policies: list[str] = []
    if isinstance(policies, list):
        iam_wildcard_policies = [
            entry.get("policy", {}).get("PolicyName", "unnamed")
            for entry in policies
            if isinstance(entry, dict) and _grants_iam_wildcard(entry.get("document"))
        ]
    caveat = ""
    if iam_wildcard_policies:
        caveat = (
            f" Separately, {len(iam_wildcard_policies)} customer-managed policy(ies) grant "
            f"iam:* ({', '.join(iam_wildcard_policies)}); anyone holding one is effectively "
            "privileged, but this scan records only direct AdministratorAccess attachments "
            "and cannot list who they are. Check those by hand."
        )

    if not privileged:
        return finding(
            control, objective, name, Verdict.PASS,
            f"No IAM user holds AdministratorAccess directly, so there are no privileged "
            f"accounts requiring MFA under this check.{caveat}",
            evidence=cited,
        )

    if without_mfa:
        # DoD Assessment Methodology v1.2.1 partial credit: 5 points when MFA is absent
        # entirely, 3 when it exists somewhere but not everywhere it is required.
        mfa_anywhere = any(mfa_by_user.values())
        if mfa_anywhere:
            deduction, state = 3, "MFA is in use on some accounts but not on all privileged ones"
        else:
            deduction, state = 5, "no account in this environment has MFA at all"

        return finding(
            control, objective, name, Verdict.FAIL,
            f"{len(without_mfa)} privileged account(s) have no MFA: "
            f"{', '.join(without_mfa)}. Partial credit applies: {state}, so the methodology "
            f"deducts {deduction} points rather than the full 5."
            + (f" Privileged accounts that do have MFA: {', '.join(with_mfa)}." if with_mfa else "")
            + caveat,
            affected_resources=without_mfa,
            remediation=(
                "Assign an MFA device to every account with administrative rights, starting "
                "with root. Then consider removing standing admin from user accounts "
                "altogether and using an assumable role, which is what 3.1.5 asks for and "
                "shrinks this finding at the same time."
            ),
            evidence=cited,
            deduction_override=deduction,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"All {len(privileged)} privileged account(s) have MFA enabled: "
        f"{', '.join(with_mfa)}.{caveat}",
        evidence=cited,
    )


def mfa_all_users(evidence: EvidenceMap) -> Finding:
    """Every user who can sign in to the console needs MFA, privileged or not."""
    control, objective, name = "3.5.3", "3.5.3[d]", "mfa_all_users"
    report = raw_value(evidence, "iam", "credential_report")
    cited = used(get_evidence(evidence, "iam", "credential_report"))

    if not isinstance(report, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate console MFA coverage: {error_reason(report)}.",
            evidence=cited,
        )

    console_users = [
        r for r in report
        if r.get("password_enabled") == "true" or r.get("user") == ROOT_USER
    ]
    without_mfa = sorted(
        r.get("user", "") for r in console_users if r.get("mfa_active") != "true"
    )

    if without_mfa:
        return finding(
            control, objective, name, Verdict.FAIL,
            f"{len(without_mfa)} of {len(console_users)} account(s) with console sign-in "
            f"have no MFA: {', '.join(without_mfa)}. 3.5.3 requires multifactor "
            "authentication for network access to non-privileged accounts as well as "
            "privileged ones.",
            affected_resources=without_mfa,
            remediation=(
                "Assign an MFA device to each account, or remove console access from "
                "accounts that only need programmatic access."
            ),
            evidence=cited,
        )

    if not console_users:
        return finding(
            control, objective, name, Verdict.PASS,
            "No account has console sign-in enabled, so no console MFA is required. Note "
            "this passes by absence rather than by configuration -- enabling a console "
            "password for any user would change the result.",
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"All {len(console_users)} account(s) with console sign-in have MFA enabled.",
        evidence=cited,
    )


# =======================================================================================
# 3.5.7 / 3.5.8 -- Password complexity and reuse
# =======================================================================================


def password_complexity(evidence: EvidenceMap) -> Finding:
    """Minimum length and character-class requirements."""
    control, objective, name = "3.5.7", "3.5.7[c]", "password_complexity"
    item = get_evidence(evidence, "iam", "password_policy")
    cited = used(item)

    if item is None:
        return finding(
            control, objective, name, Verdict.ERROR,
            "Could not evaluate password complexity: evidence missing.",
            evidence=cited,
        )
    policy = item.raw
    if is_error(policy):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate password complexity: {error_reason(policy)}.",
            evidence=cited,
        )
    if policy is None:
        return finding(
            control, objective, name, Verdict.FAIL,
            "No IAM password policy exists, so no complexity requirement is enforced.",
            affected_resources=["account"],
            remediation=(
                f"Create an account password policy requiring at least "
                f"{MIN_PASSWORD_LENGTH} characters and all four character classes."
            ),
            evidence=cited,
        )

    shortfalls: list[str] = []
    length = policy.get("MinimumPasswordLength", 0)
    if not isinstance(length, int) or length < MIN_PASSWORD_LENGTH:
        shortfalls.append(f"minimum length is {length}, needs {MIN_PASSWORD_LENGTH}")
    for flag, label in COMPLEXITY_FLAGS.items():
        if policy.get(flag) is not True:
            shortfalls.append(f"{label} not required")

    if shortfalls:
        return finding(
            control, objective, name, Verdict.FAIL,
            f"The IAM password policy falls short on {len(shortfalls)} point(s): "
            f"{'; '.join(shortfalls)}.",
            affected_resources=["account"],
            remediation=(
                f"In IAM > Account settings, set the minimum password length to "
                f"{MIN_PASSWORD_LENGTH} or more and tick all four character-type "
                "requirements. Worth knowing: NIST SP 800-63B now favours length and "
                "screening against breached-password lists over composition rules, but "
                "800-171 and the DoD baseline still expect the character classes, so set "
                "both."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"The IAM password policy requires at least {length} characters and all four "
        "character classes.",
        evidence=cited,
    )


def password_reuse(evidence: EvidenceMap) -> Finding:
    """Password history depth."""
    control, objective, name = "3.5.8", "3.5.8[b]", "password_reuse"
    item = get_evidence(evidence, "iam", "password_policy")
    cited = used(item)

    if item is None:
        return finding(
            control, objective, name, Verdict.ERROR,
            "Could not evaluate password reuse prevention: evidence missing.",
            evidence=cited,
        )
    policy = item.raw
    if is_error(policy):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate password reuse prevention: {error_reason(policy)}.",
            evidence=cited,
        )
    if policy is None:
        return finding(
            control, objective, name, Verdict.FAIL,
            "No IAM password policy exists, so previous passwords may be reused freely.",
            affected_resources=["account"],
            remediation=(
                f"Create an account password policy with password reuse prevention set to "
                f"{MIN_REUSE_PREVENTION}."
            ),
            evidence=cited,
        )

    depth = policy.get("PasswordReusePrevention")
    if not isinstance(depth, int) or depth < MIN_REUSE_PREVENTION:
        actual = "not set" if depth is None else str(depth)
        return finding(
            control, objective, name, Verdict.FAIL,
            f"Password reuse prevention is {actual}, below the expected "
            f"{MIN_REUSE_PREVENTION}. A short history lets a user cycle back to a password "
            "they have used before, which defeats the point of rotating it.",
            affected_resources=["account"],
            remediation=(
                f"Set 'Prevent password reuse' to {MIN_REUSE_PREVENTION} in IAM > Account "
                "settings."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"Password reuse prevention is set to {depth}, meeting the expected "
        f"{MIN_REUSE_PREVENTION}.",
        evidence=cited,
    )


# =======================================================================================
# 3.5.10 -- Store and transmit only cryptographically-protected passwords
# =======================================================================================


def no_root_access_keys(evidence: EvidenceMap) -> Finding:
    """The root account must have no access keys."""
    control, objective, name = "3.5.10", "3.5.10[a]", "no_root_access_keys"
    report = raw_value(evidence, "iam", "credential_report")
    cited = used(get_evidence(evidence, "iam", "credential_report"))

    if not isinstance(report, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate root access keys: {error_reason(report)}.",
            evidence=cited,
        )

    root = next((r for r in report if r.get("user") == ROOT_USER), None)
    if root is None:
        return finding(
            control, objective, name, Verdict.ERROR,
            "The credential report contains no <root_account> row, so root access keys "
            "could not be checked. Real AWS always includes this row; its absence usually "
            "means the report came from a mock or was truncated.",
            evidence=cited,
        )

    active = [
        f"access_key_{slot}"
        for slot in (1, 2)
        if root.get(f"access_key_{slot}_active") == "true"
    ]

    if active:
        return finding(
            control, objective, name, Verdict.FAIL,
            f"The root account has {len(active)} active access key(s): {', '.join(active)}. "
            "Root access keys cannot be scoped, cannot be restricted by policy, and grant "
            "unlimited permanent access to the entire account. AWS advises deleting them "
            "outright.",
            affected_resources=[f"{ROOT_USER}:{k}" for k in active],
            remediation=(
                "Sign in as root, go to Security credentials, and delete the access keys. "
                "Anything that was using them should use an IAM role or a scoped IAM user "
                "instead. This is one of the highest-value single fixes in an AWS account."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        "The root account has no active access keys.",
        evidence=cited,
    )


# =======================================================================================
# Requirements no AWS API can answer
# =======================================================================================


def _manual(control: str, objective: str, name: str, summary: str) -> Finding:
    return finding(control, objective, name, Verdict.MANUAL, summary)


def replay_resistant_auth_manual(evidence: EvidenceMap) -> Finding:
    """3.5.4 -- replay-resistant authentication for network access."""
    return _manual(
        "3.5.4", "3.5.4", "replay_resistant_auth_manual",
        "Requires human assessment, though AWS satisfies most of it by design. Every AWS "
        "API request is signed with Signature Version 4, which binds the request to a "
        "timestamp and a derived key, so a captured request cannot be replayed later. "
        "Console sign-in with a time-based MFA code is likewise replay-resistant. What an "
        "assessor still has to confirm is that any other authentication path in scope -- "
        "VPN, SSH, an application login -- is also replay-resistant. Nothing in the AWS "
        "control plane reports on those. Note this requirement has a single unlettered "
        "objective in SP 800-171A rather than the usual [a], [b], [c].",
    )


def identifier_reuse_manual(evidence: EvidenceMap) -> Finding:
    """3.5.5 -- prevent reuse of identifiers for a defined period."""
    return _manual(
        "3.5.5", "3.5.5[a]", "identifier_reuse_manual",
        "Requires human assessment. The organization must define how long a username may "
        "not be reissued after it is retired, and then honour it. IAM enforces that names "
        "are unique among *current* users, but keeps no record of deleted ones, so AWS "
        "cannot tell you whether a name was previously held by someone else. Evidence "
        "would be the defined period and an offboarding record showing it is followed.",
    )


def identifier_disable_manual(evidence: EvidenceMap) -> Finding:
    """3.5.6 -- disable identifiers after a defined period of inactivity."""
    return _manual(
        "3.5.6", "3.5.6[a]", "identifier_disable_manual",
        "Requires human assessment. The organization must define an inactivity period and "
        "disable accounts that exceed it. The credential report does expose last-used "
        "dates, so the enforcement half could be partly automated once a period is defined "
        "-- but the period is a policy decision, and an account may be legitimately dormant. "
        "Evidence would be the defined period and records of accounts disabled under it.",
    )


def temporary_password_manual(evidence: EvidenceMap) -> Finding:
    """3.5.9 -- temporary passwords must be changed immediately."""
    return _manual(
        "3.5.9", "3.5.9", "temporary_password_manual",
        "Requires human assessment. IAM can force a password change at next sign-in, but "
        "that flag is set per user at creation time and is not exposed in any list "
        "operation this scanner can read, so there is no way to confirm it was used. The "
        "process question -- how temporary credentials are issued and communicated -- is "
        "outside AWS entirely. Note this requirement has a single unlettered objective in "
        "SP 800-171A.",
    )


def obscure_feedback_manual(evidence: EvidenceMap) -> Finding:
    """3.5.11 -- obscure feedback of authentication information."""
    return _manual(
        "3.5.11", "3.5.11", "obscure_feedback_manual",
        "Requires human assessment. This is about what a user sees while authenticating -- "
        "a password masked as it is typed, an error message that does not reveal whether "
        "the username exists. The AWS console does this, but the requirement covers every "
        "authentication interface in scope, including applications the organization builds. "
        "Confirming it means looking at those interfaces, not at an API. Note this "
        "requirement has a single unlettered objective in SP 800-171A.",
    )


# =======================================================================================
# Registry
# =======================================================================================

#: Every Identification and Authentication check, in the order they are reported.
CHECKS: list[Check] = [
    iam_users_identified,
    password_policy_exists,
    mfa_privileged_users,
    mfa_all_users,
    password_complexity,
    password_reuse,
    no_root_access_keys,
    replay_resistant_auth_manual,
    identifier_reuse_manual,
    identifier_disable_manual,
    temporary_password_manual,
    obscure_feedback_manual,
]
