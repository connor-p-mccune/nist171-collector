"""Access Control (3.1.x) checks.

Seven automated checks and three that no API can answer. Each takes the loaded evidence
map and returns one Finding.

Objective citations follow the build specification. Two of them are a stretch worth
knowing about before an interview: 3.1.13 is written about remote access sessions rather
than object storage, and 3.1.20 is about connections to external systems -- a public S3
bucket is a reasonable reading of both, but they are interpretations, not literal
readings of the standard.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from nist171.checks.common import (
    Check,
    EvidenceMap,
    as_list,
    days_since,
    error_reason,
    finding,
    get_evidence,
    is_error,
    parse_report_date,
    raw_value,
    used,
)
from nist171.models import Finding, Verdict

#: An access key unused for this long is treated as stale. Not in NIST; this is the
#: widely used industry default, and the summary text says so.
STALE_KEY_DAYS = 90

#: Ports used for remote administration. Open to the internet, any of these is the
#: finding 3.1.12 is about.
ADMIN_PORTS = (22, 3389, 5985, 5986)

WORLD_IPV4 = "0.0.0.0/0"
WORLD_IPV6 = "::/0"

PUBLIC_ACCESS_BLOCK_FLAGS = (
    "BlockPublicAcls",
    "BlockPublicPolicy",
    "IgnorePublicAcls",
    "RestrictPublicBuckets",
)

ROOT_USER = "<root_account>"


# =======================================================================================
# 3.1.1 -- Limit system access to authorized users
# =======================================================================================


def iam_users_have_mfa(evidence: EvidenceMap) -> Finding:
    """Every user who can sign in to the console must have MFA, root included."""
    control, objective, name = "3.1.1", "3.1.1[d]", "iam_users_have_mfa"
    report = raw_value(evidence, "iam", "credential_report")
    cited = used(get_evidence(evidence, "iam", "credential_report"))

    if not isinstance(report, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate console MFA: {error_reason(report)}.",
            evidence=cited,
        )

    without_mfa: list[str] = []
    for row in report:
        user = row.get("user", "")
        has_mfa = row.get("mfa_active") == "true"
        # Root always has a console password, so it is judged on MFA alone.
        can_sign_in = user == ROOT_USER or row.get("password_enabled") == "true"
        if can_sign_in and not has_mfa:
            without_mfa.append(user)

    if without_mfa:
        return finding(
            control, objective, name, Verdict.FAIL,
            f"{len(without_mfa)} account(s) can sign in to the AWS console without "
            f"multi-factor authentication: {', '.join(without_mfa)}.",
            affected_resources=without_mfa,
            remediation=(
                "Enable an MFA device for each account listed. In the AWS console go to "
                "IAM > Users > (user) > Security credentials > Assign MFA device, or for "
                "the root account use IAM > Add MFA for root user. An authenticator app "
                "is free and takes about a minute per account."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        "Every account with console sign-in has multi-factor authentication enabled.",
        evidence=cited,
    )


def iam_no_stale_access_keys(evidence: EvidenceMap) -> Finding:
    """Active access keys that have sat unused long enough to be forgotten."""
    control, objective, name = "3.1.1", "3.1.1[d]", "iam_no_stale_access_keys"
    report = raw_value(evidence, "iam", "credential_report")
    cited = used(get_evidence(evidence, "iam", "credential_report"))

    if not isinstance(report, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate access key age: {error_reason(report)}.",
            evidence=cited,
        )

    now = datetime.now(UTC)
    stale: list[str] = []
    detail: list[str] = []

    for row in report:
        user = row.get("user", "")
        for slot in (1, 2):
            if row.get(f"access_key_{slot}_active") != "true":
                continue

            last_used = parse_report_date(row.get(f"access_key_{slot}_last_used_date"))
            if last_used is not None:
                age = days_since(last_used, now=now)
                if age > STALE_KEY_DAYS:
                    stale.append(f"{user}:access_key_{slot}")
                    detail.append(f"{user} key {slot} last used {age} days ago")
                continue

            # Never used. Judge it on how long it has existed instead.
            rotated = parse_report_date(row.get(f"access_key_{slot}_last_rotated"))
            if rotated is not None and days_since(rotated, now=now) > STALE_KEY_DAYS:
                age = days_since(rotated, now=now)
                stale.append(f"{user}:access_key_{slot}")
                detail.append(f"{user} key {slot} never used, created {age} days ago")

    if stale:
        return finding(
            control, objective, name, Verdict.FAIL,
            f"{len(stale)} active access key(s) unused for more than {STALE_KEY_DAYS} "
            f"days: {'; '.join(detail)}. The {STALE_KEY_DAYS}-day threshold is an "
            "industry convention, not a NIST requirement.",
            affected_resources=stale,
            remediation=(
                "Confirm each key is still needed. If not, deactivate it in IAM > Users > "
                "(user) > Security credentials, wait to confirm nothing breaks, then "
                "delete it. Unused long-lived keys are a common breach path precisely "
                "because nobody notices when they are stolen."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"No active access key has gone unused for more than {STALE_KEY_DAYS} days.",
        evidence=cited,
    )


# =======================================================================================
# 3.1.2 -- Limit access to the types of transactions users may execute
# =======================================================================================


def _wildcard_statements(document: Any) -> list[dict[str, Any]]:
    """Statements that allow any action on every resource in the account.

    A statement counts only when the action carries a wildcard AND the resource is the
    unrestricted ``*``. The specification says "Resource containing *", but a scoped ARN
    such as ``arn:aws:s3:::my-bucket/*`` also contains one and is correct, ordinary
    policy. Flagging those would bury the real finding in false positives, and a scanner
    people learn to ignore is worse than no scanner.
    """
    if not isinstance(document, dict):
        return []

    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    offending: list[dict[str, Any]] = []
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = as_list(statement.get("Action"))
        resources = as_list(statement.get("Resource"))
        if any("*" in str(a) for a in actions) and any(str(r) == "*" for r in resources):
            offending.append(statement)
    return offending


def iam_no_wildcard_admin_policies(evidence: EvidenceMap) -> Finding:
    """Customer-managed policies that grant unrestricted access."""
    control, objective, name = "3.1.2", "3.1.2[b]", "iam_no_wildcard_admin_policies"
    policies = raw_value(evidence, "iam", "policies")
    cited = used(get_evidence(evidence, "iam", "policies"))

    if not isinstance(policies, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate IAM policies: {error_reason(policies)}.",
            evidence=cited,
        )

    offenders: list[str] = []
    for entry in policies:
        if not isinstance(entry, dict):
            continue
        summary = entry.get("policy", {})
        if _wildcard_statements(entry.get("document")):
            offenders.append(summary.get("PolicyName") or summary.get("Arn", "unknown policy"))

    if offenders:
        return finding(
            control, objective, name, Verdict.FAIL,
            f"{len(offenders)} customer-managed policy(ies) allow any action on every "
            f"resource: {', '.join(offenders)}. A policy like this makes every other "
            "access restriction in the account unenforceable.",
            affected_resources=offenders,
            remediation=(
                "Rewrite each policy to name the specific actions and resource ARNs the "
                "role actually needs. Use the IAM Access Analyzer policy generator, which "
                "reads CloudTrail history and proposes a scoped policy based on what was "
                "really used. Delete the wildcard version once the replacement is attached."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"None of the {len(policies)} customer-managed policies allow all actions on all "
        "resources.",
        evidence=cited,
    )


# =======================================================================================
# 3.1.5 -- Employ the principle of least privilege
# =======================================================================================


def iam_least_privilege_admin(evidence: EvidenceMap) -> Finding:
    """Users holding AdministratorAccess directly.

    Roles are deliberately not flagged. A role is assumed temporarily and every
    assumption is logged in CloudTrail, which is how administrative access is supposed to
    work. A user holding the policy permanently has standing admin rights instead.
    """
    control, objective, name = "3.1.5", "3.1.5[b]", "iam_least_privilege_admin"
    attached = raw_value(evidence, "iam", "attached_admin")
    cited = used(get_evidence(evidence, "iam", "attached_admin"))

    if not isinstance(attached, dict) or "users" not in attached:
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate administrator attachments: {error_reason(attached)}.",
            evidence=cited,
        )

    admin_users = sorted(attached.get("users", {}))
    role_count = len(attached.get("roles", {}))

    if admin_users:
        return finding(
            control, objective, name, Verdict.FAIL,
            f"{len(admin_users)} IAM user(s) have AdministratorAccess attached directly: "
            f"{', '.join(admin_users)}. Standing administrator rights on a user account "
            "are not least privilege; roles assumed when needed are.",
            affected_resources=admin_users,
            remediation=(
                "Create an administrator role and have these users assume it only when "
                "they need it, then detach AdministratorAccess from the user. Assuming a "
                "role is recorded in CloudTrail, so administrative actions become "
                "attributable and time-bounded instead of permanent."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        "No IAM user has AdministratorAccess attached directly"
        + (f" ({role_count} role(s) hold it, which is acceptable)." if role_count else "."),
        evidence=cited,
    )


# =======================================================================================
# 3.1.12 -- Monitor and control remote access sessions
# =======================================================================================


def _admin_ports_covered(permission: dict[str, Any]) -> list[int]:
    """Which remote-administration ports an ingress rule opens."""
    protocol = str(permission.get("IpProtocol", "")).lower()

    # "-1" is AWS's way of saying every protocol and every port.
    if protocol == "-1":
        return list(ADMIN_PORTS)
    if protocol not in {"tcp", "6"}:
        return []

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return list(ADMIN_PORTS)
    return [port for port in ADMIN_PORTS if from_port <= port <= to_port]


def _world_open_cidrs(permission: dict[str, Any]) -> list[str]:
    """The internet-wide CIDRs in an ingress rule, if any."""
    ipv4 = [r.get("CidrIp") for r in permission.get("IpRanges", []) or []]
    ipv6 = [r.get("CidrIpv6") for r in permission.get("Ipv6Ranges", []) or []]
    return [c for c in ipv4 if c == WORLD_IPV4] + [c for c in ipv6 if c == WORLD_IPV6]


def sg_no_unrestricted_admin_ingress(evidence: EvidenceMap) -> Finding:
    """Security groups exposing SSH, RDP or WinRM to the whole internet."""
    control, objective, name = "3.1.12", "3.1.12[c]", "sg_no_unrestricted_admin_ingress"
    groups = raw_value(evidence, "ec2", "security_groups")
    cited = used(get_evidence(evidence, "ec2", "security_groups"))

    if not isinstance(groups, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate security groups: {error_reason(groups)}.",
            evidence=cited,
        )

    offenders: list[str] = []
    detail: list[str] = []
    for group in groups:
        group_id = group.get("GroupId", "unknown")
        group_name = group.get("GroupName", "")
        exposed: set[int] = set()
        sources: set[str] = set()
        for permission in group.get("IpPermissions", []) or []:
            world = _world_open_cidrs(permission)
            if not world:
                continue
            ports = _admin_ports_covered(permission)
            if ports:
                exposed.update(ports)
                sources.update(world)
        if exposed:
            offenders.append(group_id)
            ports_text = ", ".join(str(p) for p in sorted(exposed))
            source_text = "/".join(sorted(sources))
            detail.append(f"{group_id} ({group_name}) ports {ports_text} from {source_text}")

    if offenders:
        return finding(
            control, objective, name, Verdict.FAIL,
            f"{len(offenders)} security group(s) allow remote administration from any "
            f"address on the internet: {'; '.join(detail)}.",
            affected_resources=offenders,
            remediation=(
                "Replace the 0.0.0.0/0 source with the specific office or VPN CIDR ranges "
                "that need access, or remove the rule entirely and use AWS Systems Manager "
                "Session Manager, which needs no inbound port at all. Ports 22 (SSH), 3389 "
                "(RDP), 5985 and 5986 (WinRM) open to the internet are scanned continuously "
                "by automated attackers."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"None of the {len(groups)} security groups expose ports "
        f"{', '.join(str(p) for p in ADMIN_PORTS)} to the internet.",
        evidence=cited,
    )


# =======================================================================================
# 3.1.13 -- Cryptographic mechanisms protecting remote access
# =======================================================================================


def _denies_insecure_transport(policy: Any) -> bool:
    """True if a bucket policy refuses plaintext HTTP.

    Looks for a Deny statement conditioned on ``aws:SecureTransport`` being false.
    Condition operator and key names are matched case-insensitively because AWS treats
    them that way, and the value may be the string "false" or a list containing it.
    """
    if not isinstance(policy, dict):
        return False

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Deny":
            continue
        conditions = statement.get("Condition")
        if not isinstance(conditions, dict):
            continue
        for operator, body in conditions.items():
            if str(operator).lower() != "bool" or not isinstance(body, dict):
                continue
            for key, value in body.items():
                if str(key).lower() != "aws:securetransport":
                    continue
                if any(str(v).lower() == "false" for v in as_list(value)):
                    return True
    return False


def s3_requires_tls(evidence: EvidenceMap) -> Finding:
    """Buckets that will still accept unencrypted HTTP requests."""
    control, objective, name = "3.1.13", "3.1.13[a]", "s3_requires_tls"
    configs = raw_value(evidence, "s3", "bucket_config")
    cited = used(get_evidence(evidence, "s3", "bucket_config"))

    if not isinstance(configs, dict) or is_error(configs):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate bucket policies: {error_reason(configs)}.",
            evidence=cited,
        )
    if not configs:
        return finding(
            control, objective, name, Verdict.PASS,
            "No S3 buckets exist in this account, so none can accept plaintext requests.",
            evidence=cited,
        )

    missing: list[str] = []
    unknown: list[str] = []
    for bucket, config in sorted(configs.items()):
        policy = (config or {}).get("policy")
        if is_error(policy):
            unknown.append(bucket)
        elif not _denies_insecure_transport(policy):
            missing.append(bucket)

    if missing:
        summary = (
            f"{len(missing)} of {len(configs)} bucket(s) have no policy denying "
            f"plaintext HTTP: {', '.join(missing)}. Without it, a client that omits TLS "
            "is served anyway and the data crosses the network in the clear."
        )
        if unknown:
            summary += f" {len(unknown)} more could not be read: {', '.join(unknown)}."
        return finding(
            control, objective, name, Verdict.FAIL, summary,
            affected_resources=missing,
            remediation=(
                "Attach a bucket policy with a Deny statement on s3:* for both the bucket "
                "ARN and its objects, conditioned on Bool aws:SecureTransport = false. "
                "terraform/s3.tf in this repository has a working example."
            ),
            evidence=cited,
        )

    if unknown:
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Bucket policies could not be read for {len(unknown)} bucket(s): "
            f"{', '.join(unknown)}. The SecurityAudit policy does not always grant "
            "s3:GetBucketPolicy.",
            affected_resources=unknown,
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"All {len(configs)} bucket(s) deny requests that do not use TLS.",
        evidence=cited,
    )


# =======================================================================================
# 3.1.20 -- Verify and control connections to external systems
# =======================================================================================


def s3_public_access_blocked(evidence: EvidenceMap) -> Finding:
    """Buckets without all four public-access-block settings switched on."""
    control, objective, name = "3.1.20", "3.1.20[a]", "s3_public_access_blocked"
    configs = raw_value(evidence, "s3", "bucket_config")
    cited = used(get_evidence(evidence, "s3", "bucket_config"))

    if not isinstance(configs, dict) or is_error(configs):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate public access blocks: {error_reason(configs)}.",
            evidence=cited,
        )
    if not configs:
        return finding(
            control, objective, name, Verdict.PASS,
            "No S3 buckets exist in this account.",
            evidence=cited,
        )

    incomplete: list[str] = []
    unknown: list[str] = []
    for bucket, config in sorted(configs.items()):
        block = (config or {}).get("public_access_block")
        if is_error(block):
            unknown.append(bucket)
        elif not isinstance(block, dict) or not all(
            block.get(flag) is True for flag in PUBLIC_ACCESS_BLOCK_FLAGS
        ):
            incomplete.append(bucket)

    if incomplete:
        summary = (
            f"{len(incomplete)} of {len(configs)} bucket(s) do not have all four public "
            f"access block settings enabled: {', '.join(incomplete)}."
        )
        if unknown:
            summary += f" {len(unknown)} more could not be read: {', '.join(unknown)}."
        return finding(
            control, objective, name, Verdict.FAIL, summary,
            affected_resources=incomplete,
            remediation=(
                "Enable Block Public Access on each bucket (S3 console > bucket > "
                "Permissions > Block public access > Edit, tick all four). Turning it on "
                "at the account level as well prevents a future bucket from being created "
                "without it."
            ),
            evidence=cited,
        )

    if unknown:
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Public access block could not be read for {len(unknown)} bucket(s): "
            f"{', '.join(unknown)}.",
            affected_resources=unknown,
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"All {len(configs)} bucket(s) have all four public access block settings enabled.",
        evidence=cited,
    )


# =======================================================================================
# Requirements no AWS API can answer
# =======================================================================================


def cui_flow_control_manual(evidence: EvidenceMap) -> Finding:
    """3.1.3 -- control the flow of CUI in accordance with approved authorizations."""
    return finding(
        "3.1.3", "3.1.3[a]", "cui_flow_control_manual", Verdict.MANUAL,
        "Requires human assessment. An assessor must confirm that the organization has "
        "defined where CUI is allowed to travel -- which systems, networks and people may "
        "send or receive it -- and that the defined flows are actually enforced. AWS "
        "shows network configuration but cannot say which data is CUI or which flows were "
        "authorized, so no API answers this. Evidence would be a data flow diagram, the "
        "system security plan, and the approved authorizations themselves.",
    )


def separation_of_duties_manual(evidence: EvidenceMap) -> Finding:
    """3.1.4 -- separate the duties of individuals."""
    return finding(
        "3.1.4", "3.1.4[a]", "separation_of_duties_manual", Verdict.MANUAL,
        "Requires human assessment. This asks whether duties that should be held by "
        "different people actually are -- for example whether the person who approves a "
        "change is also the one who deploys it. IAM shows which identities hold which "
        "permissions, but not which human being sits behind each identity or what their "
        "job is. Evidence would be an org chart, role definitions, and the mapping of "
        "people to accounts.",
    )


def privileged_function_control_manual(evidence: EvidenceMap) -> Finding:
    """3.1.7 -- prevent non-privileged users from executing privileged functions."""
    return finding(
        "3.1.7", "3.1.7[a]", "privileged_function_control_manual", Verdict.MANUAL,
        "Requires human assessment. The organization must first define which functions "
        "count as privileged and which users count as non-privileged; only then can "
        "enforcement be judged. Those definitions live in policy documents, not in AWS. "
        "Partial automation is possible later -- CloudTrail records privileged API calls "
        "and could be checked against a defined list -- but the list has to exist first.",
    )


# =======================================================================================
# Registry
# =======================================================================================

#: Every Access Control check, in the order they are reported.
CHECKS: list[Check] = [
    iam_users_have_mfa,
    iam_no_stale_access_keys,
    iam_no_wildcard_admin_policies,
    iam_least_privilege_admin,
    sg_no_unrestricted_admin_ingress,
    s3_requires_tls,
    s3_public_access_blocked,
    cui_flow_control_manual,
    separation_of_duties_manual,
    privileged_function_control_manual,
]
