"""Audit and Accountability (3.3.x) checks.

Five automated checks and six that no API can answer.

The family reduces to two questions in a cloud account: is activity being recorded, and
can the recording be trusted. CloudTrail answers both -- a multi-region trail that is
actually logging, with log file validation on and its bucket protected. The rest of the
family is about what humans do with those logs, which is why six of the nine requirements
here are MANUAL.
"""

from __future__ import annotations

import re
from typing import Any

from nist171.checks.common import (
    Check,
    EvidenceMap,
    error_reason,
    finding,
    get_evidence,
    is_error,
    raw_value,
    used,
)
from nist171.models import Finding, Verdict

PUBLIC_ACCESS_BLOCK_FLAGS = (
    "BlockPublicAcls",
    "BlockPublicPolicy",
    "IgnorePublicAcls",
    "RestrictPublicBuckets",
)

#: Name fragments that indicate an account is shared by several people.
SHARED_TOKENS = ("shared", "team", "group", "common", "everyone", "generic")

#: Fragments that indicate a privileged account, which is only a concern for
#: attribution when no individual person is named alongside them.
PRIVILEGED_TOKENS = ("admin", "administrator", "superuser", "sysadmin")

#: Fragments that suggest a non-human account.
SERVICE_TOKENS = ("svc", "service", "bot", "automation", "ci", "cd", "pipeline")

#: Words that are organizational or infrastructural rather than personal. A name built
#: only from these plus a privileged token names a role, not a person. This vocabulary is
#: the whole heuristic and is meant to be extended per organization.
NON_PERSONAL_TOKENS = frozenset(
    {
        "aws", "cloud", "corp", "company", "dev", "development", "eng", "engineering",
        "global", "infra", "infrastructure", "it", "main", "master", "net", "network",
        "nist", "ops", "org", "platform", "prod", "production", "qa", "root", "sec",
        "security", "srv", "stage", "staging", "sys", "system", "test", "user", "users",
    }
    | set(SHARED_TOKENS)
    | set(PRIVILEGED_TOKENS)
    | set(SERVICE_TOKENS)
)


def _tokens(name: str) -> list[str]:
    """Split an IAM user name into lowercase word-ish pieces."""
    return [t for t in re.split(r"[^A-Za-z0-9]+", name.lower()) if t]


# =======================================================================================
# 3.3.1 -- Create and retain audit logs
# =======================================================================================


def cloudtrail_enabled_multiregion(evidence: EvidenceMap) -> Finding:
    """At least one multi-region trail must exist and actually be logging."""
    control, objective, name = "3.3.1", "3.3.1[c]", "cloudtrail_enabled_multiregion"
    trails = raw_value(evidence, "cloudtrail", "trails")
    status = raw_value(evidence, "cloudtrail", "trail_status")
    cited = used(
        get_evidence(evidence, "cloudtrail", "trails"),
        get_evidence(evidence, "cloudtrail", "trail_status"),
    )

    if not isinstance(trails, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate CloudTrail configuration: {error_reason(trails)}.",
            evidence=cited,
        )

    statuses: dict[str, Any] = status if isinstance(status, dict) else {}
    logging_multiregion = [
        t.get("Name") or t.get("TrailARN", "unnamed")
        for t in trails
        if t.get("IsMultiRegionTrail")
        and isinstance(statuses.get(t.get("TrailARN")), dict)
        and statuses[t["TrailARN"]].get("IsLogging")
    ]

    if logging_multiregion:
        return finding(
            control, objective, name, Verdict.PASS,
            f"{len(logging_multiregion)} multi-region trail(s) are actively logging: "
            f"{', '.join(logging_multiregion)}.",
            evidence=cited,
        )

    # Distinguish "no trail at all" from "a trail exists but is switched off", because
    # they are different problems with different fixes.
    if not trails:
        detail = (
            "No CloudTrail trail exists in this account, so no API activity is "
            "recorded at all."
        )
    else:
        configured = [t.get("Name", "unnamed") for t in trails]
        detail = (
            f"{len(trails)} trail(s) exist ({', '.join(configured)}) but none is both "
            "multi-region and currently logging."
        )

    return finding(
        control, objective, name, Verdict.FAIL,
        f"{detail} Without this, there is no record of who did what in the account, and "
        "most of the Audit and Accountability family cannot be satisfied by any other means.",
        affected_resources=[t.get("Name", "unnamed") for t in trails] or ["account"],
        remediation=(
            "Create a CloudTrail trail with multi-region enabled and start logging "
            "(CloudTrail console > Trails > Create trail, tick 'Enable for all accounts "
            "in my organization' only if applicable, and leave the multi-region default "
            "on). One trail delivering a single copy of management events is free."
        ),
        evidence=cited,
    )


# =======================================================================================
# 3.3.2 -- Trace actions to individual users
# =======================================================================================


def cloudtrail_global_events(evidence: EvidenceMap) -> Finding:
    """Trails must include global service events or IAM activity is invisible."""
    control, objective, name = "3.3.2", "3.3.2[a]", "cloudtrail_global_events"
    trails = raw_value(evidence, "cloudtrail", "trails")
    cited = used(get_evidence(evidence, "cloudtrail", "trails"))

    if not isinstance(trails, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate CloudTrail configuration: {error_reason(trails)}.",
            evidence=cited,
        )
    if not trails:
        return finding(
            control, objective, name, Verdict.FAIL,
            "No CloudTrail trail exists, so no action can be traced to the user who took it.",
            affected_resources=["account"],
            remediation="Create a multi-region trail with global service events included.",
            evidence=cited,
        )

    missing = [
        t.get("Name") or t.get("TrailARN", "unnamed")
        for t in trails
        if not t.get("IncludeGlobalServiceEvents")
    ]

    if missing:
        return finding(
            control, objective, name, Verdict.FAIL,
            f"{len(missing)} trail(s) do not record global service events: "
            f"{', '.join(missing)}. IAM, STS and other global services are not tied to a "
            "region, so without this their activity never reaches the log and IAM changes "
            "cannot be attributed to a user.",
            affected_resources=missing,
            remediation=(
                "Edit each trail and enable 'Include global service events'. In Terraform "
                "that is include_global_service_events = true on the aws_cloudtrail "
                "resource."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"All {len(trails)} trail(s) record global service events, so IAM and STS activity "
        "is attributable.",
        evidence=cited,
    )


def no_shared_accounts_heuristic(evidence: EvidenceMap) -> Finding:
    """Guess at IAM user names that look shared rather than individual.

    This is a name-pattern heuristic, not a determination. AWS has no field saying
    "this login belongs to one human", so the only signal available is what the account
    is called. The summary says so plainly, because a finding a reader cannot calibrate
    is worse than no finding.
    """
    control, objective, name = "3.3.2", "3.3.2[a]", "no_shared_accounts_heuristic"
    users = raw_value(evidence, "iam", "users")
    report = raw_value(evidence, "iam", "credential_report")
    cited = used(
        get_evidence(evidence, "iam", "users"),
        get_evidence(evidence, "iam", "credential_report"),
    )

    if not isinstance(users, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate IAM user names: {error_reason(users)}.",
            evidence=cited,
        )

    has_console: dict[str, bool] = {}
    if isinstance(report, list):
        has_console = {r.get("user", ""): r.get("password_enabled") == "true" for r in report}

    suspicious: list[str] = []
    reasons: list[str] = []
    for user in users:
        username = user.get("UserName", "") if isinstance(user, dict) else str(user)
        tokens = _tokens(username)
        if not tokens:
            continue

        if any(token in SHARED_TOKENS for token in tokens):
            suspicious.append(username)
            reasons.append(f"{username} (name suggests a shared account)")
            continue

        # A privileged name is only a concern when nothing in it names a person.
        if any(token in PRIVILEGED_TOKENS for token in tokens):
            if all(token in NON_PERSONAL_TOKENS or len(token) < 3 for token in tokens):
                suspicious.append(username)
                reasons.append(f"{username} (privileged name with no individual identified)")
                continue

        # A service account with console sign-in is a person logging in as a robot.
        if any(token in SERVICE_TOKENS for token in tokens) and has_console.get(username):
            suspicious.append(username)
            reasons.append(f"{username} (service-style name with console access enabled)")

    caveat = (
        "This is a heuristic based on naming patterns only -- AWS exposes no field stating "
        "whether a login belongs to one person. Treat each as a prompt to confirm, not as a "
        "determination; a name like 'jsmith-admin' is correctly ignored, and a shared "
        "account named 'jupiter' would be missed entirely."
    )

    if suspicious:
        return finding(
            control, objective, name, Verdict.FAIL,
            f"{len(suspicious)} IAM user name(s) look like shared or role accounts rather "
            f"than individuals: {'; '.join(reasons)}. Shared logins break attribution -- an "
            f"action in the audit log points at the account, not at a person. {caveat}",
            affected_resources=suspicious,
            remediation=(
                "Confirm whether each account is used by more than one person. If so, "
                "replace it with per-person users, or move to federated sign-in through an "
                "identity provider so the audit log records the individual. If the account "
                "genuinely belongs to one person, rename it to include their identifier."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"None of the {len(users)} IAM user names match the shared-account naming patterns. "
        f"{caveat}",
        evidence=cited,
    )


# =======================================================================================
# 3.3.8 -- Protect audit information from unauthorized access and modification
# =======================================================================================


def cloudtrail_log_validation(evidence: EvidenceMap) -> Finding:
    """Log file validation makes tampering with delivered logs detectable."""
    control, objective, name = "3.3.8", "3.3.8[a]", "cloudtrail_log_validation"
    trails = raw_value(evidence, "cloudtrail", "trails")
    cited = used(get_evidence(evidence, "cloudtrail", "trails"))

    if not isinstance(trails, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate CloudTrail configuration: {error_reason(trails)}.",
            evidence=cited,
        )
    if not trails:
        return finding(
            control, objective, name, Verdict.FAIL,
            "No CloudTrail trail exists, so there are no audit logs to protect.",
            affected_resources=["account"],
            remediation="Create a trail with log file validation enabled.",
            evidence=cited,
        )

    missing = [
        t.get("Name") or t.get("TrailARN", "unnamed")
        for t in trails
        if not t.get("LogFileValidationEnabled")
    ]

    if missing:
        return finding(
            control, objective, name, Verdict.FAIL,
            f"{len(missing)} trail(s) do not have log file validation enabled: "
            f"{', '.join(missing)}. Without it, a log file altered after delivery is "
            "indistinguishable from an authentic one.",
            affected_resources=missing,
            remediation=(
                "Enable log file validation on each trail. CloudTrail then writes a signed "
                "digest file every hour, and 'aws cloudtrail validate-logs' can prove "
                "afterwards that no log file was changed or deleted. It is free."
            ),
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"All {len(trails)} trail(s) have log file validation enabled, so tampering with "
        "delivered logs is detectable.",
        evidence=cited,
    )


def cloudtrail_bucket_protected(evidence: EvidenceMap) -> Finding:
    """The bucket holding the logs must be versioned and not publicly reachable."""
    control, objective, name = "3.3.8", "3.3.8[a]", "cloudtrail_bucket_protected"
    trails = raw_value(evidence, "cloudtrail", "trails")
    configs = raw_value(evidence, "s3", "bucket_config")
    cited = used(
        get_evidence(evidence, "cloudtrail", "trails"),
        get_evidence(evidence, "s3", "bucket_config"),
    )

    if not isinstance(trails, list):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate CloudTrail configuration: {error_reason(trails)}.",
            evidence=cited,
        )
    if not isinstance(configs, dict) or is_error(configs):
        return finding(
            control, objective, name, Verdict.ERROR,
            f"Could not evaluate the log bucket: {error_reason(configs)}.",
            evidence=cited,
        )
    if not trails:
        return finding(
            control, objective, name, Verdict.FAIL,
            "No CloudTrail trail exists, so there is no protected log bucket.",
            affected_resources=["account"],
            remediation="Create a trail writing to a versioned bucket with public access blocked.",
            evidence=cited,
        )

    problems: list[str] = []
    unknown: list[str] = []
    checked: set[str] = set()

    for trail in trails:
        bucket = trail.get("S3BucketName")
        if not bucket or bucket in checked:
            continue
        checked.add(bucket)

        config = configs.get(bucket)
        if config is None:
            # Trails can deliver to a bucket in another account, which this scan cannot see.
            unknown.append(bucket)
            continue

        faults = []
        if config.get("versioning") != "Enabled":
            faults.append("versioning not enabled")
        block = config.get("public_access_block")
        if is_error(block):
            unknown.append(bucket)
            continue
        if not isinstance(block, dict) or not all(
            block.get(flag) is True for flag in PUBLIC_ACCESS_BLOCK_FLAGS
        ):
            faults.append("public access not fully blocked")
        if faults:
            problems.append(f"{bucket} ({', '.join(faults)})")

    if problems:
        summary = (
            f"{len(problems)} CloudTrail log bucket(s) are not adequately protected: "
            f"{'; '.join(problems)}. Versioning means a deleted or overwritten log object "
            "can still be recovered; blocking public access keeps the audit trail from "
            "being readable by anyone who finds the bucket name."
        )
        if unknown:
            summary += f" {len(unknown)} bucket(s) could not be inspected: {', '.join(unknown)}."
        return finding(
            control, objective, name, Verdict.FAIL, summary,
            affected_resources=[p.split(" (")[0] for p in problems],
            remediation=(
                "Enable versioning on the log bucket and turn on all four Block Public "
                "Access settings. For stronger protection, add S3 Object Lock in compliance "
                "mode so log objects cannot be deleted before their retention period ends."
            ),
            evidence=cited,
        )

    if unknown:
        return finding(
            control, objective, name, Verdict.ERROR,
            f"{len(unknown)} CloudTrail log bucket(s) could not be inspected: "
            f"{', '.join(unknown)}. They are most likely in another AWS account, which this "
            "scan does not reach.",
            affected_resources=unknown,
            evidence=cited,
        )

    return finding(
        control, objective, name, Verdict.PASS,
        f"All {len(checked)} CloudTrail log bucket(s) have versioning enabled and public "
        "access fully blocked.",
        evidence=cited,
    )


# =======================================================================================
# Requirements no AWS API can answer
# =======================================================================================


def _manual(control: str, objective: str, name: str, summary: str) -> Finding:
    return finding(control, objective, name, Verdict.MANUAL, summary)


def logged_events_review_manual(evidence: EvidenceMap) -> Finding:
    """3.3.3 -- review and update logged events."""
    return _manual(
        "3.3.3", "3.3.3[a]", "logged_events_review_manual",
        "Requires human assessment. The organization must define which events it needs "
        "logged, and then review that definition periodically as the system changes. "
        "CloudTrail shows what is being captured today; it cannot show that anyone decided "
        "what ought to be captured, or revisited the decision. Evidence would be a logging "
        "policy with a review date and records of past reviews.",
    )


def audit_failure_alerting_manual(evidence: EvidenceMap) -> Finding:
    """3.3.4 -- alert in the event of an audit logging process failure."""
    return _manual(
        "3.3.4", "3.3.4[a]", "audit_failure_alerting_manual",
        "Requires human assessment for now, but this one is genuinely automatable and is "
        "the top item on the roadmap. The requirement is that someone is alerted when audit "
        "logging itself fails. In AWS that is a CloudWatch alarm on CloudTrail delivery "
        "errors wired to an SNS topic. This scanner does not yet collect CloudWatch alarms "
        "or SNS subscriptions, so it cannot confirm the alarm exists or that anyone is "
        "subscribed. Until it does, an assessor must check by hand. Note the human part "
        "does not disappear either: an alarm nobody reads is not an alert.",
    )


def audit_correlation_manual(evidence: EvidenceMap) -> Finding:
    """3.3.5 -- correlate audit review, analysis and reporting."""
    return _manual(
        "3.3.5", "3.3.5[a]", "audit_correlation_manual",
        "Requires human assessment. This asks whether audit records from different sources "
        "are brought together and examined as a whole, so that activity spanning several "
        "systems can be recognized. The presence of a log aggregation tool is not the "
        "answer; the requirement is about the investigative process built on top of it. "
        "Evidence would be documented correlation procedures and examples of past analyses.",
    )


def audit_reduction_manual(evidence: EvidenceMap) -> Finding:
    """3.3.6 -- audit record reduction and report generation."""
    return _manual(
        "3.3.6", "3.3.6[a]", "audit_reduction_manual",
        "Requires human assessment. The organization must be able to reduce large volumes "
        "of audit records into something a person can analyse on demand, without altering "
        "the original records. Whether a capability exists and is usable is a judgment "
        "about tooling and practice, not a configuration value. Evidence would be a "
        "demonstration of the reporting capability and the procedures around it.",
    )


def time_synchronization_manual(evidence: EvidenceMap) -> Finding:
    """3.3.7 -- provide a system capability that compares and synchronizes clocks."""
    return _manual(
        "3.3.7", "3.3.7[a]", "time_synchronization_manual",
        "Requires human assessment, though AWS does most of the work. Audit records are "
        "only correlatable if clocks agree, and AWS-managed services timestamp events from "
        "an authoritative time source, with the Amazon Time Sync Service available to EC2 "
        "instances at no cost. What an assessor still has to confirm is that any "
        "self-managed hosts in scope actually use it and that the authoritative source is "
        "documented. Nothing in the AWS control plane reports on that.",
    )


def audit_management_access_manual(evidence: EvidenceMap) -> Finding:
    """3.3.9 -- limit management of audit functionality to a privileged subset."""
    return _manual(
        "3.3.9", "3.3.9[a]", "audit_management_access_manual",
        "Requires human assessment. Only a defined subset of privileged users should be "
        "able to manage audit logging -- stop a trail, change what it captures, delete its "
        "records. IAM policies can be read to see who holds cloudtrail:* or s3:DeleteObject "
        "on the log bucket, but the requirement is that the organization has defined that "
        "subset in the first place. Partial automation is possible once the definition "
        "exists; the definition itself is a policy document.",
    )


# =======================================================================================
# Registry
# =======================================================================================

#: Every Audit and Accountability check, in the order they are reported.
CHECKS: list[Check] = [
    cloudtrail_enabled_multiregion,
    cloudtrail_global_events,
    no_shared_accounts_heuristic,
    cloudtrail_log_validation,
    cloudtrail_bucket_protected,
    logged_events_review_manual,
    audit_failure_alerting_manual,
    audit_correlation_manual,
    audit_reduction_manual,
    time_synchronization_manual,
    audit_management_access_manual,
]
