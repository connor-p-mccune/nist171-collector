"""Command-line entry point for nist171-collector.

Three subcommands, matching the three stages of the pipeline:

    collect  ask AWS questions and save the answers as hashed evidence
    assess   read saved evidence and decide PASS / FAIL / MANUAL per requirement
    report   turn findings into a score, a POA&M, and human- or machine-readable output
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
import click
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound
from rich.console import Console
from rich.table import Table

from nist171 import __version__
from nist171.checks import checks_for
from nist171.collectors.aws.cloudtrail import CloudTrailCollector
from nist171.collectors.aws.ec2 import EC2Collector
from nist171.collectors.aws.iam import IAMCollector
from nist171.collectors.aws.kms import KMSCollector
from nist171.collectors.aws.s3 import S3Collector
from nist171.collectors.base import VERSION as COLLECTOR_VERSION
from nist171.collectors.base import Collector
from nist171.evidence_io import (
    EvidenceIntegrityError,
    latest_evidence_dir,
    load_evidence,
    load_manifest,
)
from nist171.models import Evidence, Finding
from nist171.session import DEFAULT_REGION, make_session

EVIDENCE_DIR = "evidence"
OUTPUT_DIR = "output"
MANIFEST_NAME = "manifest.json"

#: Run in a fixed order so two runs of the same account produce comparable output.
COLLECTORS: tuple[type[Collector], ...] = (
    IAMCollector,
    CloudTrailCollector,
    EC2Collector,
    S3Collector,
    KMSCollector,
)


def _run_stamp() -> str:
    """UTC timestamp used as the evidence folder name. Sorts chronologically as text."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _write_evidence_file(path: Path, items: dict[str, Evidence]) -> None:
    """Write one collector's evidence as a JSON list.

    Each element is that item's ``to_dict()`` plus the key it was collected under, so the
    file can be read back into the same ``{key: Evidence}`` shape later.
    """
    payload = [{"key": key, **evidence.to_dict()} for key, evidence in items.items()]
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _file_sha256(path: Path) -> str:
    """SHA-256 of a file's bytes as written to disk."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _detail(name: str, items: dict[str, Evidence]) -> str:
    """A short, human-readable note about what one collector actually found."""
    raw = {key: evidence.raw for key, evidence in items.items()}

    def count(key: str) -> int | None:
        value = raw.get(key)
        return len(value) if isinstance(value, list | dict) else None

    if name == "iam":
        parts = []
        users = count("users")
        parts.append(_plural(users, "user") if users is not None else "users denied")
        report = raw.get("credential_report")
        parts.append(
            f"credential report {_plural(len(report), 'row')}"
            if isinstance(report, list)
            else "credential report unavailable"
        )
        admin = raw.get("attached_admin")
        if isinstance(admin, dict) and "users" in admin:
            parts.append(f"{_plural(len(admin['users']), 'user')} with AdministratorAccess")
        parts.append(
            "no password policy" if raw.get("password_policy") is None else "password policy set"
        )
        return ", ".join(parts)

    if name == "cloudtrail":
        trails = raw.get("trails")
        if not isinstance(trails, list):
            return "trails denied"
        status_raw = raw.get("trail_status")
        status: dict[str, Any] = status_raw if isinstance(status_raw, dict) else {}
        logging_now = len(
            [s for s in status.values() if isinstance(s, dict) and s.get("IsLogging")]
        )
        return f"{_plural(len(trails), 'trail')}, {logging_now} logging"

    if name == "ec2":
        groups = count("security_groups")
        ebs = raw.get("ebs_encryption_default")
        return (
            f"{_plural(groups, 'security group')}, "
            f"default EBS encryption {'on' if ebs else 'off'}"
            if groups is not None
            else "security groups denied"
        )

    if name == "s3":
        buckets = count("buckets")
        return _plural(buckets, "bucket") if buckets is not None else "buckets denied"

    if name == "kms":
        keys = count("keys")
        return _plural(keys, "KMS key") if keys is not None else "keys denied"

    return _plural(len(items), "item")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "--version", prog_name="nist171")
def cli() -> None:
    """Assess an AWS account against NIST SP 800-171 Rev 2 (AC, AU, IA families)."""


@cli.command()
@click.option(
    "--profile",
    default=None,
    help="AWS named profile to use, e.g. nist-scanner. Falls back to $AWS_PROFILE.",
)
@click.option("--region", default=DEFAULT_REGION, show_default=True, help="AWS region.")
@click.option(
    "--out",
    "out_dir",
    default=EVIDENCE_DIR,
    show_default=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Directory to write the timestamped evidence folder into.",
)
def collect(profile: str | None, region: str, out_dir: Path) -> None:
    """Query AWS read-only and write timestamped, hashed evidence."""
    try:
        session = make_session(profile, region)
        # Cheap identity check: fails immediately and clearly on a bad or missing profile
        # rather than part-way through collection. Needs no IAM permissions.
        account_id = session.client("sts").get_caller_identity()["Account"]
    except ProfileNotFound as exc:
        raise click.ClickException(
            f"{exc}. Run 'aws configure --profile {profile or 'nist-scanner'}' first, "
            "or check C:\\Users\\<you>\\.aws\\credentials."
        ) from exc
    except (NoCredentialsError, ClientError, BotoCoreError) as exc:
        raise click.ClickException(f"Could not authenticate to AWS: {exc}") from exc

    started = datetime.now(UTC)
    run_dir = Path(out_dir) / _run_stamp()
    run_dir.mkdir(parents=True, exist_ok=True)

    files, failures = _run_collectors(session, run_dir)
    _write_manifest(run_dir, account_id, region, started, files, failures)

    click.echo(f"\nEvidence written to {run_dir}  (manifest: {MANIFEST_NAME})")
    if failures:
        click.echo(
            f"{_plural(len(failures), 'collector')} failed; see {MANIFEST_NAME}.", err=True
        )


def _run_collectors(
    session: boto3.Session, run_dir: Path
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Run every collector, writing one evidence file each.

    A collector that blows up in an unexpected way is recorded and skipped rather than
    ending the run. Losing the other four services' evidence because KMS returned
    something surprising would be a bad trade.
    """
    files: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []

    for collector_class in COLLECTORS:
        collector = collector_class(session)
        try:
            items = collector.collect()
        except Exception as exc:  # noqa: BLE001 - deliberately broad; recorded, not hidden
            failures.append(
                {
                    "collector": collector.name,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
            click.echo(f"  {collector.name:<12} FAILED  {type(exc).__name__}: {exc}", err=True)
            continue

        path = run_dir / f"{collector.name}.json"
        _write_evidence_file(path, items)
        files.append(
            {
                "name": path.name,
                "sha256": _file_sha256(path),
                "bytes": path.stat().st_size,
                "items": len(items),
                "keys": list(items),
            }
        )
        click.echo(
            f"  {collector.name:<12} {_plural(len(items), 'item'):<8} "
            f"({_detail(collector.name, items)})"
        )

    return files, failures


def _write_manifest(
    run_dir: Path,
    account_id: str,
    region: str,
    started: datetime,
    files: list[dict[str, Any]],
    failures: list[dict[str, str]],
) -> None:
    """Write the manifest: what was collected, when, and the hash of every file.

    The manifest is the index an auditor checks first. Re-hashing each file and comparing
    against these values proves the evidence set is complete and unmodified.
    """
    manifest = {
        "tool": "nist171-collector",
        "tool_version": __version__,
        "collector_version": COLLECTOR_VERSION,
        "account_id": account_id,
        "region": region,
        "collection_started_at": started.isoformat(),
        "collection_completed_at": datetime.now(UTC).isoformat(),
        "files": files,
        "failed_collectors": failures,
    }
    (run_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, default=str), encoding="utf-8"
    )


VERDICT_STYLE = {
    "PASS": "green",
    "FAIL": "bold red",
    "MANUAL": "yellow",
    "NOT_APPLICABLE": "blue",
    "ERROR": "magenta",
}


@cli.command()
@click.option(
    "--evidence",
    "evidence_dir",
    default=None,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Evidence run folder. Defaults to the most recent one under evidence/.",
)
@click.option(
    "--families",
    default="AC,AU,IA",
    show_default=True,
    help="Comma-separated control families to assess, e.g. AC or AC,IA.",
)
@click.option(
    "--out",
    "out_dir",
    default=OUTPUT_DIR,
    show_default=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Directory to write findings.json into.",
)
def assess(evidence_dir: Path | None, families: str, out_dir: Path) -> None:
    """Evaluate saved evidence against the control catalog."""
    try:
        run_dir = Path(evidence_dir) if evidence_dir else latest_evidence_dir(EVIDENCE_DIR)
        evidence = load_evidence(run_dir)
    except (FileNotFoundError, EvidenceIntegrityError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    family_list = [f.strip().upper() for f in families.split(",") if f.strip()]
    try:
        checks = checks_for(family_list)
    except KeyError as exc:
        raise click.ClickException(str(exc).strip("'")) from exc

    findings = [check(evidence) for check in checks]

    manifest = load_manifest(run_dir)
    _print_findings(run_dir, findings)
    out_path = _write_findings(out_dir, run_dir, manifest, family_list, findings)

    counts = Counter(f.verdict.value for f in findings)
    click.echo(
        "  ".join(f"{verdict}: {counts.get(verdict, 0)}" for verdict in VERDICT_STYLE)
        + f"\nFindings written to {out_path}"
    )


def _print_findings(run_dir: Path, findings: list[Finding]) -> None:
    """Render the findings as a table."""
    console = Console()
    table = Table(
        title=f"NIST SP 800-171 Rev 2 assessment - evidence {run_dir.name}",
        title_style="bold",
        header_style="bold",
        show_lines=False,
    )
    table.add_column("Control", no_wrap=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Summary")

    for found in findings:
        verdict = found.verdict.value
        table.add_row(
            found.control_id,
            found.check_name,
            f"[{VERDICT_STYLE.get(verdict, 'white')}]{verdict}[/]",
            found.summary,
        )
    console.print(table)


def _write_findings(
    out_dir: Path,
    run_dir: Path,
    manifest: dict[str, Any],
    families: list[str],
    findings: list[Finding],
) -> Path:
    """Write findings.json, carrying enough provenance to rebuild the report later."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "tool": "nist171-collector",
        "tool_version": __version__,
        "assessed_at": datetime.now(UTC).isoformat(),
        "evidence_dir": str(run_dir),
        "account_id": manifest.get("account_id"),
        "region": manifest.get("region"),
        "collected_at": manifest.get("collection_started_at"),
        "families": families,
        "findings": [f.to_dict() for f in findings],
    }
    path = out_dir / "findings.json"
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


@cli.command()
def report() -> None:
    """Generate the score, POA&M, and HTML/OSCAL output from findings."""
    click.echo("not implemented yet")


def main() -> None:
    """Console-script entry point declared in pyproject.toml."""
    try:
        cli()
    except KeyboardInterrupt:  # pragma: no cover
        click.echo("Interrupted.", err=True)
        sys.exit(130)


if __name__ == "__main__":
    main()
