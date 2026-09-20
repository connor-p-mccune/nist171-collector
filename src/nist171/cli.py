"""Command-line entry point for nist171-collector.

Three subcommands, matching the three stages of the pipeline:

    collect  ask AWS questions and save the answers as hashed evidence
    assess   read saved evidence and decide PASS / FAIL / MANUAL per requirement
    report   turn findings into a score, a POA&M, and human- or machine-readable output
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import click
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

from nist171 import __version__
from nist171.collectors.aws.iam import IAMCollector
from nist171.models import Evidence
from nist171.session import DEFAULT_REGION, make_session

EVIDENCE_DIR = "evidence"
OUTPUT_DIR = "output"


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


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _describe(items: dict[str, Evidence]) -> str:
    """Short human summary of what a collector actually found."""
    parts: list[str] = []
    users = items["users"].raw
    parts.append(_plural(len(users), "user") if isinstance(users, list) else "users: access denied")

    report = items["credential_report"].raw
    if isinstance(report, list):
        parts.append(f"credential report {_plural(len(report), 'row')}")
    else:
        parts.append("credential report unavailable")

    policies = items["policies"].raw
    if isinstance(policies, list):
        parts.append(
            _plural(len(policies), "customer-managed policy", "customer-managed policies")
        )

    admin = items["attached_admin"].raw
    if isinstance(admin, dict):
        parts.append(f"{_plural(len(admin.get('users', {})), 'user')} with AdministratorAccess")

    policy = items["password_policy"].raw
    parts.append("no password policy" if policy is None else "password policy set")
    return ", ".join(parts)


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

    run_dir = Path(out_dir) / _run_stamp()
    run_dir.mkdir(parents=True, exist_ok=True)

    collector = IAMCollector(session)
    items = collector.collect()
    _write_evidence_file(run_dir / f"{collector.name}.json", items)

    click.echo(
        f"Collected {len(items)} IAM evidence items from account {account_id} "
        f"({_describe(items)}) -> {run_dir / f'{collector.name}.json'}"
    )


@cli.command()
def assess() -> None:
    """Evaluate saved evidence against the control catalog."""
    click.echo("not implemented yet")


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
