"""Command-line entry point for nist171-collector.

Three subcommands, matching the three stages of the pipeline:

    collect  ask AWS questions and save the answers as hashed evidence
    assess   read saved evidence and decide PASS / FAIL / MANUAL per requirement
    report   turn findings into a score, a POA&M, and human- or machine-readable output

All three are placeholders at this stage.
"""

from __future__ import annotations

import click

from nist171 import __version__


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "--version", prog_name="nist171")
def cli() -> None:
    """Assess an AWS account against NIST SP 800-171 Rev 2 (AC, AU, IA families)."""


@cli.command()
def collect() -> None:
    """Query AWS read-only and write timestamped, hashed evidence."""
    click.echo("not implemented yet")


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
    cli()


if __name__ == "__main__":
    main()
