from __future__ import annotations

import os
from pathlib import Path

import click

from nodesentry.checks.chain import check_chain
from nodesentry.checks.config import audit_config
from nodesentry.checks.disk import check_disk
from nodesentry.checks.peers import check_peers
from nodesentry.models import Finding, Severity, Status, summarize
from nodesentry.report import render_json, render_terminal
from nodesentry.rpc import BitcoinRPC, RPCError


def _emit(report, output_format: str) -> None:
    click.echo(render_json(report) if output_format == "json" else render_terminal(report))


def _exit_code(status: Status) -> int:
    return {Status.PASS: 0, Status.WARN: 1, Status.FAIL: 1, Status.UNKNOWN: 2, Status.SKIP: 0}[
        status
    ]


@click.group()
@click.version_option()
def cli() -> None:
    """Audit a Bitcoin Core node without surrendering control or data."""


@cli.command()
@click.option("--rpc-url", default="http://127.0.0.1:8332", show_default=True)
@click.option("--cookie-file", type=click.Path(path_type=Path), envvar="NODESENTRY_COOKIE_FILE")
@click.option("--rpc-user", envvar="NODESENTRY_RPC_USER")
@click.option("--rpc-password", envvar="NODESENTRY_RPC_PASSWORD", hidden=True)
@click.option("--bitcoin-conf", type=click.Path(path_type=Path))
@click.option("--data-dir", type=click.Path(path_type=Path), default=Path("~/.bitcoin"))
@click.option(
    "--format", "output_format", type=click.Choice(["terminal", "json"]), default="terminal"
)
def audit(
    rpc_url: str,
    cookie_file: Path | None,
    rpc_user: str | None,
    rpc_password: str | None,
    bitcoin_conf: Path | None,
    data_dir: Path,
    output_format: str,
) -> None:
    """Run a local read-only sovereignty audit."""
    findings: list[Finding] = []
    data_dir = data_dir.expanduser()
    cookie_file = cookie_file or (
        data_dir / ".cookie" if (data_dir / ".cookie").is_file() else None
    )
    try:
        rpc = BitcoinRPC(
            rpc_url,
            cookie_file=cookie_file,
            username=rpc_user,
            password=rpc_password or os.getenv("NODESENTRY_RPC_PASSWORD"),
        )
        findings.extend(check_chain(rpc.call("getblockchaininfo")))
        findings.extend(check_peers(rpc.call("getpeerinfo")))
    except RPCError as exc:
        evidence = str(exc)
        for check_id, title in (
            ("CHAIN-000", "Bitcoin Core chain evidence"),
            ("PEER-000", "Bitcoin Core peer evidence"),
        ):
            findings.append(
                Finding(
                    check_id,
                    title,
                    Status.UNKNOWN,
                    Severity.HIGH,
                    evidence,
                    "Start Bitcoin Core and provide read-only RPC credentials.",
                )
            )
    if bitcoin_conf:
        findings.extend(audit_config(bitcoin_conf.expanduser()))
    if data_dir.exists():
        findings.append(check_disk(data_dir))
    report = summarize(findings)
    _emit(report, output_format)
    raise click.exceptions.Exit(_exit_code(report.status))


@cli.group("config")
def config_group() -> None:
    """Audit static Bitcoin Core configuration."""


@config_group.command("audit")
@click.argument("path", type=click.Path(path_type=Path))
@click.option(
    "--format", "output_format", type=click.Choice(["terminal", "json"]), default="terminal"
)
def config_audit(path: Path, output_format: str) -> None:
    report = summarize(audit_config(path.expanduser()))
    _emit(report, output_format)
    raise click.exceptions.Exit(_exit_code(report.status))
