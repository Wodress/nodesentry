from __future__ import annotations

import ipaddress
import stat
from pathlib import Path

from nodesentry.models import Finding, Severity, Status

_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def _parse(path: Path) -> tuple[dict[str, list[str]], bool]:
    values: dict[str, list[str]] = {}
    unresolved = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            unresolved = True
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        values.setdefault(key, []).append(value.strip())
        if key == "includeconf":
            unresolved = True
    return values, unresolved


def _scope(value: str) -> str:
    host = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    host = host.strip("[]")
    if host in {"0.0.0.0", "::", "*"}:
        return "public"
    if host == "localhost":
        return "loopback"
    try:
        network = ipaddress.ip_network(host, strict=False)
    except ValueError:
        return "unknown"
    if network.is_loopback:
        return "loopback"
    if network.is_link_local or any(
        network.version == private.version and network.subnet_of(private)
        for private in _PRIVATE_NETWORKS
    ):
        return "private"
    return "public"


def audit_config(path: Path) -> list[Finding]:
    if not path.is_file():
        return [
            Finding(
                "CONF-000",
                "Bitcoin configuration available",
                Status.UNKNOWN,
                Severity.MEDIUM,
                f"Configuration not found: {path}",
                "Provide the effective bitcoin.conf path.",
            )
        ]
    config, unresolved = _parse(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    permission_status = Status.WARN if mode & 0o077 else Status.PASS
    findings = [
        Finding(
            "CONF-001",
            "Configuration file permissions",
            permission_status,
            Severity.MEDIUM,
            f"Mode is {mode:04o}; file contents were not copied into the report.",
            "Restrict the file to the Bitcoin service account (chmod 600).",
        )
    ]
    has_password = bool(config.get("rpcpassword"))
    password_status = Status.FAIL if has_password else Status.UNKNOWN if unresolved else Status.PASS
    password_evidence = (
        "rpcpassword directive is present; value redacted."
        if has_password
        else "Included or network-specific configuration is unresolved."
        if unresolved
        else "No rpcpassword directive found."
    )
    findings.append(
        Finding(
            "CONF-002",
            "No plaintext RPC password",
            password_status,
            Severity.HIGH,
            password_evidence,
            "Prefer a dedicated rpcauth user constrained by rpcwhitelist.",
        )
    )

    scopes = [_scope(value) for key in ("rpcbind", "rpcallowip") for value in config.get(key, [])]
    if "public" in scopes:
        exposure_status = Status.FAIL
        exposure_evidence = "Non-loopback public RPC bind or allow scope detected; values redacted."
    elif "private" in scopes:
        exposure_status = Status.WARN
        exposure_evidence = (
            "RPC is reachable from a private or link-local network; values redacted."
        )
    elif unresolved or "unknown" in scopes:
        exposure_status = Status.UNKNOWN
        exposure_evidence = "Effective RPC exposure cannot be proven from this configuration view."
    else:
        exposure_status = Status.PASS
        exposure_evidence = "RPC directives are absent or restricted to loopback."
    findings.append(
        Finding(
            "RPC-001",
            "RPC network exposure",
            exposure_status,
            Severity.CRITICAL,
            exposure_evidence,
            "Bind RPC to loopback and allow only exact management hosts.",
        )
    )
    return findings
