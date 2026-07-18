from __future__ import annotations

import ipaddress
import stat
from pathlib import Path

from nodesentry.models import Finding, Severity, Status


def _parse(path: Path) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values.setdefault(key.strip().lower(), []).append(value.strip())
    return values


def _is_public(value: str) -> bool:
    host = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    host = host.strip("[]")
    if host in {"0.0.0.0", "::", "*"}:
        return True
    try:
        network = ipaddress.ip_network(host, strict=False)
    except ValueError:
        return False
    return network.prefixlen == 0


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
    config = _parse(path)
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
    findings.append(
        Finding(
            "CONF-002",
            "No plaintext RPC password",
            Status.FAIL if has_password else Status.PASS,
            Severity.HIGH,
            "rpcpassword directive is present; value redacted."
            if has_password
            else "No rpcpassword directive found.",
            "Prefer Bitcoin Core cookie authentication or rpcauth.",
        )
    )
    dangerous = [
        value
        for key in ("rpcbind", "rpcallowip")
        for value in config.get(key, [])
        if _is_public(value)
    ]
    findings.append(
        Finding(
            "RPC-001",
            "RPC network exposure",
            Status.FAIL if dangerous else Status.PASS,
            Severity.CRITICAL,
            "Public RPC scope detected: " + ", ".join(dangerous)
            if dangerous
            else "No wildcard RPC bind or allow rule detected.",
            "Bind RPC to loopback and allow only exact management hosts.",
        )
    )
    return findings
