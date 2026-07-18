from __future__ import annotations

from datetime import UTC, datetime

from nodesentry.models import Finding, Severity, Status


def check_chain(info: dict, *, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(UTC)
    age = max(0, int(now.timestamp()) - int(info.get("mediantime", 0)))
    stale = age > 3600
    ibd = bool(info.get("initialblockdownload", True))
    blocks, headers = int(info.get("blocks", 0)), int(info.get("headers", 0))
    progress = float(info.get("verificationprogress", 0))
    return [
        Finding(
            "CHAIN-001",
            "Chain tip freshness",
            Status.FAIL if stale else Status.PASS,
            Severity.HIGH,
            f"Median-time age: {age} seconds.",
            "Check connectivity, clock, peers, disk and Bitcoin Core logs.",
        ),
        Finding(
            "CHAIN-002",
            "Initial block download complete",
            Status.WARN if ibd else Status.PASS,
            Severity.MEDIUM,
            f"initialblockdownload={str(ibd).lower()}.",
            "Wait for IBD to complete before relying on node-backed applications.",
        ),
        Finding(
            "CHAIN-003",
            "Headers and verification progress",
            Status.WARN if headers - blocks > 2 or progress < 0.999 else Status.PASS,
            Severity.MEDIUM,
            f"blocks={blocks}, headers={headers}, verification={progress:.6f}.",
            "Investigate stalled validation or constrained host resources.",
        ),
    ]
