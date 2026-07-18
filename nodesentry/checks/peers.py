from __future__ import annotations

import ipaddress
from collections import Counter

from nodesentry.models import Finding, Severity, Status


def _host(addr: str) -> str:
    if addr.startswith("["):
        return addr[1:].split("]", 1)[0]
    return addr.rsplit(":", 1)[0]


def network_group(addr: str, network: str) -> str:
    network = network.lower()
    if network in {"onion", "i2p", "cjdns"}:
        return network
    try:
        ip = ipaddress.ip_address(_host(addr))
    except ValueError:
        return network or "unknown"
    if ip.version == 4:
        octets = str(ip).split(".")
        return f"ipv4:{octets[0]}.{octets[1]}"
    parts = ip.compressed.split(":")
    return f"ipv6:{parts[0]}:{parts[1]}"


def check_peers(peers: list[dict]) -> list[Finding]:
    total = len(peers)
    outbound = [peer for peer in peers if not peer.get("inbound", False)]
    count_status = Status.PASS if len(outbound) >= 8 else Status.WARN
    malformed = any(not peer.get("addr") or not peer.get("network") for peer in outbound)
    groups = Counter(
        network_group(str(peer.get("addr", "")), str(peer.get("network", "unknown")))
        for peer in outbound
    )
    dominant = max(groups.values(), default=0)
    ratio = dominant / len(outbound) if outbound else 1.0
    diversity_status = (
        Status.UNKNOWN
        if malformed
        else Status.WARN
        if len(outbound) < 4 or ratio > 0.5
        else Status.PASS
    )
    return [
        Finding(
            "PEER-001",
            "Outbound peer count",
            count_status,
            Severity.MEDIUM,
            f"Outbound peers: {len(outbound)}; inbound peers: {total - len(outbound)}.",
            "Maintain at least eight independently selected outbound peers.",
        ),
        Finding(
            "PEER-002",
            "Outbound network-group diversity",
            diversity_status,
            Severity.HIGH,
            (
                f"Outbound peers={len(outbound)}, groups={len(groups)}, "
                f"dominant share={ratio:.0%}; exact addresses redacted."
            ),
            "Diversify connectivity across IPv4/IPv6/Tor/I2P and network groups.",
        ),
    ]
