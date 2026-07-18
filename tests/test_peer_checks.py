from nodesentry.checks.peers import check_peers, network_group
from nodesentry.models import Status


def by_id(findings):
    return {item.check_id: item for item in findings}


def test_network_group_redacts_precise_addresses():
    assert network_group("203.0.113.42:8333", "ipv4") == "ipv4:203.0"
    assert network_group("[2001:db8:abcd::1]:8333", "ipv6") == "ipv6:2001:db8"
    assert network_group("examplehiddenservice.onion:8333", "onion") == "onion"


def test_low_peer_count_warns():
    peers = [{"addr": f"10.0.{i}.1:8333", "network": "ipv4", "inbound": False} for i in range(3)]
    assert by_id(check_peers(peers))["PEER-001"].status is Status.WARN


def test_concentrated_outbound_peers_warn_without_reporting_addresses():
    peers = [{"addr": f"203.0.113.{i}:8333", "network": "ipv4", "inbound": False} for i in range(8)]
    finding = by_id(check_peers(peers))["PEER-002"]
    assert finding.status is Status.WARN
    assert "203.0.113." not in finding.evidence


def test_diverse_peers_pass():
    peers = [
        {"addr": f"{20 + i}.0.0.1:8333", "network": "ipv4", "inbound": False} for i in range(8)
    ]
    result = by_id(check_peers(peers))
    assert result["PEER-001"].status is Status.PASS
    assert result["PEER-002"].status is Status.PASS
