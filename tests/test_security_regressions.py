import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nodesentry.checks.config import audit_config
from nodesentry.checks.peers import check_peers
from nodesentry.cli import cli
from nodesentry.models import Finding, Severity, Status, summarize
from nodesentry.rpc import BitcoinRPC, RPCError


def by_id(findings):
    return {item.check_id: item for item in findings}


def finding(status: Status) -> Finding:
    return Finding("TEST-001", "Test", status, Severity.MEDIUM, "evidence", "remediation")


def test_public_specific_bind_and_allow_network_fail(tmp_path: Path):
    conf = tmp_path / "bitcoin.conf"
    conf.write_text("rpcbind=203.0.113.2\nrpcallowip=203.0.113.0/24\n")
    assert by_id(audit_config(conf))["RPC-001"].status is Status.FAIL


def test_private_lan_rpc_scope_warns(tmp_path: Path):
    conf = tmp_path / "bitcoin.conf"
    conf.write_text("rpcbind=192.168.1.2\nrpcallowip=192.168.1.0/24\n")
    assert by_id(audit_config(conf))["RPC-001"].status is Status.WARN


def test_unresolved_include_never_passes_affected_checks(tmp_path: Path):
    conf = tmp_path / "bitcoin.conf"
    conf.write_text("includeconf=unsafe.conf\n")
    result = by_id(audit_config(conf))
    assert result["CONF-002"].status is Status.UNKNOWN
    assert result["RPC-001"].status is Status.UNKNOWN


def test_unknown_required_evidence_has_precedence_over_warning():
    assert summarize([finding(Status.UNKNOWN), finding(Status.WARN)]).status is Status.UNKNOWN


def test_many_inbound_peers_do_not_mask_weak_outbound_count():
    peers = [
        {"addr": f"10.0.{i}.1:8333", "network": "ipv4", "inbound": True} for i in range(12)
    ] + [{"addr": f"{20 + i}.0.0.1:8333", "network": "ipv4", "inbound": False} for i in range(2)]
    result = by_id(check_peers(peers))
    assert result["PEER-001"].status is Status.WARN
    assert "Outbound peers: 2" in result["PEER-001"].evidence


def test_malformed_outbound_peer_data_is_unknown():
    assert by_id(check_peers([{"inbound": False}]))["PEER-002"].status is Status.UNKNOWN


class Response:
    def __init__(self, payload):
        self.payload = payload

    def read(self, limit=-1):
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.mark.parametrize("payload", [[], {"error": None, "id": "nodesentry"}])
def test_malformed_rpc_response_becomes_sanitized_rpc_error(monkeypatch, payload):
    monkeypatch.setattr("nodesentry.rpc.urlopen", lambda req, timeout: Response(payload))
    with pytest.raises(RPCError, match="malformed"):
        BitcoinRPC("http://127.0.0.1:8332", username="x", password="y").call("getpeerinfo")


@pytest.mark.parametrize(
    "url",
    ["http://[::ffff:127.0.0.1]:8332", "http://127.0.0.1:bad"],
)
def test_ambiguous_or_invalid_loopback_urls_are_rejected(url):
    with pytest.raises(RPCError):
        BitcoinRPC(url, username="x", password="y")


def test_peer_rpc_failure_preserves_successful_chain_evidence(monkeypatch):
    chain = {
        "mediantime": 9999999999,
        "initialblockdownload": False,
        "blocks": 10,
        "headers": 10,
        "verificationprogress": 1,
    }

    def call(self, method, params=None):
        if method == "getblockchaininfo":
            return chain
        raise RPCError("peer RPC unavailable")

    monkeypatch.setattr("nodesentry.cli.BitcoinRPC.call", call)
    result = CliRunner().invoke(
        cli,
        ["audit", "--rpc-user", "x", "--format", "json"],
        env={"NODESENTRY_RPC_PASSWORD": "y"},
    )
    payload = json.loads(result.output)
    findings = {item["id"]: item for item in payload["findings"]}
    assert findings["CHAIN-001"]["status"] == "pass"
    assert "CHAIN-000" not in findings
    assert findings["PEER-000"]["status"] == "unknown"
    assert result.exit_code == 2


def test_rpc_password_cli_option_is_not_accepted():
    result = CliRunner().invoke(cli, ["audit", "--rpc-password", "secret"])
    assert result.exit_code == 2
    assert "No such option" in result.output


def test_invalid_rpc_url_still_emits_machine_readable_unknown():
    result = CliRunner().invoke(
        cli,
        ["audit", "--rpc-url", "http://127.0.0.1:bad", "--format", "json"],
    )
    payload = json.loads(result.output)
    assert result.exit_code == 2
    assert payload["status"] == "unknown"


def test_wrong_result_type_becomes_rpc_error(monkeypatch):
    payload = {"result": {}, "error": None, "id": "nodesentry"}
    monkeypatch.setattr("nodesentry.rpc.urlopen", lambda req, timeout: Response(payload))
    with pytest.raises(RPCError, match="result"):
        BitcoinRPC("http://127.0.0.1:8332", username="x", password="y").call("getpeerinfo")
