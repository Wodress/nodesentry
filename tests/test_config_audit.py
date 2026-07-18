from pathlib import Path

from nodesentry.checks.config import audit_config
from nodesentry.models import Status


def by_id(findings):
    return {item.check_id: item for item in findings}


def test_public_rpc_allow_rule_fails(tmp_path: Path):
    conf = tmp_path / "bitcoin.conf"
    conf.write_text("server=1\nrpcbind=0.0.0.0\nrpcallowip=0.0.0.0/0\n")
    result = by_id(audit_config(conf))
    assert result["RPC-001"].status is Status.FAIL
    assert "0.0.0.0/0" in result["RPC-001"].evidence


def test_loopback_rpc_configuration_passes(tmp_path: Path):
    conf = tmp_path / "bitcoin.conf"
    conf.write_text("server=1\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n")
    result = by_id(audit_config(conf))
    assert result["RPC-001"].status is Status.PASS


def test_embedded_rpc_password_fails_without_leaking_secret(tmp_path: Path):
    conf = tmp_path / "bitcoin.conf"
    conf.write_text("rpcpassword=correct-horse-battery-staple\n")
    result = by_id(audit_config(conf))
    finding = result["CONF-002"]
    assert finding.status is Status.FAIL
    assert "correct-horse" not in finding.evidence


def test_world_readable_config_warns(tmp_path: Path):
    conf = tmp_path / "bitcoin.conf"
    conf.write_text("server=1\n")
    conf.chmod(0o644)
    assert by_id(audit_config(conf))["CONF-001"].status is Status.WARN


def test_missing_config_is_unknown(tmp_path: Path):
    findings = audit_config(tmp_path / "missing.conf")
    assert len(findings) == 1
    assert findings[0].status is Status.UNKNOWN
