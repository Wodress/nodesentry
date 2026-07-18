import json
from pathlib import Path

from click.testing import CliRunner

from nodesentry.cli import cli


def test_config_audit_json_is_machine_readable(tmp_path: Path):
    conf = tmp_path / "bitcoin.conf"
    conf.write_text("rpcbind=127.0.0.1\n")
    conf.chmod(0o600)
    result = CliRunner().invoke(cli, ["config", "audit", str(conf), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1"
    assert payload["status"] == "pass"


def test_audit_rpc_failure_is_unknown_not_crash():
    result = CliRunner().invoke(
        cli, ["audit", "--rpc-url", "http://127.0.0.1:1", "--format", "json"]
    )
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["status"] == "unknown"
    assert all(
        item["status"] == "unknown"
        for item in payload["findings"]
        if item["id"].startswith(("CHAIN", "PEER"))
    )
