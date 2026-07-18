import base64
import json
from pathlib import Path

import pytest

from nodesentry.rpc import BitcoinRPC, RPCError


class Response:
    def __init__(self, payload, status=200):
        self.payload = payload
        self.status = status

    def read(self, limit=-1):
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_cookie_auth_and_read_only_method(monkeypatch, tmp_path: Path):
    cookie = tmp_path / ".cookie"
    cookie.write_text("__cookie__:secret")
    captured = {}

    def opener(req, timeout):
        captured["auth"] = req.headers["Authorization"]
        captured["body"] = json.loads(req.data)
        return Response({"result": {"blocks": 1}, "error": None, "id": "nodesentry"})

    monkeypatch.setattr("nodesentry.rpc.urlopen", opener)
    result = BitcoinRPC("http://127.0.0.1:8332", cookie_file=cookie).call("getblockchaininfo")
    assert result == {"blocks": 1}
    assert captured["auth"] == "Basic " + base64.b64encode(b"__cookie__:secret").decode()
    assert captured["body"]["method"] == "getblockchaininfo"


def test_disallowed_mutating_rpc_method_is_rejected():
    with pytest.raises(RPCError, match="not allowed"):
        BitcoinRPC("http://127.0.0.1:8332", username="x", password="y").call("sendtoaddress")


def test_error_does_not_expose_password(monkeypatch):
    def opener(req, timeout):
        raise OSError("network down")

    monkeypatch.setattr("nodesentry.rpc.urlopen", opener)
    with pytest.raises(RPCError) as exc:
        BitcoinRPC("http://127.0.0.1:8332", username="alice", password="supersecret").call(
            "getpeerinfo"
        )
    assert "supersecret" not in str(exc.value)
