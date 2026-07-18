import pytest

from nodesentry.rpc import BitcoinRPC, RPCError


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.10:8332",
        "http://bitcoin-node.local:8332",
        "http://localhost.evil.example:8332",
        "http://127.0.0.1.evil.example:8332",
        "ftp://127.0.0.1:8332",
        "https://alice:secret@node.example:8332",
    ],
)
def test_plaintext_or_unsupported_remote_rpc_is_rejected(url):
    with pytest.raises(RPCError):
        BitcoinRPC(url, username="x", password="y")


def test_https_remote_rpc_is_allowed():
    BitcoinRPC("https://node.example:8332", username="x", password="y")
