from __future__ import annotations

import base64
import json
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class RPCError(RuntimeError):
    pass


class BitcoinRPC:
    ALLOWED_METHODS = frozenset(
        {
            "getblockchaininfo",
            "getnetworkinfo",
            "getpeerinfo",
            "getmempoolinfo",
            "getnettotals",
            "uptime",
        }
    )

    def __init__(
        self,
        url: str,
        *,
        cookie_file: Path | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 5.0,
    ):
        parsed = urlsplit(url)
        loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        if parsed.scheme not in {"http", "https"} or (parsed.scheme == "http" and not loopback):
            raise RPCError("Plaintext RPC is restricted to loopback; use HTTPS for remote nodes")
        if parsed.username or parsed.password or parsed.fragment:
            raise RPCError("RPC URL must not contain credentials or a fragment")
        self.url, self.cookie_file, self.username, self.password, self.timeout = (
            url,
            cookie_file,
            username,
            password,
            timeout,
        )

    def _credentials(self) -> str:
        if self.cookie_file:
            try:
                return self.cookie_file.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise RPCError("Unable to read RPC cookie") from exc
        if self.username is None or self.password is None:
            raise RPCError("RPC credentials missing")
        return f"{self.username}:{self.password}"

    def call(self, method: str, params: list | None = None):
        if method not in self.ALLOWED_METHODS:
            raise RPCError(f"RPC method not allowed in read-only policy: {method}")
        auth = base64.b64encode(self._credentials().encode()).decode()
        body = json.dumps(
            {"jsonrpc": "2.0", "id": "nodesentry", "method": method, "params": params or []}
        ).encode()
        request = Request(  # noqa: S310 -- scheme and host policy validated above
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # noqa: S310 -- URL policy enforced in constructor
                payload = json.loads(response.read(2_000_000))
        except Exception as exc:
            raise RPCError(f"RPC request failed: {type(exc).__name__}") from exc
        if payload.get("error"):
            raise RPCError("Bitcoin Core returned an RPC error")
        return payload.get("result")
