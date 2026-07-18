from __future__ import annotations

import base64
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class RPCError(RuntimeError):
    pass


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


urlopen = build_opener(_RejectRedirects()).open


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
    EXPECTED_RESULT_TYPES = {
        "getblockchaininfo": dict,
        "getnetworkinfo": dict,
        "getpeerinfo": list,
        "getmempoolinfo": dict,
        "getnettotals": dict,
        "uptime": int,
    }

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
        try:
            port = parsed.port
        except ValueError as exc:
            raise RPCError("RPC URL has an invalid port") from exc
        if not parsed.hostname or port is None:
            raise RPCError("RPC URL must include a host and explicit port")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            loopback = parsed.hostname == "localhost"
        else:
            loopback = address.is_loopback and not getattr(address, "ipv4_mapped", None)
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
        if not isinstance(payload, dict) or payload.get("id") != "nodesentry":
            raise RPCError("Bitcoin Core returned a malformed RPC response")
        if payload.get("error"):
            raise RPCError("Bitcoin Core returned an RPC error")
        if "result" not in payload:
            raise RPCError("Bitcoin Core returned a malformed RPC response without a result")
        result = payload["result"]
        if not isinstance(result, self.EXPECTED_RESULT_TYPES[method]):
            raise RPCError("Bitcoin Core returned a malformed RPC result")
        return result
