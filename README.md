# NodeSentry

**A local-first sovereignty auditor for Bitcoin Core.**

NodeSentry answers a harder question than “is `bitcoind` running?” It inspects chain state, peer topology, RPC exposure, configuration hygiene, and host storage, then emits deterministic findings with evidence and remediation.

> No token. No telemetry. No custody. No mandatory cloud.

## Why

A synchronized node can still expose RPC, depend on a narrow peer set, run out of disk, or quietly lack evidence. Metrics show numbers. NodeSentry interprets their operational and security meaning without asking a third-party API what your own node should believe.

## Install

```bash
git clone https://github.com/Wodress/nodesentry
cd nodesentry
uv venv .venv --python 3.11
uv pip install -e . --python .venv/bin/python
```

## Use

```bash
# Cookie authentication from the default ~/.bitcoin directory
.venv/bin/nodesentry audit

# Explicit cookie and data directory
.venv/bin/nodesentry audit \
  --cookie-file ~/.bitcoin/.cookie \
  --data-dir ~/.bitcoin

# Machine-readable evidence
.venv/bin/nodesentry audit --format json

# Offline configuration audit; no running node needed
.venv/bin/nodesentry config audit ~/.bitcoin/bitcoin.conf
```

Remote plaintext RPC is rejected. Use loopback, an SSH tunnel terminating on loopback, or HTTPS. Passwords may be supplied through `NODESENTRY_RPC_PASSWORD`, but cookie authentication is preferred.

## Example without a running node

```text
NODE SOVEREIGNTY: 0/100  UNKNOWN

????  CHAIN-000  Bitcoin Core chain evidence
      RPC credentials missing
      → Start Bitcoin Core and provide read-only RPC credentials.
????  PEER-000   Bitcoin Core peer evidence
      RPC credentials missing
      → Start Bitcoin Core and provide read-only RPC credentials.
```

`UNKNOWN` is not painted green. Absence of evidence is not evidence of sovereignty.

## Current deterministic checks

| ID | Evidence |
|---|---|
| `CHAIN-001` | Median chain-tip age |
| `CHAIN-002` | Initial block download status |
| `CHAIN-003` | Header gap and verification progress |
| `PEER-001` | Connected peer count |
| `PEER-002` | Outbound local network-group concentration |
| `RPC-001` | Wildcard `rpcbind` / `rpcallowip` exposure |
| `CONF-001` | `bitcoin.conf` file permissions |
| `CONF-002` | Plaintext `rpcpassword` directive |
| `DISK-001` | Free-space safety floor |

Peer reports redact exact addresses. MVP uses local IPv4 `/16`, IPv6 prefix, Tor and I2P groups; it deliberately avoids third-party ASN lookups that would disclose peer addresses.

## Exit codes

- `0`: pass
- `1`: warning or failure
- `2`: unknown because required evidence was unavailable

## Security model

- allowlisted read-only RPC methods only
- no wallet methods, keys, seeds, signing, or transactions
- no automatic configuration changes
- no telemetry or external HTTP calls
- credentials never rendered in reports
- bounded RPC response reads
- public findings preserve evidence while redacting secrets and peer addresses

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`docs/DEFINITION_OF_DONE.md`](docs/DEFINITION_OF_DONE.md).

## Container

```bash
cp .env.example .env
# Set BITCOIN_DATA_DIR to a host path containing .cookie and optionally bitcoin.conf
docker compose run --rm nodesentry
```

The container is read-only, drops every Linux capability, enables `no-new-privileges`, mounts Bitcoin data read-only, and uses host networking so loopback RPC remains loopback. On macOS Docker Desktop, host networking must be enabled; otherwise use HTTPS or an explicit loopback tunnel. NodeSentry rejects plaintext remote RPC by design.

## Development

```bash
uv sync --extra dev
uv run pytest --cov=nodesentry --cov-report=term-missing
uv run ruff check .
uv run python -m build
uv run pip-audit
```

## Verified smoke evidence

The MVP was exercised against a real `bitcoin/bitcoin:31.1` process in Docker regtest,
not only mocked RPC responses. After mining 101 blocks, Bitcoin Core reported
`blocks=101`, `headers=101`, `verificationprogress=1`, and
`initialblockdownload=false`. NodeSentry then returned:

- `CHAIN-001`: pass — fresh median time
- `CHAIN-002`: pass — IBD complete
- `CHAIN-003`: pass — headers and validation complete
- `PEER-001` / `PEER-002`: warn — expected for an isolated regtest node with zero peers
- `DISK-001`: pass

The resulting overall status was `warn` with exit code `1`, as designed. A closed-port
test separately returns `unknown` with exit code `2`; missing evidence is never green.

## Honest limitations

- Live smoke coverage currently uses isolated regtest; mainnet topology and long-running degradation still require operator validation.
- Peer concentration is a heuristic, not proof of an eclipse attack.
- Disk MVP checks a safety floor, not historical growth runway.
- Includes and network-specific sections in `bitcoin.conf` are not yet resolved into Bitcoin Core's full effective configuration.
- Backup recovery drills, Prometheus, alerts, ASN enrichment and signed reports are roadmap items.

## License

MIT. Bitcoin only.
