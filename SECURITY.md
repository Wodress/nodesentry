# Security Policy

## Scope

NodeSentry reads Bitcoin Core operational evidence. It must never require wallet keys,
seed words, signing authority, or transaction permissions.

## Reporting

Report vulnerabilities privately through GitHub Security Advisories for this repository.
Do not include live RPC cookies, passwords, peer addresses, wallet metadata, or operator
hostnames in a public issue.

## Operator rules

- Prefer a dedicated `rpcauth` identity constrained by `rpcwhitelistdefault=1` and an
  explicit `rpcwhitelist` containing only NodeSentry's observational methods.
- Bitcoin Core cookie authentication normally carries broad RPC authority. NodeSentry's
  internal method allowlist constrains honest execution but cannot make a stolen cookie
  read-only. Restrict cookie file access accordingly.
- Keep RPC on loopback. For remote administration, terminate an authenticated SSH tunnel
  on loopback or use correctly validated HTTPS.
- Mount only a dedicated credential file and a separate disk-probe path. Do not expose the
  full Bitcoin data directory, wallets, or logs to the container.
- Treat JSON reports as potentially sensitive operational evidence even though exact peer
  addresses and credentials are not rendered.
- NodeSentry does not make an exposed RPC endpoint safe; it only reports evidence.

## Supported versions

Only the latest tagged NodeSentry release receives security fixes during the MVP phase.