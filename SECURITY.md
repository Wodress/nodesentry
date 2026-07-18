# Security Policy

## Scope

NodeSentry reads Bitcoin Core operational evidence. It must never require wallet keys,
seed words, signing authority, or transaction permissions.

## Reporting

Report vulnerabilities privately through GitHub Security Advisories for this repository.
Do not include live RPC cookies, passwords, peer addresses, wallet metadata, or operator
hostnames in a public issue.

## Operator rules

- Prefer Bitcoin Core cookie authentication on the same host.
- Keep RPC on loopback. For remote administration, terminate an authenticated SSH tunnel
  on loopback or use correctly validated HTTPS.
- Mount Bitcoin data read-only when using the container.
- Treat JSON reports as potentially sensitive operational evidence even though exact peer
  addresses and credentials are not rendered.
- NodeSentry does not make an exposed RPC endpoint safe; it only reports evidence.

## Supported versions

Only the latest tagged NodeSentry release receives security fixes during the MVP phase.