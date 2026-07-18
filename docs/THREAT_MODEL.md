# Threat Model

## Protect

Bitcoin Core RPC credentials, node addresses, wallet metadata, operator privacy, and report integrity.

## Adversaries

Internet scanners, malicious LAN peers, hostile containers, compromised dependencies, eclipse attempts, accidental operator misconfiguration, and misleading absence of data.

## Boundaries

NodeSentry does not hold keys, sign transactions, alter `bitcoin.conf`, open ports, or decide consensus. MVP peer concentration uses local network groups rather than third-party ASN APIs to avoid leaking peer addresses.

## Controls

Read-only RPC calls, credential redaction, local execution, no telemetry, bounded HTTP responses, deterministic checks, explicit `UNKNOWN`, restrictive container capabilities, and stable finding IDs.
