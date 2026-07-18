# Threat Model

## Protect

Bitcoin Core RPC credentials, node addresses, wallet metadata, operator privacy, and report integrity.

## Adversaries

Internet scanners, malicious LAN peers, hostile containers, compromised dependencies, eclipse attempts, accidental operator misconfiguration, and misleading absence of data.

## Boundaries

NodeSentry does not hold keys, sign transactions, alter `bitcoin.conf`, open ports, or decide consensus. MVP peer concentration uses local network groups rather than third-party ASN APIs to avoid leaking peer addresses.

## Controls

Client-side allowlisted observational RPC calls, credential redaction, redirect rejection,
strict RPC URL parsing, local execution, no telemetry, bounded HTTP responses, deterministic
checks, explicit `UNKNOWN`, restrictive container capabilities, and stable finding IDs.

The Bitcoin Core cookie is not a read-only credential. Server-side least privilege requires
a dedicated `rpcauth` user constrained with `rpcwhitelistdefault=1` and `rpcwhitelist`.
