# NodeSentry Goal

NodeSentry is a local-first, read-only sovereignty auditor for Bitcoin Core.
It turns node state, peer topology, host storage, and `bitcoin.conf` into deterministic findings with evidence and remediation.

## Principles

- Bitcoin only. No tokens, custody, telemetry, or mandatory cloud.
- Read-only by default; never change Bitcoin Core configuration.
- Missing evidence is `UNKNOWN`, never `PASS`.
- Critical findings override cosmetic aggregate scores.
- Secrets never appear in reports or logs.
- The operator's own node is authoritative; external APIs are optional evidence, never consensus.

## MVP end state

A packaged CLI that audits a live Bitcoin Core node or static configuration, emits terminal and JSON reports, degrades honestly when RPC is unavailable, and ships with tested Docker/systemd deployment examples.
