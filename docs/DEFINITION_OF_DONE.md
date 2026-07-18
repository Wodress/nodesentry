# Definition of Done — MVP

- [x] `nodesentry audit` produces deterministic terminal output.
- [x] `nodesentry audit --format json` emits schema-stable JSON.
- [x] Cookie and user/password RPC authentication work without secret disclosure.
- [x] Chain freshness, IBD, verification progress and peer-count checks exist.
- [x] Peer network-group concentration is assessed without external lookups.
- [x] `nodesentry config audit PATH` detects public RPC exposure and file-permission risks.
- [x] Disk free-space check exists and reports evidence.
- [x] RPC failure yields `UNKNOWN`, not a false green result.
- [x] Critical failures force the overall verdict to `FAIL`.
- [x] Tests, coverage, Ruff, package build and dependency audit pass.
- [x] Docker and systemd examples use least privilege.
- [x] README documents security model, limitations and real smoke evidence.
- [x] Git repository has a clean working tree and public GitHub remote.
