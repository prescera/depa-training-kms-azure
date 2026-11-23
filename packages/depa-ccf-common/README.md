# depa-ccf-common

Code shared verbatim by the DEPA Training v2 KMS and contract service (both CCF JavaScript
applications on Azure Confidential Ledger). The source of truth is
`depa-training-kms-azure/packages/depa-ccf-common`; `contract-service` vendors an exact copy
(`scripts/sync-common.sh`, verified by `scripts/check-common.sh`).

| Module | Purpose |
|---|---|
| `encoding`, `jcs` | strict base64/base64url/hex; RFC 8785 JCS and `digest(x)` |
| `jws` | ES256/ES384 compact JWS (raw r‖s, as CCF 6 produces and verifies), JWK validation, RFC 7638 thumbprints |
| `party`, `signed_request` | party registry; signed-request verification (aud, op, ±300 s iat, jti replay table, roles) |
| `governance` | proposals, ballots, thresholds, common actions, bootstrap, governance read endpoints |
| `releases`, `platforms`, `attestation`, `binding` | CCR release registry (immutable ids), attestation verification/normalization (aci-snp, gcp-cs-tdx, virtual), run binding hash |
| `settings`, `service_keys`, `tokens` | settings, JWT validation policies, pinned peers, approved app digests; in-CCF ES256 keys; RAT and release-receipt checks |
| `http`, `errors`, `logger`, `kv`, `time`, `acl`, `service` | endpoint wrapper, typed errors, logging, JSON KV tables, time/UUIDs, ACL operator auth, `/info` and `/receipt` |

Tests in `test/` run in both repositories with a Node shim of the CCF runtime (`ccf-shim.ts`).
