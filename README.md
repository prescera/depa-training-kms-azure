# DEPA Training v2 — KMS (`depa-kms`)

A CCF JavaScript application, hosted on Azure Confidential Ledger (ACL), that is one of the
two Data Collaborative (DC) trust services of DEPA Training v2. The model comes to the data:
a dataset's decryption key is released only to an attested confidential clean room (CCR)
running an approved image, for a run the contract service has authorised, and only if the
dataset owner's release policy allows it.

The normative protocol is `docs/specs/protocol.md` in the `depa-training` repository; section
references (§) below point there.

## What the KMS holds

| State | Owner | Changed by |
|---|---|---|
| Per-dataset X25519 HPKE key pairs (`<dataset_id>#n`), private halves in a ledger-encrypted table | TDP | owner signed requests (`dataset.create`, `dataset.rotate`) |
| Release policy v1 per dataset, versioned with history | TDP | owner signed requests only (`dataset.set_policy`) |
| Owner / DC suspensions | TDP / DC | owner (`dataset.suspend`/`resume`); DC may only add or lift its *own* suspension |
| CCR release registry (§6) | DC | governance (`approve_ccr_release`, `revoke_ccr_release`); release ids are immutable |
| Parties, members, constitution, settings, pinned CS JWKS, JWT validation policies, approved app digests | DC | app-level governance (§4) |
| Service signing key (ES256) and OIDC issuer key (ES256) | service | generated inside CCF at bootstrap, never exported |
| Key release log, per-(dataset, contract) run counters, issued-token log | service | `/keys/release`, `/oidc/token` |

Governance can never modify a TDP's policy or keys: no such action exists.

## Role in a run

1. The CCR obtains a Run Authorization Token (RAT) from the contract service (CS).
2. `POST /keys/release` — in **one transaction** the KMS checks (§9.4): the binding's
   `trust_bundle_digest` equals the governance setting (required for non-virtual platforms,
   §9.1, so substituted trust anchors never obtain keys); attestation (aci-snp,
   gcp-cs-tdx, or development-only virtual) proves the binding hash; the wrapping key hash
   matches the binding; the RAT is signed by the pinned CS key, fresh (≤ 300 s) and issued for
   exactly this binding and attested measurement; the measurement belongs to an approved,
   non-revoked release listed in `rat.ccr_releases` for the RAT tier (tier 3: listed in the
   dataset policy's `allowed_custom_measurements`); the dataset is in the run and not
   suspended; the release policy allows platform, tier, TDC, purpose, privacy budget, output
   mode, `not_after` and `max_runs_per_contract`. It records the release and returns the
   private keys wrapped with RSA-OAEP-SHA256 plus a signed release receipt.
3. `POST /oidc/token` — the same run checks plus the audience allowlist, then a short-lived
   federation token (`sub = dataset:<id>` or `output:<tdc>`) the CCR exchanges with the cloud
   STS for read access to ciphertext (or write access to the output location).
4. Output mode `tee-only`: `POST /outputs/{contract_id}/key` gives the CCR a per-contract X25519
   public key; the private key is released only to an attested workload whose measurement is in
   an approved release with family `inference`.

## Dataset keys and release policies (how providers use this service)

There is no key import: the KMS generates each dataset's HPKE key pair, and the provider
encrypts locally with the public key. Only the dataset owner can set or change its release
policy, and clean rooms obtain the private key only through the atomic `/keys/release` check.

```bash
depa --party bank-a dataset create-key <dataset template>   # key pair generated in the KMS
depa --party bank-a dataset policy set <dataset template>   # owner-only release policy
depa --party bank-a dataset encrypt <dataset template> --out ./enc
depa --party bank-a dataset suspend bank-a/credit-applications   # kill switch
```

Walkthrough: [identities, contracts and keys](https://github.com/prescera/depa-training/blob/main/docs/guides/identities-contracts-keys.md).

## API

All paths are under `/app` on ACL and on the CCF sandbox. "signed" = body `{"jws": …}` with a
party signature (§3.2); "attested" = attestation envelope in the body (gcp-cs-tdx: GCA token as
`Authorization: Bearer`). Full request/response details: [docs/api.md](docs/api.md).

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/info` | — | service, version, `bundle_digest`, `bundle_digest_approved`, service JWKS, OIDC issuer + JWKS |
| GET | `/receipt?transaction_id=` | — | CCF receipt for a transaction (202 while fetching) |
| POST | `/gov/bootstrap` | ACL Administrator (sandbox: CCF user cert) | one-time bootstrap |
| POST/GET | `/gov/proposals` | signed (dc-member) / — | propose, list |
| GET | `/gov/proposals/{id}` | — | proposal with tally |
| POST | `/gov/proposals/{id}/ballots` | signed (dc-member) | vote |
| GET | `/gov/members`, `/gov/constitution`, `/gov/state` | — | governance state |
| GET | `/parties`, `/parties/{id}`, `/releases`, `/releases/{id}` | — | registries |
| POST | `/datasets` | signed (owner) | create dataset + key `#1` |
| GET | `/datasets/{owner}/{name}` | — | keys, policy, state |
| PUT | `/datasets/{owner}/{name}/policy` | signed (owner) | set release policy |
| GET | `/datasets/{owner}/{name}/policy/history` | — | policy versions with signed requests |
| POST | `/datasets/{owner}/{name}/rotate` · `/suspend` · `/resume` | signed (owner) | key rotation, owner kill switch |
| POST | `/keys/release` | attested + RAT | atomic key release |
| GET | `/key-releases/{release_id}` | — | release record |
| GET | `/oidc/.well-known/openid-configuration`, `/oidc/jwks` | — | OIDC discovery |
| POST | `/oidc/token` | attested + RAT | storage federation token |
| POST | `/outputs/{contract_id}/key` | attested + RAT | tee-only output public key |
| POST | `/outputs/{contract_id}/release` | attested (inference release) | output private key release |

Governance actions: common (`set_member`, `remove_member`, `set_party`, `remove_party`,
`set_constitution`, `set_peer_service`, `set_jwt_validation_policy`, `set_settings`,
`approve_app_digest`, `approve_ccr_release`, `revoke_ccr_release`) and KMS-only
(`set_oidc_settings`, `suspend_dataset`, `resume_dataset`).

## Local development

Requirements: Node ≥ 18, Docker, jq, Python ≥ 3.10 (integration tests).

```bash
make build              # tsc + rollup + dist/bundle.json, dist/bundle_digest.txt
make test               # unit tests (jest; Node shim of the CCF runtime)
make sandbox-up         # CCF virtual sandbox on 127.0.0.1:18010 with the app
make test-integration   # both services in two sandboxes, end-to-end (needs ../contract-service)
make check-common       # shared code identical to ../contract-service
```

### Sandbox script interface (stable)

```
scripts/sandbox-up.sh <port> [--jwt-issuer <issuer.json>] [--no-build] [--recreate]
scripts/sandbox-down.sh [<port> | --all] [--purge]
```

- `<port>` must be in 18000–18199. Container: `depa2-dc-kms-<port>`; image
  `depa2-dc-ccf-sandbox:6.0.0-rc1` (built from `docker/Dockerfile.ccf-sandbox`).
- Idempotent: a running sandbox with the same bundle digest and issuer file is reused (state
  kept); otherwise a fresh network is started. `--recreate` forces a fresh network.
- stdout is one JSON line: `url`, `app_url` (base URL for all API calls), `service_cert` (TLS
  trust anchor), `user_cert`/`user_key` (operator identity for `/gov/bootstrap` on the sandbox),
  `member_cert`/`member_key` (CCF member, for CCF-level proposals), `container`,
  `bundle_digest`, `workspace`. Files live in
  `${DEPA_SANDBOX_DIR:-<repo>/workspace}/sandbox-<port>/`.
- `--jwt-issuer` registers a JWT issuer at network start (CCF `set_jwt_issuer`), e.g. a test
  stand-in for `https://confidentialcomputing.googleapis.com`:
  `{"issuer": "...", "auto_refresh": false, "jwks": {"keys": [{"kty": "RSA", "kid": "...", "x5c": ["..."], "issuer": "..."}]}}`.

Python ≥ 3.13 enables `VERIFY_X509_STRICT`, which rejects the CCF service certificate (no
keyUsage extension); clients must clear that flag while still verifying against
`service_cert` (see `test/integration/depa_client.py`).

### Bootstrap on the sandbox

```bash
curl --cacert $SERVICE_CERT --cert $USER_CERT --key $USER_KEY \
  -H 'content-type: application/json' $APP_URL/gov/bootstrap \
  -d '{"members": [<Party with role dc-member>...], "threshold": {"default": "majority"},
       "settings": {"base_url": "'$APP_URL'"}}'
```

`settings` (optional extension) sets `base_url` (used as receipt `iss` and GCP attestation
audience), `allow_virtual_attestation` (development only) and `trust_bundle_digest`.

## ACL deployment

```bash
ACL_NAME=<ledger> scripts/deploy-acl.sh      # or ACL_URL + ACL_CACERT; ACL_TOKEN optional (az CLI)
```

The script builds the bundle, `PUT`s it to
`/app/userDefinedEndpoints?api-version=2024-08-22-preview` as an ACL Administrator and waits
until `/app/info` reports the new `bundle_digest`. Then: `POST /app/gov/bootstrap` once (ACL
Administrator via `user_cose_sign1`, `user_cert` or Entra ID token); propose `set_settings`
(`base_url` = public URL, `trust_bundle_digest` = digest of the CCR trust bundle built from both
services' URLs, TLS certificates and JWKS — identical in both services), `set_peer_service` (CS URL + CS `/info` JWKS),
`set_jwt_validation_policy` for the GCA issuer, `set_oidc_settings`, `approve_ccr_release` and
`approve_app_digest`.

GCP Confidential Space CCRs require the GCA issuer to be registered at ledger level on the ACL
instance (ACL JWT issuer configuration); the app accepts only tokens that CCF validated
(`caller.policy == "jwt"`, `keyIssuer` = GCA) and then enforces §9.2 (audience = `base_url`,
`hwmodel`, `swname`, `dbgstat`, secure boot, `eat_nonce` ∋ binding hash, image digest, support
attributes) plus the governance JWT validation policy (fail closed if absent).

## Platform facts (CCF 6.0.x JS runtime, verified on the sandbox)

- `ccf.crypto.sign` supports `RSA-PSS`, `ECDSA`, `EdDSA`, `HMAC` only. RSASSA-PKCS1-v1_5 is
  rejected (`Unsupported signing algorithm`), so **RS256 cannot be produced**; OIDC tokens are
  **ES256**.
- ECDSA `sign` returns raw r‖s (IEEE P1363); `verifySignature` accepts only that encoding (DER
  verifies as false). JWS signatures therefore need no conversion; DER is rejected.
- `generateEddsaKeyPair("x25519")` + `eddsaPemToJwk` gives raw 32-byte X25519 keys;
  `wrapKey(…, {name: "RSA-OAEP"})` is RSA-OAEP with SHA-256.
- `Date.now()` returns 0 unless untrusted host time is enabled; the app enables it per request
  and fails closed if unavailable.
- Endpoints that accept attestation use `authn_policies: ["jwt", "no_auth"]`: an absent or
  invalid bearer token falls through to `no_auth`, and the app requires `jwt` for gcp-cs-tdx.
- The transaction id of the current request is not available inside the handler; it is
  returned in the `x-ms-ccf-transaction-id` response header, and claims (release receipt,
  token record) are bound to the transaction with `setClaimsDigest`, so
  `GET /receipt?transaction_id=` proves them.
- Newest CCF 6.0 sandbox image on GHCR is `ccf-6.0.0-rc1`; the app is built against
  `@microsoft/ccf-app` 6.0.1 (ACL pin).

### Federation token compatibility (ES256)

| Cloud | ES256-signed external OIDC tokens |
|---|---|
| AWS (IAM OIDC provider, `AssumeRoleWithWebIdentity`) | supported (RS256/384/512, ES256/384/512) |
| GCP (Workload Identity Federation) | supported (RS256 or ES256; JWKS without `x5c`) |
| Azure (Entra workload identity federation) | **not supported**: Entra documents RS256 only for external issuers |

Azure-hosted TDP storage therefore cannot use KMS federation tokens until ACL/CCF exposes
RSASSA-PKCS1-v1_5 signing (an in-enclave hand-written RSA implementation was rejected because
it is not constant-time). Until then, use S3/GCS locations or an RS256-capable token relay that
is itself attested.

## Security notes

- **ACL Administrator can replace the bundle.** ACL lets the Administrator `PUT` new app code at
  any time; new code could exfiltrate keys. Mitigations: the bundle digest is reproducible
  (`dist/bundle_digest.txt`; `bundle_digest = sha256(JCS({metadata, modules}))` excluding the
  generated `build_info.js`) and exposed by `/info` together with
  `bundle_digest_approved` (governance `approve_app_digest`); every bundle update is recorded in
  the ledger; `depa dc audit` fetches the deployed bundle from
  `GET /app/userDefinedEndpoints`, recomputes the digest and compares it with the approved one.
  `/info` alone is not proof (a malicious bundle can lie); auditors must recompute. Run the
  ledger in a subscription controlled by the DC, restrict the Administrator role, and alert on
  `userDefinedEndpoints` writes.
- **Host time is untrusted.** Validity windows (`iat` ±300 s, RAT expiry, `not_after`, run
  deadlines) rely on host time. A malicious host can skew it but cannot forge attestation, RAT
  signatures or policy decisions.
- **Revocation latency.** A RAT issued before a contract revocation stays valid at the KMS for
  ≤ 300 s; registry revocations and dataset suspensions take effect immediately.
- Private keys (service, OIDC, dataset, output) live in non-`public:` tables (encrypted in the
  ledger) and are never returned except wrapped to an attested CCR key.
- Node logs are operator-visible; the app logs only scopes, status codes and error codes.
- Virtual attestation is for development: it requires `allow_virtual_attestation = true`
  (unanimous `set_settings`) **and** the dataset policy listing `virtual`.

## Repository layout

```
src/                          KMS application (datasets, policy, key release, OIDC, outputs)
packages/depa-ccf-common/     shared code, vendored verbatim into contract-service
test/unit/                    KMS unit tests          test/integration/  two-sandbox e2e tests (shared)
scripts/                      sandbox-up/down, deploy-acl, check-common
docker/Dockerfile.ccf-sandbox app.json (CCF endpoint metadata)  build_bundle.js
```

`deploy/` and `.github/` are owned by the infrastructure workstream.

License: MIT (see LICENSE, NOTICE).
