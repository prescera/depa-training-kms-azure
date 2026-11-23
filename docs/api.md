# depa-kms API

Base URL: `https://<host>/app`. Bodies are JSON. Errors: non-2xx with
`{"error": {"code": "<stable code>", "message": "<text>"}}`; a failed request never leaves
partial state (CCF discards writes of non-2xx transactions). Every write response carries
`x-ms-ccf-transaction-id`; use it with `GET /receipt`.

## Conventions

**Signed request** (§3.2): body `{"jws": "<compact JWS>"}`, protected header
`{"alg": "ES256", "kid": "<party_id>#<kid>", "typ": "depa-request+jws"}` (ES384 with a P-384 key
also accepted), payload `{"aud": "depa-kms", "op": "<op>", "iat": <s>, "jti": "<uuid>", "body": {…}}`.
Rejections: `invalid_signature` (401), `wrong_audience` / `wrong_operation` (401),
`stale_request` (|now − iat| > 300 s, 401), `replay` (jti seen, 401), `missing_role` (403),
`party_suspended` (403). The raw JWS is stored with the state change.

**Path-addressed operations name their target in the signed body** (`dataset_id`,
`proposal_id`, …) so a signature cannot be redirected to another resource.

**Attestation envelope** (§9.2) — field `attestation`:

```json
{"platform": "aci-snp", "evidence": "<b64>", "endorsements": "<b64>", "uvm_endorsements": "<b64>", "endorsed_tcb": "<16 hex, optional>"}
{"platform": "gcp-cs-tdx"}            // + Authorization: Bearer <GCA OIDC token, aud = base_url, eat_nonce ∋ hex(binding_hash)>
{"platform": "virtual", "binding_hash": "<hex>", "virtual_id": "virtual-dev"}
```

Failures: `attestation_invalid` (401).

**Run binding** (§9.1): `{"v":1, contract_id, contract_digest, run_id, recipe_digest, platform, wrapping_key_sha256, run_key, trust_bundle_digest}`;
`binding_hash = hex(SHA-256(JCS(binding as sent)))`. `trust_bundle_digest = digest({v:1, cs:{url, service_cert_pem, jwks}, kms:{url, service_cert_pem, jwks}})`
must equal `settings.trust_bundle_digest` for every non-virtual platform (403
`trust_bundle_mismatch`; 403 `trust_bundle_not_configured` while unset); for `virtual` it is
checked only when the setting is set. Both services check it independently.

## Service

`GET /info` →
`{service, version, bundle_digest, bundle_digest_approved, bootstrapped, jwks: [JWK], oidc_issuer, oidc_jwks: [JWK]}`

`GET /receipt?transaction_id=<view>.<seqno>` → `200 {transaction_id, receipt}` (CCF receipt;
`receipt.leaf_components.claims_digest` = SHA-256(JCS(claim)) for releases and issued tokens),
`202` while pending/fetching (`retry-after`), `404` if invalid.

## Governance (identical in both services)

`POST /gov/bootstrap` — operator only (ACL Administrator; sandbox: CCF user cert), once.
Body `{"members": [Party…], "threshold": {"default": "majority" | "unanimous" | {"n": k}}, "settings": {"base_url": "...", "allow_virtual_attestation": false}}`
→ `{service, jwks, members}`. Second call: 403 `already_bootstrapped`.

`POST /gov/proposals` — signed, op `gov.propose`, role dc-member.
Body `{"actions": [{"name", "args"}], "expires_in_s": 604800}` (60 s – 30 d) →
`{proposal_id, state: "open"}`, `proposal_id = digest(signed payload)`. Every action is
validated against current state (400/404/409 on failure).

`POST /gov/proposals/{proposal_id}/ballots` — signed, op `gov.vote`, role dc-member.
Body `{"proposal_id": "<same as path>", "vote": "approve" | "reject"}` → proposal view.
The ballot that reaches the threshold applies the actions in the same transaction; if an action
no longer applies the whole request fails with 409 `proposal_not_applicable` and the ballot is
not recorded. Closed proposals: 409 `proposal_closed`.

`GET /gov/proposals`, `GET /gov/proposals/{id}` → proposal views
`{proposal_id, proposer, actions, created_at, expires_at, state: open|accepted|rejected|expired, ballots, tally: {approvals, rejections, required, members}, resolved_at, proposal_jws, ballot_jws}`.

`GET /gov/members` → `{members: [Party]}`; `GET /gov/constitution` →
`{constitution, effective_thresholds, actions}`; `GET /gov/state` →
`{bootstrapped, settings, peer_services, jwt_validation_policies, approved_app_digests}`.
`GET /parties[/{party_id}]`, `GET /releases[/{release_id}]` (release entries
`{release, state: approved|revoked, approved_by_proposal, revoked_by_proposal?}`).

| Action | Args | Default threshold |
|---|---|---|
| `set_member` | Party with role `dc-member`, status active | unanimous |
| `remove_member` | `{party_id}` (≥ 1 member must remain; `{n:k}` thresholds must stay feasible) | unanimous |
| `set_party` / `remove_party` | Party without `dc-member` / `{party_id}` (members only via set/remove_member) | majority |
| `set_constitution` | `{default, thresholds?: {action: threshold}}` | unanimous |
| `set_settings` | `{allow_virtual_attestation?, base_url?, trust_bundle_digest?}` | unanimous |
| `set_peer_service` | `{name: "depa-contract-service", url, jwks: [ES256 JWK with kid]}` | majority |
| `set_jwt_validation_policy` | `{issuer, claims: {"<claim or dotted.path>": value | [values]}}` | majority |
| `approve_app_digest` | `{digest}` | majority |
| `approve_ccr_release` | release record (§6); identical re-approval is a no-op, different content 409 `release_immutable`, revoked id 409 `release_revoked` | majority |
| `revoke_ccr_release` | `{release_id}` | majority |
| `set_oidc_settings` (KMS) | `{issuer_url, token_ttl_s (60–900), allowed_audiences_global: [..]}` | majority |
| `suspend_dataset` / `resume_dataset` (KMS) | `{dataset_id, reason}`; resume lifts only the DC suspension | majority |

## Datasets

`POST /datasets` — signed, op `dataset.create`, role tdp or tdc. Body `{dataset_id, description?}`;
`dataset_id = "<signer party_id>/<name>"`, name `[a-z0-9][a-z0-9._-]{0,54}` (so `dataset:<dataset_id>` fits the 127-byte GCP `google.subject` limit).
→ dataset view. Errors: `not_owner` (403), `exists` (409).

`GET /datasets/{owner}/{name}` →
`{dataset_id, owner, description, keys: [{kid, x25519, created_at, state: current|previous|retired}], policy, policy_version, state: active|suspended, owner_suspension, dc_suspension, created_at}`

`PUT /datasets/{owner}/{name}/policy` — signed (owner), op `dataset.set_policy`,
body `{dataset_id, policy: <Release Policy v1>}`. Stored with every default explicit:
`allowed_platforms []`, `allowed_tiers [1]`, `allowed_tdcs []`, `allowed_purposes []`,
`allowed_output_modes ["tee-only"]`, `allowed_audiences []`, `allowed_custom_measurements []`.

`GET /datasets/{owner}/{name}/policy/history` → `{dataset_id, versions: [{version, policy, set_at, jws}]}`

`POST /datasets/{owner}/{name}/rotate` — signed (owner), op `dataset.rotate`,
body `{dataset_id, retire_previous?: bool}`. Adds `#n+1` (current); earlier keys become
`previous` (still releasable) or `retired`.

`POST /datasets/{owner}/{name}/suspend` · `/resume` — signed (owner), ops `dataset.suspend` /
`dataset.resume`, body `{dataset_id, reason?}`.

## Key release

`POST /keys/release` — authn `jwt` or none.
Body `{binding, attestation, rat, dataset_id, kids?: [kid], wrappingKey: "<PEM RSA ≥ 3072>"}`.

```json
{"release_id": "<uuid>",
 "keys": [{"kid": "bank-a/credit#1", "wrapped": "<b64 RSA-OAEP-SHA256(raw 32-byte X25519 private key)>"}],
 "release_receipt": "<JWS typ depa-key-release+jwt>"}
```

Release receipt payload: `{iss: <KMS base_url>, release_id, run_id, contract_id, dataset_id, kids, binding_hash, measurement_id, platform, iat}`,
signed with the KMS service key (`/info` jwks). Without `kids`, all non-retired keys are released.

Error codes: `trust_bundle_not_configured` / `trust_bundle_mismatch` 403, `attestation_invalid` 401, `platform_mismatch` 403, `wrapping_key_mismatch` 403,
`invalid_wrapping_key` 400, `invalid_token` 401 (RAT signature/expiry/audience/shape),
`rat_mismatch` 403, `deadline_passed` 403, `measurement_not_approved` 403,
`dataset_not_in_rat` 403, `dataset_suspended` 403, `policy_denied` 403, `key_retired` 403,
`peer_not_pinned` / `not_configured` 409.

`GET /key-releases/{release_id}` → `{release_id, run_id, contract_id, dataset_id, kids, measurement_id, platform, binding_hash, release, at}`

## OIDC issuer

`GET /oidc/.well-known/openid-configuration` →
`{issuer, jwks_uri: issuer + "/jwks", response_types_supported: ["id_token"], subject_types_supported: ["public"], id_token_signing_alg_values_supported: ["ES256"], claims_supported}`
(409 until `set_oidc_settings`). `issuer_url` should be `https://<public gateway>/app/oidc`.

`GET /oidc/jwks` → `{keys: [ES256 JWK, use "sig"]}`.

`POST /oidc/token` — body `{binding, attestation, rat, resource: {"dataset_id": "..."} | {"output": true}, audience}`.
Dataset: run checks, dataset checks and release policy (run counter not advanced) and
`audience ∈ policy.allowed_audiences`; output: `audience ∈ allowed_audiences_global`
(`audience_denied`). →
`{token, token_type: "urn:ietf:params:oauth:token-type:jwt", expires_at}` with claims
`{iss, sub: "dataset:<id>" | "output:<tdc>", aud, iat, nbf, exp = min(iat + ttl, rat.deadline), jti, contract_id, run_id, platform, measurement_id}`.

## Output keys (tee-only)

`POST /outputs/{contract_id}/key` — body `{binding, attestation, rat}`; RAT for this contract
with `output.mode = "tee-only"` (else 403 `output_mode`). Creates the key on first use. →
`{contract_id, kid: "output:<contract_id>#1", x25519, recipient: "kms:output:<contract_id>#1", created_at}`

`POST /outputs/{contract_id}/release` — body
`{binding: {"v": 1, "purpose": "depa-output-release", contract_id, platform, wrapping_key_sha256, nonce}, attestation, wrappingKey}`.
The attestation must prove SHA-256(JCS(binding)); the measurement must be in an approved,
non-revoked release with family `inference`. → `{release_id, keys: [{kid, wrapped}], release_receipt}`.
