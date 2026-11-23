# stacks/2-gateway (KMS)

Phase 2: publicly trusted TLS front for the KMS OIDC issuer (spec §10).
Prerequisite: phase 1 applied, ledger Private Link Service created out of band,
alias recorded.

| Resource | Notes |
|---|---|
| Ledger private endpoint(s) | manual connection to the PLS alias; per-ledger private DNS zone (`primary` + optional `runner`) |
| ACME storage | private static website for HTTP-01 tokens; ops identity is *Storage Blob Data Contributor* on it only |
| Log Analytics | created unless `log_analytics_workspace_id` is given |
| Application Gateway WAF_v2 | host-header check, default-deny WAF allowlist (`public_routes`: GET/HEAD `/app/oidc/.well-known/openid-configuration`, `/app/oidc/jwks`, `/app/info`), Let's Encrypt cert from Key Vault (versionless), backend TLS pinned to the ledger service identity |
| Monitoring | unhealthy-ledger-backend alert; multi-region web test on the discovery document checking status, `jwks_uri` content and >= `min_certificate_days` certificate lifetime |

Inputs: `core` (= phase-1 `gateway_stack_inputs`), `ledger_private_link_service_alias`,
optional `runner_network`, routing/WAF/monitoring settings. Outputs: `dns_record`,
`oidc_issuer_url`, `oidc_discovery_url`, `gateway_public_ip(_id)`,
`ledger_private_endpoint_ids` (approve on the PLS), `renewal_workflow_settings`.
