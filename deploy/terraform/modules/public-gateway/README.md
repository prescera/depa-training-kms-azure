# public-gateway

Application Gateway **WAF_v2** that gives a DC service (KMS OIDC issuer, optional
Contract Service front) a publicly trusted TLS endpoint in front of Azure
Confidential Ledger, whose own certificate is not publicly trusted. Modelled on
DEPA-inferencing `application_gateway`.

- Frontend: Standard static public IP (or reuse `public_ip_id`), HTTPS listener
  for `hostname` with the Key Vault certificate referenced by its **versionless**
  secret ID (new versions are picked up automatically), TLS policy
  `AppGwSslPolicy20220101S`, HSTS/nosniff headers, `Server` header removed.
- Port 80: `/.well-known/acme-challenge/*` → ACME storage static website (private
  endpoint); everything else redirects to HTTPS.
- Backend: the ledger FQDN (resolved to its private endpoint), backend TLS
  validated against the ledger's CCF service certificate (`backend_trusted_root_pem`,
  converted to DER natively), health probe `/node/metrics` (probes bypass WAF).
- WAF policy (Prevention by default, managed rule set DRS 2.1): block foreign
  `Host` headers; **default deny** for any path not matching `public_routes`
  (anchored regex on the URL-decoded path, query string allowed); per-route method
  allowlist. Allowed requests still pass the managed rule set (no `Allow`
  short-circuit). The ACME challenge path is an implicit GET/HEAD route.
- Optional diagnostics (access/firewall/performance logs) to Log Analytics.

Key inputs: `subnet_id`, `hostname`, `identity_id`, `ssl_certificate_secret_id`,
`backend_fqdn`, `backend_trusted_root_pem`, `acme_backend_fqdn`, `public_routes`,
`waf_mode`, `autoscale`, `zones`, `public_ip_id`, `enable_diagnostics` +
`log_analytics_workspace_id`.

Outputs: `id`, `name`, `public_ip_address`, `public_ip_id`,
`ledger_backend_settings_pool`, `waf_policy_id`.

Security note: the gateway terminates TLS, so the DC operator could serve a
different JWKS on the public endpoint. The KMS also publishes its JWKS in
`GET /info` on the ledger endpoint (verifiable with the CCF service identity);
monitors must compare both (spec §10).

> A vendored copy lives in `contract-service/deploy/terraform/modules/public-gateway`; keep the `.tf` files identical.
