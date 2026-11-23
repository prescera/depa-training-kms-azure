# KMS example environment

Two root modules with separate state, applied in order. Copy this directory per
environment (e.g. `environments/prod`), fill `terraform.tfvars` from the
`.example` files and enable the commented `backend "azurerm"` block.

Prerequisites: Terraform >= 1.9, Azure CLI logged in (`az login`) as an identity
with *Owner* (or *Contributor* + *Role Based Access Control Administrator*) on
the subscription or a pre-created scope; your egress IP in
`key_vault_allowed_ip_ranges`; a DNS zone where you can create an A record for
`gateway_hostname`.

## Apply order

1. **Phase 1 - core** (`1-core/`): resource group, VNet, identities, Key Vault
   (member + bootstrap frontend certificates), Confidential Ledger.
   ```bash
   cd 1-core
   terraform init
   terraform apply
   terraform output -json gateway_stack_inputs   # -> ../2-gateway/terraform.tfvars `core`
   ```
2. **Manual - ledger Private Link Service.** Azure does not expose the ACL
   Private Link Service through ARM/Terraform. Create it out of band for the
   ledger (`terraform output ledger_name`), e.g. via the ledger's *Networking*
   blade or the ACL team, and record its alias
   (`<name>-pls.<guid>.<region>.azure.privatelinkservice`) as
   `ledger_private_link_service_alias`.
3. **Phase 2 - gateway** (`2-gateway/`): ledger private endpoint(s) + DNS,
   ACME storage, Log Analytics, Application Gateway WAF_v2, alerts.
   ```bash
   cd ../2-gateway
   terraform init
   terraform apply
   ```
4. **Manual - approve private endpoint connections** listed in
   `terraform output ledger_private_endpoint_ids` on the ledger PLS
   (*Private endpoint connections*). Until then the backend is unhealthy and the
   backend alert fires.
5. **DNS:** create the record from `terraform output dns_record`
   (`<gateway_hostname> A <public ip>`). Keep the IP stable across rebuilds by
   setting `gateway_public_ip_id` to `terraform output gateway_public_ip_id`.
6. **TLS:** set the GitHub environment variables from
   `terraform output renewal_workflow_settings` plus `AZURE_CLIENT_ID`
   (phase-1 `ops_identity_client_id`), `AZURE_TENANT_ID`,
   `AZURE_SUBSCRIPTION_ID`, secret `LETSENCRYPT_EMAIL`, then run
   *Refresh frontend certificate* once (`workflow_dispatch`, `staging` first).
   The gateway serves the self-signed bootstrap certificate until then and picks
   up the imported version within ~4 h.
7. **Application (owned by the KMS app tooling, not Terraform):**
   - deploy the bundle: `PUT <ledger_endpoint>/app/userDefinedEndpoints?api-version=2024-08-22-preview`
     with an ACL Administrator AAD token;
   - `POST <ledger_endpoint>/app/gov/bootstrap` exactly once (spec §3.3);
   - governance proposal `set_oidc_settings` with
     `issuer_url = terraform output oidc_issuer_url`
     (`https://<gateway_hostname>/app/oidc`);
   - approve the bundle digest (`approve_app_digest`) from the release artifact.
8. Verify: `curl https://<gateway_hostname>/app/oidc/.well-known/openid-configuration`
   and compare `/app/oidc/jwks` with the `jwks` in `GET <ledger_endpoint>/app/info`
   (fetched directly from the ledger, pinning `ledger_tls_certificate_pem`).

Destroy in reverse order (2-gateway, then 1-core). Key Vault purge protection
keeps the vault name reserved for the retention period.
