# Let's Encrypt renewal hooks

Used by `.github/workflows/refresh-frontend-certificate.yml` (certbot
`--manual --preferred-challenges http`). `auth-hook.sh` uploads the HTTP-01
token to the `$web` container of the ACME storage account created by
`stacks/2-gateway`; the gateway's port-80 listener serves it from
`/.well-known/acme-challenge/`. `cleanup-hook.sh` deletes it.

The workflow identity (phase-1 `-ops-mi`) has *Storage Blob Data Contributor* on
the ACME account and *Key Vault Certificates Officer* on the frontend
certificate only. The runner must reach the account's blob endpoint (runner
private endpoint via `runner_network`, or its egress IP in
`acme_storage_allowed_ip_ranges`) and the Key Vault (runner subnet in
`key_vault_additional_subnet_ids` or IP in `key_vault_allowed_ip_ranges`).
