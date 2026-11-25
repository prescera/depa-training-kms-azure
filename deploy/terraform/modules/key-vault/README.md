# key-vault

Premium (HSM-backed), RBAC-mode Key Vault with purge protection and a firewall
that denies everything except `allowed_ip_ranges` (operators/CI running
Terraform or the certificate renewal) and `allowed_subnet_ids` (the Application
Gateway subnet via its `Microsoft.KeyVault` service endpoint). This replaces the
DEPA-inferencing "phase 2 private endpoint + import" step with a single owner of
the vault resource.

Certificates:
- `member_certificate`: self-signed EC P-384 (EC-HSM) certificate registered on
  the Confidential Ledger as a certificate-based Administrator. Non-exportable by
  default; sign governance COSE messages with the Key Vault sign API.
- `frontend_certificate` (optional): self-signed *bootstrap* TLS certificate for
  the gateway hostname. Let's Encrypt renewals (`.github/workflows/refresh-frontend-certificate.yml`)
  import new versions under the same name; Terraform ignores policy drift and the
  gateway follows the versionless secret ID.

The identity running Terraform needs data-plane access (its egress IP in
`allowed_ip_ranges`) and receives `Key Vault Administrator` unless
`administrator_principal_ids` is set. A 60 s `time_sleep` absorbs RBAC
propagation. Private keys never enter Terraform state; only public certificate
data does.

Outputs: `id`, `name`, `uri`, `member_certificate_name`, `member_certificate_pem`,
`member_certificate_key_id`, `frontend_certificate_name`,
`frontend_certificate_versionless_secret_id`,
`frontend_certificate_resource_manager_versionless_id`.

> A vendored copy lives in `contract-service/deploy/terraform/modules/key-vault`; keep the `.tf` files identical.

`purge_protection_enabled` (default `true`) can be turned off for demos, so that destroying the
stack (with the azurerm provider feature `key_vault.purge_soft_delete_on_destroy`) purges the
vault and frees its name. Production keeps purge protection on.
