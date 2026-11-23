output "id" {
  description = "Resource ID of the vault."
  value       = azurerm_key_vault.this.id
}

output "name" {
  description = "Name of the vault."
  value       = azurerm_key_vault.this.name
}

output "uri" {
  description = "Vault URI."
  value       = azurerm_key_vault.this.vault_uri
}

output "member_certificate_name" {
  description = "Name of the ledger member certificate."
  value       = azurerm_key_vault_certificate.member.name
}

output "member_certificate_pem" {
  description = "Public PEM of the ledger member certificate (no private key)."
  value       = "-----BEGIN CERTIFICATE-----\n${join("\n", regexall(".{1,64}", azurerm_key_vault_certificate.member.certificate_data_base64))}\n-----END CERTIFICATE-----\n"
}

output "member_certificate_key_id" {
  description = "Versionless Key Vault key ID backing the member certificate (for COSE signing via the Key Vault sign API)."
  value       = azurerm_key_vault_certificate.member.versionless_id
}

output "frontend_certificate_name" {
  description = "Name of the gateway frontend TLS certificate (null when disabled)."
  value       = one(azurerm_key_vault_certificate.frontend[*].name)
}

output "frontend_certificate_versionless_secret_id" {
  description = "Versionless secret ID of the frontend certificate; Application Gateway polls it for new versions (null when disabled)."
  value       = one(azurerm_key_vault_certificate.frontend[*].versionless_secret_id)
}

output "frontend_certificate_resource_manager_versionless_id" {
  description = "ARM scope of the frontend certificate, used for certificate-scoped role assignments (null when disabled)."
  value       = one(azurerm_key_vault_certificate.frontend[*].resource_manager_versionless_id)
}
