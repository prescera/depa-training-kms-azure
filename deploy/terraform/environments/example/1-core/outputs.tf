output "ledger_name" {
  description = "Confidential Ledger name (needed for the Private Link Service step)."
  value       = module.kms_core.ledger_name
}

output "ledger_endpoint" {
  description = "Ledger endpoint (bundle deployment, direct CCF access)."
  value       = module.kms_core.ledger_endpoint
}

output "identity_service_endpoint" {
  description = "ACL identity service endpoint."
  value       = module.kms_core.identity_service_endpoint
}

output "ledger_tls_certificate_pem" {
  description = "Ledger TLS certificate (pin in DEPA_TRUST_BUNDLE / CLI)."
  value       = module.kms_core.ledger_tls_certificate_pem
}

output "key_vault_name" {
  description = "Key Vault name."
  value       = module.kms_core.key_vault_name
}

output "key_vault_uri" {
  description = "Key Vault URI."
  value       = module.kms_core.key_vault_uri
}

output "member_certificate_name" {
  description = "Member certificate name in Key Vault."
  value       = module.kms_core.member_certificate_name
}

output "member_certificate_key_id" {
  description = "Key Vault key ID for COSE signing with the member identity."
  value       = module.kms_core.member_certificate_key_id
}

output "ops_identity_client_id" {
  description = "AZURE_CLIENT_ID for the renewal workflow."
  value       = module.kms_core.ops_identity_client_id
}

output "gateway_stack_inputs" {
  description = "Paste as `core` into ../2-gateway/terraform.tfvars."
  value       = module.kms_core.gateway_stack_inputs
}
