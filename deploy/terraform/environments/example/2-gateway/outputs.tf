output "dns_record" {
  description = "Public DNS record to create (hostname -> gateway IP)."
  value       = module.kms_gateway.dns_record
}

output "gateway_public_ip_id" {
  description = "Public IP resource ID (pin via gateway_public_ip_id)."
  value       = module.kms_gateway.gateway_public_ip_id
}

output "oidc_issuer_url" {
  description = "Issuer URL for set_oidc_settings and TDP federation."
  value       = module.kms_gateway.oidc_issuer_url
}

output "oidc_discovery_url" {
  description = "OIDC discovery document URL."
  value       = module.kms_gateway.oidc_discovery_url
}

output "ledger_private_endpoint_ids" {
  description = "Private endpoint connections to approve on the ledger PLS."
  value       = module.kms_gateway.ledger_private_endpoint_ids
}

output "renewal_workflow_settings" {
  description = "GitHub environment variables for the certificate renewal workflow."
  value       = module.kms_gateway.renewal_workflow_settings
}
