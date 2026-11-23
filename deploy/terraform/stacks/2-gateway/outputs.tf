output "gateway_public_ip" {
  description = "Public IP of the KMS gateway."
  value       = module.gateway.public_ip_address
}

output "gateway_public_ip_id" {
  description = "Resource ID of the gateway public IP (set gateway_public_ip_id to keep it across rebuilds)."
  value       = module.gateway.public_ip_id
}

output "dns_record" {
  description = "DNS record to create in the public zone before the first Let's Encrypt issuance."
  value = {
    name  = local.hostname
    type  = "A"
    value = module.gateway.public_ip_address
  }
}

output "oidc_issuer_url" {
  description = "Value for the KMS governance action set_oidc_settings.issuer_url and for TDP federation trust."
  value       = local.issuer_url
}

output "oidc_discovery_url" {
  description = "Public OIDC discovery document URL."
  value       = "${local.issuer_url}/.well-known/openid-configuration"
}

output "ledger_private_endpoint_ids" {
  description = "Private endpoints whose connections must be approved on the ledger PLS."
  value       = module.ledger_private_endpoint.private_endpoint_ids
}

output "application_gateway_name" {
  description = "Name of the Application Gateway."
  value       = module.gateway.name
}

output "renewal_workflow_settings" {
  description = "GitHub environment variables for .github/workflows/refresh-frontend-certificate.yml."
  value = {
    DOMAIN          = local.hostname
    KEY_VAULT_NAME  = data.azurerm_key_vault.this.name
    CERT_NAME       = var.core.frontend_certificate_name
    STORAGE_ACCOUNT = module.acme_storage.name
  }
}
