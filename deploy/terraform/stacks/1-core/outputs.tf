output "resource_group_name" {
  description = "Resource group of the KMS."
  value       = azurerm_resource_group.this.name
}

output "ledger_name" {
  description = "Confidential Ledger name."
  value       = module.ledger.name
}

output "ledger_endpoint" {
  description = "Ledger endpoint (direct CCF access; clients pin ledger_tls_certificate_pem)."
  value       = module.ledger.ledger_endpoint
}

output "identity_service_endpoint" {
  description = "ACL identity service endpoint."
  value       = module.ledger.identity_service_endpoint
}

output "ledger_tls_certificate_pem" {
  description = "Ledger TLS (CCF service identity) certificate."
  value       = module.ledger.ledger_tls_certificate_pem
}

output "key_vault_name" {
  description = "Key Vault name."
  value       = module.key_vault.name
}

output "key_vault_uri" {
  description = "Key Vault URI."
  value       = module.key_vault.uri
}

output "member_certificate_name" {
  description = "Key Vault certificate registered as the ledger certificate Administrator."
  value       = module.key_vault.member_certificate_name
}

output "member_certificate_key_id" {
  description = "Versionless Key Vault key ID of the member certificate (COSE signing via Key Vault)."
  value       = module.key_vault.member_certificate_key_id
}

output "frontend_certificate_name" {
  description = "Key Vault certificate served by the gateway (renewed by Let's Encrypt)."
  value       = module.key_vault.frontend_certificate_name
}

output "ops_identity_client_id" {
  description = "Client ID of the operations identity (AZURE_CLIENT_ID of the renewal workflow)."
  value       = module.ops_identity.client_id
}

output "ops_identity_principal_id" {
  description = "Object ID of the operations identity."
  value       = module.ops_identity.principal_id
}

output "virtual_network_id" {
  description = "Resource ID of the service VNet."
  value       = module.network.id
}

output "gateway_stack_inputs" {
  description = "Value for the `core` input of stacks/2-gateway."
  value = {
    resource_group_name          = azurerm_resource_group.this.name
    base_name                    = local.base_name
    gateway_hostname             = var.gateway_hostname
    virtual_network_name         = module.network.name
    gateway_subnet_name          = module.network.gateway_subnet_name
    private_endpoint_subnet_name = module.network.private_endpoint_subnet_name
    key_vault_name               = module.key_vault.name
    frontend_certificate_name    = module.key_vault.frontend_certificate_name
    gateway_identity_name        = module.gateway_identity.name
    ops_identity_principal_id    = module.ops_identity.principal_id
    ledger_name                  = module.ledger.name
  }
}
