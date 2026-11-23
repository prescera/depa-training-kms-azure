output "id" {
  description = "Resource ID of the Application Gateway."
  value       = azurerm_application_gateway.this.id
}

output "name" {
  description = "Name of the Application Gateway."
  value       = azurerm_application_gateway.this.name
}

output "public_ip_address" {
  description = "Public IPv4 address; create an A record <hostname> -> this address."
  value       = var.public_ip_id == null ? azurerm_public_ip.this[0].ip_address : data.azurerm_public_ip.existing[0].ip_address
}

output "public_ip_id" {
  description = "Resource ID of the public IP (pass back as public_ip_id to keep it across rebuilds)."
  value       = local.public_ip_id
}

output "ledger_backend_settings_pool" {
  description = "BackendSettingsPool metric dimension value of the ledger backend (<pool>~<http settings>)."
  value       = "${local.names.ledger_pool}~${local.names.ledger_http}"
}

output "waf_policy_id" {
  description = "Resource ID of the WAF policy."
  value       = azurerm_web_application_firewall_policy.this.id
}
