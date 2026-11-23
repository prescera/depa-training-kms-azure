output "private_endpoint_ids" {
  description = "Private endpoint IDs by key; each connection must be approved on the ledger PLS."
  value       = { for k, pe in azurerm_private_endpoint.this : k => pe.id }
}

output "private_ip_addresses" {
  description = "Private IP of each endpoint by key."
  value       = { for k, pe in azurerm_private_endpoint.this : k => pe.private_service_connection[0].private_ip_address }
}

output "ledger_fqdn" {
  description = "Ledger FQDN; resolves to the private endpoint inside the linked VNets."
  value       = local.ledger_fqdn
}

output "private_dns_zone_id" {
  description = "Resource ID of the per-ledger private DNS zone."
  value       = azurerm_private_dns_zone.ledger.id
}
