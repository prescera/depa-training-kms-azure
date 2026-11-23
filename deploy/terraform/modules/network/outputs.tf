output "id" {
  description = "Resource ID of the virtual network."
  value       = azurerm_virtual_network.this.id
}

output "name" {
  description = "Name of the virtual network."
  value       = azurerm_virtual_network.this.name
}

output "gateway_subnet_id" {
  description = "Resource ID of the Application Gateway subnet."
  value       = azurerm_subnet.gateway.id
}

output "gateway_subnet_name" {
  description = "Name of the Application Gateway subnet."
  value       = azurerm_subnet.gateway.name
}

output "private_endpoint_subnet_id" {
  description = "Resource ID of the private endpoint subnet."
  value       = azurerm_subnet.private_endpoint.id
}

output "private_endpoint_subnet_name" {
  description = "Name of the private endpoint subnet."
  value       = azurerm_subnet.private_endpoint.name
}
