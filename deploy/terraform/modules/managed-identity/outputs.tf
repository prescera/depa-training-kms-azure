output "id" {
  description = "Resource ID of the identity."
  value       = azurerm_user_assigned_identity.this.id
}

output "name" {
  description = "Name of the identity."
  value       = azurerm_user_assigned_identity.this.name
}

output "client_id" {
  description = "Client (application) ID of the identity."
  value       = azurerm_user_assigned_identity.this.client_id
}

output "principal_id" {
  description = "Object (principal) ID of the identity."
  value       = azurerm_user_assigned_identity.this.principal_id
}
