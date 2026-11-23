output "id" {
  description = "Resource ID of the ACME storage account."
  value       = azurerm_storage_account.this.id
}

output "name" {
  description = "Name of the ACME storage account (STORAGE_ACCOUNT for the renewal hooks)."
  value       = azurerm_storage_account.this.name
}

output "web_endpoint_host" {
  description = "Static website host used as the gateway's ACME backend."
  value       = azurerm_storage_account.this.primary_web_host
}
