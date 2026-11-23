output "id" {
  description = "Resource ID of the ledger."
  value       = azurerm_confidential_ledger.this.id
}

output "name" {
  description = "Name of the ledger."
  value       = azurerm_confidential_ledger.this.name
}

output "ledger_endpoint" {
  description = "Ledger endpoint URL (https://<name>.confidential-ledger.azure.com)."
  value       = azurerm_confidential_ledger.this.ledger_endpoint
}

output "ledger_fqdn" {
  description = "Ledger FQDN."
  value       = trimsuffix(trimprefix(azurerm_confidential_ledger.this.ledger_endpoint, "https://"), "/")
}

output "identity_service_endpoint" {
  description = "ACL identity service endpoint."
  value       = azurerm_confidential_ledger.this.identity_service_endpoint
}

output "ledger_tls_certificate_pem" {
  description = "Ledger TLS (CCF service identity) certificate in PEM format."
  value       = jsondecode(data.http.ledger_identity.response_body).ledgerTlsCertificate
}
