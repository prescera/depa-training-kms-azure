resource "azurerm_confidential_ledger" "this" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location
  ledger_type         = "Public"
  tags                = var.tags

  dynamic "azuread_based_service_principal" {
    for_each = toset(var.administrator_principal_ids)
    content {
      tenant_id        = var.tenant_id
      principal_id     = azuread_based_service_principal.value
      ledger_role_name = "Administrator"
    }
  }

  certificate_based_security_principal {
    pem_public_key   = var.member_certificate_pem
    ledger_role_name = "Administrator"
  }

  dynamic "certificate_based_security_principal" {
    for_each = var.additional_certificate_principals
    content {
      pem_public_key   = certificate_based_security_principal.value.pem
      ledger_role_name = certificate_based_security_principal.value.role
    }
  }

  lifecycle {
    # ACL adds the creating principal itself; managing the AAD list afterwards is
    # done through the ledger's user management API (same as DEPA-inferencing).
    ignore_changes = [azuread_based_service_principal]
  }
}

# The ledger's TLS identity (CCF service certificate), published by the ACL
# identity service. Used as the gateway's trusted backend root and pinned by
# clients that talk to the ledger endpoint directly.
# Azure returns identity_service_endpoint as the full identity URL for this ledger
# (https://identity.confidential-ledger.core.azure.com/ledgerIdentity/<name>); append the
# path only if a bare service URL is ever returned.
locals {
  identity_endpoint = trimsuffix(azurerm_confidential_ledger.this.identity_service_endpoint, "/")
  identity_url      = strcontains(local.identity_endpoint, "/ledgerIdentity/") ? local.identity_endpoint : "${local.identity_endpoint}/ledgerIdentity/${azurerm_confidential_ledger.this.name}"
}

data "http" "ledger_identity" {
  url = local.identity_url

  # Transient errors only (connection failures, 5xx, 429); a 404 still fails the postcondition.
  retry {
    attempts     = 5
    min_delay_ms = 2000
    max_delay_ms = 15000
  }

  request_headers = {
    Accept = "application/json"
  }

  lifecycle {
    postcondition {
      condition     = self.status_code == 200 && can(jsondecode(self.response_body).ledgerTlsCertificate)
      error_message = "The ACL identity service did not return a ledgerTlsCertificate."
    }
  }
}
