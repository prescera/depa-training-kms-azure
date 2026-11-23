data "azurerm_client_config" "current" {}

locals {
  administrator_principal_ids = length(var.administrator_principal_ids) > 0 ? var.administrator_principal_ids : [data.azurerm_client_config.current.object_id]
  ip_rules                    = [for c in var.allowed_ip_ranges : trimsuffix(c, "/32")]
}

resource "azurerm_key_vault" "this" {
  name                          = var.name
  location                      = var.location
  resource_group_name           = var.resource_group_name
  tenant_id                     = var.tenant_id
  sku_name                      = "premium"
  soft_delete_retention_days    = var.soft_delete_retention_days
  purge_protection_enabled      = true
  rbac_authorization_enabled    = true
  public_network_access_enabled = true
  tags                          = var.tags

  # The firewall denies everything except the listed operator IPs and subnets.
  # Application Gateway is not a "trusted Microsoft service", so it reaches the
  # vault through the service endpoint on its subnet.
  network_acls {
    bypass                     = "None"
    default_action             = "Deny"
    ip_rules                   = local.ip_rules
    virtual_network_subnet_ids = var.allowed_subnet_ids
  }
}

resource "azurerm_role_assignment" "administrator" {
  for_each = toset(local.administrator_principal_ids)

  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = each.value
}

# Azure RBAC propagation is eventually consistent; certificate creation right
# after the role assignment otherwise fails intermittently with 403.
resource "time_sleep" "rbac_propagation" {
  create_duration = "60s"
  depends_on      = [azurerm_role_assignment.administrator]
}

resource "azurerm_key_vault_certificate" "member" {
  name         = var.member_certificate.name
  key_vault_id = azurerm_key_vault.this.id
  tags         = var.tags

  certificate_policy {
    issuer_parameters {
      name = "Self"
    }

    key_properties {
      key_type   = "EC-HSM"
      curve      = "P-384"
      exportable = var.member_certificate.exportable
      reuse_key  = true
    }

    lifetime_action {
      action {
        action_type = "AutoRenew"
      }
      trigger {
        days_before_expiry = 60
      }
    }

    secret_properties {
      content_type = "application/x-pkcs12"
    }

    x509_certificate_properties {
      subject            = var.member_certificate.subject
      key_usage          = ["digitalSignature"]
      validity_in_months = var.member_certificate.validity_in_months
    }
  }

  depends_on = [time_sleep.rbac_propagation]
}

resource "azurerm_key_vault_certificate" "frontend" {
  count = var.frontend_certificate == null ? 0 : 1

  name         = var.frontend_certificate.name
  key_vault_id = azurerm_key_vault.this.id
  tags         = var.tags

  certificate_policy {
    issuer_parameters {
      name = "Self"
    }

    key_properties {
      key_type   = "RSA"
      key_size   = 2048
      exportable = true # Application Gateway needs the PFX secret.
      reuse_key  = false
    }

    secret_properties {
      content_type = "application/x-pkcs12"
    }

    x509_certificate_properties {
      subject            = "CN=${var.frontend_certificate.hostname}"
      key_usage          = ["digitalSignature", "keyEncipherment"]
      extended_key_usage = ["1.3.6.1.5.5.7.3.1"]
      validity_in_months = 3

      subject_alternative_names {
        dns_names = [var.frontend_certificate.hostname]
      }
    }
  }

  lifecycle {
    # Let's Encrypt renewals import new versions with an "Unknown" issuer policy.
    ignore_changes = [certificate_policy, tags]
  }

  depends_on = [time_sleep.rbac_propagation]
}
