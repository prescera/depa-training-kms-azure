locals {
  component = "kms"
  tags = merge(var.tags, {
    workload   = "depa-training"
    component  = local.component
    managed_by = "terraform"
  })

  hostname          = var.core.gateway_hostname
  acme_storage_name = coalesce(var.acme_storage_account_name, substr("${replace(var.core.base_name, "-", "")}acme", 0, 24))
  issuer_url        = "https://${local.hostname}${var.oidc_issuer_path}"

  runner = var.runner_network == null ? {} : { runner = var.runner_network }
  endpoints = merge({
    primary = {
      subnet_id          = data.azurerm_subnet.private_endpoint.id
      virtual_network_id = data.azurerm_virtual_network.this.id
    }
  }, local.runner)

  log_analytics_workspace_id = coalesce(var.log_analytics_workspace_id, one(azurerm_log_analytics_workspace.this[*].id))
}

data "azurerm_resource_group" "this" {
  name = var.core.resource_group_name
}

data "azurerm_virtual_network" "this" {
  name                = var.core.virtual_network_name
  resource_group_name = var.core.resource_group_name
}

data "azurerm_subnet" "gateway" {
  name                 = var.core.gateway_subnet_name
  virtual_network_name = var.core.virtual_network_name
  resource_group_name  = var.core.resource_group_name
}

data "azurerm_subnet" "private_endpoint" {
  name                 = var.core.private_endpoint_subnet_name
  virtual_network_name = var.core.virtual_network_name
  resource_group_name  = var.core.resource_group_name
}

data "azurerm_key_vault" "this" {
  name                = var.core.key_vault_name
  resource_group_name = var.core.resource_group_name
}

data "azurerm_user_assigned_identity" "gateway" {
  name                = var.core.gateway_identity_name
  resource_group_name = var.core.resource_group_name
}

data "azurerm_confidential_ledger" "this" {
  name                = var.core.ledger_name
  resource_group_name = var.core.resource_group_name
}

# Azure returns identity_service_endpoint as the full identity URL for this ledger
# (https://identity.confidential-ledger.core.azure.com/ledgerIdentity/<name>); append the
# path only if a bare service URL is ever returned.
locals {
  identity_endpoint = trimsuffix(data.azurerm_confidential_ledger.this.identity_service_endpoint, "/")
  identity_url      = strcontains(local.identity_endpoint, "/ledgerIdentity/") ? local.identity_endpoint : "${local.identity_endpoint}/ledgerIdentity/${var.core.ledger_name}"
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

module "ledger_private_endpoint" {
  source = "../../modules/ledger-private-endpoint"

  ledger_name                = var.core.ledger_name
  resource_group_name        = data.azurerm_resource_group.this.name
  location                   = data.azurerm_resource_group.this.location
  private_link_service_alias = var.ledger_private_link_service_alias
  endpoints                  = local.endpoints
  tags                       = local.tags
}

module "acme_storage" {
  source = "../../modules/letsencrypt-storage"

  name                      = local.acme_storage_name
  resource_group_name       = data.azurerm_resource_group.this.name
  location                  = data.azurerm_resource_group.this.location
  endpoints                 = local.endpoints
  allowed_ip_ranges         = var.acme_storage_allowed_ip_ranges
  blob_writer_principal_ids = [var.core.ops_identity_principal_id]
  tags                      = local.tags
}

resource "azurerm_log_analytics_workspace" "this" {
  count = var.log_analytics_workspace_id == null ? 1 : 0

  name                = "${var.core.base_name}-log"
  resource_group_name = data.azurerm_resource_group.this.name
  location            = data.azurerm_resource_group.this.location
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}

module "gateway" {
  source = "../../modules/public-gateway"

  name                       = "${var.core.base_name}-agw"
  resource_group_name        = data.azurerm_resource_group.this.name
  location                   = data.azurerm_resource_group.this.location
  subnet_id                  = data.azurerm_subnet.gateway.id
  zones                      = var.gateway_zones
  autoscale                  = var.gateway_autoscale
  public_ip_id               = var.gateway_public_ip_id
  hostname                   = local.hostname
  identity_id                = data.azurerm_user_assigned_identity.gateway.id
  ssl_certificate_secret_id  = "${data.azurerm_key_vault.this.vault_uri}secrets/${var.core.frontend_certificate_name}"
  backend_fqdn               = module.ledger_private_endpoint.ledger_fqdn
  backend_trusted_root_pem   = jsondecode(data.http.ledger_identity.response_body).ledgerTlsCertificate
  acme_backend_fqdn          = module.acme_storage.web_endpoint_host
  public_routes              = var.public_routes
  waf_mode                   = var.waf_mode
  waf_disabled_rules         = var.waf_disabled_rules
  enable_diagnostics         = true
  log_analytics_workspace_id = local.log_analytics_workspace_id
  tags                       = local.tags
}

module "monitoring" {
  source = "../../modules/monitoring"

  name                         = var.core.base_name
  resource_group_name          = data.azurerm_resource_group.this.name
  location                     = data.azurerm_resource_group.this.location
  application_gateway_id       = module.gateway.id
  ledger_backend_settings_pool = module.gateway.ledger_backend_settings_pool
  log_analytics_workspace_id   = local.log_analytics_workspace_id
  alert_email_addresses        = var.alert_email_addresses
  additional_action_group_ids  = var.additional_action_group_ids

  public_check = {
    url                  = "${local.issuer_url}/.well-known/openid-configuration"
    content_match        = "jwks_uri"
    min_certificate_days = var.min_certificate_days
  }

  tags = local.tags
}
