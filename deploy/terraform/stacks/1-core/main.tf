data "azurerm_client_config" "current" {}

locals {
  component = "kms"
  base_name = "${var.name_prefix}-${var.environment}-${var.region_short}"

  resource_group_name = coalesce(var.resource_group_name, "${local.base_name}-rg")
  key_vault_name      = coalesce(var.key_vault_name, substr("${replace(local.base_name, "-", "")}kv", 0, 24))
  ledger_name         = coalesce(var.ledger_name, local.base_name)
  member_cert_name    = "${local.base_name}-member"
  frontend_cert_name  = "${local.base_name}-frontend"

  ledger_administrators = length(var.ledger_administrator_principal_ids) > 0 ? var.ledger_administrator_principal_ids : [data.azurerm_client_config.current.object_id]

  tags = merge(var.tags, {
    workload    = "depa-training"
    component   = local.component
    environment = var.environment
    managed_by  = "terraform"
  })
}

resource "azurerm_resource_group" "this" {
  name     = local.resource_group_name
  location = var.region
  tags     = local.tags
}

module "network" {
  source = "../../modules/network"

  name                           = "${local.base_name}-vnet"
  resource_group_name            = azurerm_resource_group.this.name
  location                       = azurerm_resource_group.this.location
  address_space                  = var.network.address_space
  gateway_subnet_prefix          = var.network.gateway_subnet_prefix
  private_endpoint_subnet_prefix = var.network.private_endpoint_subnet_prefix
  enable_ddos_protection         = var.network.enable_ddos_protection
  tags                           = local.tags
}

# Identity of the Application Gateway: reads only the frontend certificate secret.
module "gateway_identity" {
  source = "../../modules/managed-identity"

  name                = "${local.base_name}-agw-mi"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tags                = local.tags
}

# Identity of the operations workflows (Let's Encrypt renewal). Federated to
# GitHub Actions; no client secret exists.
module "ops_identity" {
  source = "../../modules/managed-identity"

  name                 = "${local.base_name}-ops-mi"
  resource_group_name  = azurerm_resource_group.this.name
  location             = azurerm_resource_group.this.location
  github_oidc_subjects = var.ops_github_oidc_subjects
  tags                 = local.tags
}

module "key_vault" {
  source = "../../modules/key-vault"

  name                       = local.key_vault_name
  resource_group_name        = azurerm_resource_group.this.name
  location                   = azurerm_resource_group.this.location
  tenant_id                  = var.tenant_id
  soft_delete_retention_days = var.key_vault_soft_delete_retention_days
  allowed_ip_ranges          = var.key_vault_allowed_ip_ranges
  network_default_action     = var.key_vault_network_default_action
  allowed_subnet_ids         = concat([module.network.gateway_subnet_id], var.key_vault_additional_subnet_ids)

  member_certificate = {
    name               = local.member_cert_name
    subject            = var.member_certificate.subject
    validity_in_months = var.member_certificate.validity_in_months
    exportable         = var.member_certificate.exportable
  }

  frontend_certificate = {
    name     = local.frontend_cert_name
    hostname = var.gateway_hostname
  }

  tags = local.tags
}

# Certificate-scoped grants (not vault-wide).
resource "azurerm_role_assignment" "gateway_frontend_secret" {
  scope                = "${module.key_vault.id}/secrets/${module.key_vault.frontend_certificate_name}"
  role_definition_name = "Key Vault Secrets User"
  principal_id         = module.gateway_identity.principal_id
}

resource "azurerm_role_assignment" "ops_frontend_certificate" {
  scope                = module.key_vault.frontend_certificate_resource_manager_versionless_id
  role_definition_name = "Key Vault Certificates Officer"
  principal_id         = module.ops_identity.principal_id
}

module "ledger" {
  source = "../../modules/confidential-ledger"

  name                              = local.ledger_name
  resource_group_name               = azurerm_resource_group.this.name
  location                          = azurerm_resource_group.this.location
  tenant_id                         = var.tenant_id
  administrator_principal_ids       = local.ledger_administrators
  member_certificate_pem            = module.key_vault.member_certificate_pem
  additional_certificate_principals = var.ledger_additional_certificate_principals
  tags                              = local.tags
}
