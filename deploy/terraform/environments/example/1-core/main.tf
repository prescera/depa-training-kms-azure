module "kms_core" {
  source = "../../../stacks/1-core"

  environment                        = var.environment
  region                             = var.region
  region_short                       = var.region_short
  name_prefix                        = var.name_prefix
  tenant_id                          = var.tenant_id
  gateway_hostname                   = var.gateway_hostname
  network                            = var.network
  key_vault_allowed_ip_ranges        = var.key_vault_allowed_ip_ranges
  key_vault_additional_subnet_ids    = var.key_vault_additional_subnet_ids
  ledger_administrator_principal_ids = var.ledger_administrator_principal_ids
  ops_github_oidc_subjects           = var.ops_github_oidc_subjects
  tags                               = var.tags
}
