module "kms_gateway" {
  source = "../../../stacks/2-gateway"

  core                              = var.core
  ledger_private_link_service_alias = var.ledger_private_link_service_alias
  runner_network                    = var.runner_network
  acme_storage_allowed_ip_ranges    = var.acme_storage_allowed_ip_ranges
  log_analytics_workspace_id        = var.log_analytics_workspace_id
  gateway_public_ip_id              = var.gateway_public_ip_id
  gateway_zones                     = var.gateway_zones
  alert_email_addresses             = var.alert_email_addresses
  additional_action_group_ids       = var.additional_action_group_ids
  tags                              = var.tags
}
