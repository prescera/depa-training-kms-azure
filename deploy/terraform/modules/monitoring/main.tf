locals {
  create_email_group = length(var.alert_email_addresses) > 0
  # Decided from inputs only so the plan never depends on unknown IDs.
  alerts_enabled   = local.create_email_group || length(var.additional_action_group_ids) > 0
  action_group_ids = concat(var.additional_action_group_ids, azurerm_monitor_action_group.email[*].id)
}

resource "azurerm_monitor_action_group" "email" {
  count = local.create_email_group ? 1 : 0

  name                = "${var.name}-alerts"
  resource_group_name = var.resource_group_name
  short_name          = substr(replace(var.name, "-", ""), 0, 12)
  location            = "global"
  tags                = var.tags

  dynamic "email_receiver" {
    for_each = var.alert_email_addresses
    content {
      name                    = email_receiver.key
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }
}

# TLS/certificate problems between gateway and ledger, a broken private endpoint
# or an unhealthy ledger all surface as unhealthy backend hosts.
resource "azurerm_monitor_metric_alert" "ledger_backend_unhealthy" {
  count = local.alerts_enabled ? 1 : 0

  name                = "${var.name}-ledger-backend-unhealthy"
  resource_group_name = var.resource_group_name
  scopes              = [var.application_gateway_id]
  description         = "Ledger backend behind ${var.name} reports unhealthy hosts."
  severity            = var.severity
  frequency           = "PT1M"
  window_size         = "PT5M"
  auto_mitigate       = true
  tags                = var.tags

  criteria {
    metric_namespace = "Microsoft.Network/applicationGateways"
    metric_name      = "UnhealthyHostCount"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 0

    dimension {
      name     = "BackendSettingsPool"
      operator = "Include"
      values   = [var.ledger_backend_settings_pool]
    }
  }

  dynamic "action" {
    for_each = local.action_group_ids
    content {
      action_group_id = action.value
    }
  }
}

resource "azurerm_application_insights" "this" {
  name                = "${var.name}-appi"
  resource_group_name = var.resource_group_name
  location            = var.location
  workspace_id        = var.log_analytics_workspace_id
  application_type    = "other"
  tags                = var.tags
}

resource "azurerm_application_insights_standard_web_test" "public" {
  name                    = "${var.name}-public-endpoint"
  resource_group_name     = var.resource_group_name
  location                = var.location
  application_insights_id = azurerm_application_insights.this.id
  geo_locations           = var.public_check.locations
  frequency               = var.public_check.frequency_seconds
  timeout                 = 30
  enabled                 = true
  retry_enabled           = true
  description             = "Public endpoint ${var.public_check.url}: status, content and TLS certificate lifetime."
  tags                    = var.tags

  request {
    url                              = var.public_check.url
    http_verb                        = "GET"
    follow_redirects_enabled         = false
    parse_dependent_requests_enabled = false
  }

  validation_rules {
    expected_status_code        = 200
    ssl_check_enabled           = true
    ssl_cert_remaining_lifetime = var.public_check.min_certificate_days

    dynamic "content" {
      for_each = var.public_check.content_match == "" ? [] : [var.public_check.content_match]
      content {
        content_match      = content.value
        ignore_case        = false
        pass_if_text_found = true
      }
    }
  }
}

resource "azurerm_monitor_metric_alert" "public_endpoint" {
  count = local.alerts_enabled ? 1 : 0

  name                = "${var.name}-public-endpoint-failed"
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_application_insights_standard_web_test.public.id, azurerm_application_insights.this.id]
  description         = "Public endpoint ${var.public_check.url} failing (availability, content or TLS certificate lifetime)."
  severity            = var.severity
  frequency           = "PT1M"
  window_size         = "PT5M"
  auto_mitigate       = true
  tags                = var.tags

  application_insights_web_test_location_availability_criteria {
    web_test_id           = azurerm_application_insights_standard_web_test.public.id
    component_id          = azurerm_application_insights.this.id
    failed_location_count = var.public_check.failed_locations
  }

  dynamic "action" {
    for_each = local.action_group_ids
    content {
      action_group_id = action.value
    }
  }
}
