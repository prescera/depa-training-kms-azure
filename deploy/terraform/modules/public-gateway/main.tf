locals {
  trusted_root_name = "ledger-service-identity"
  # PEM -> base64 DER, as App Gateway expects for trusted_root_certificate.
  trusted_root_der_b64 = join("", [
    for line in split("\n", replace(trimspace(var.backend_trusted_root_pem), "\r", "")) :
    trimspace(line) if !startswith(trimspace(line), "-----")
  ])

  public_ip_id = var.public_ip_id != null ? var.public_ip_id : azurerm_public_ip.this[0].id

  # The WAF policy covers both listeners, so the ACME challenge path (port 80)
  # is an implicit GET/HEAD route.
  routes = concat(var.public_routes, [{
    name       = "AcmeChallenge"
    path_regex = "/\\.well-known/acme-challenge/[A-Za-z0-9_-]+"
    methods    = ["GET", "HEAD"]
  }])

  # Anchored allowlist: a request must match one route's path (query allowed).
  route_regex = {
    for r in local.routes : r.name => "^(${r.path_regex})(\\?.*)?$"
  }
  any_route_regex = "^(${join("|", [for r in local.routes : r.path_regex])})(\\?.*)?$"

  names = {
    frontend_ip    = "public"
    https_port     = "https"
    http_port      = "http"
    https_listener = "https"
    http_listener  = "http-acme"
    ledger_pool    = "ledger"
    ledger_http    = "ledger-https"
    ledger_probe   = "ledger"
    acme_pool      = "acme"
    acme_http      = "acme-https"
    acme_probe     = "acme"
    ssl_cert       = "frontend"
    redirect       = "http-to-https"
    path_map       = "http-acme"
    rewrite_set    = "security-headers"
  }
}

resource "azurerm_public_ip" "this" {
  count = var.public_ip_id == null ? 1 : 0

  name                = "${var.name}-pip"
  resource_group_name = var.resource_group_name
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = var.zones
  tags                = var.tags
}

data "azurerm_public_ip" "existing" {
  count = var.public_ip_id == null ? 0 : 1

  name                = element(split("/", var.public_ip_id), 8)
  resource_group_name = element(split("/", var.public_ip_id), 4)
}

resource "azurerm_web_application_firewall_policy" "this" {
  name                = "${var.name}-waf"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  policy_settings {
    enabled                     = true
    mode                        = var.waf_mode
    request_body_check          = true
    max_request_body_size_in_kb = var.max_request_body_size_kb
    file_upload_limit_in_mb     = 1
  }

  managed_rules {
    managed_rule_set {
      type    = var.waf_managed_rule_set.type
      version = var.waf_managed_rule_set.version

      dynamic "rule_group_override" {
        for_each = var.waf_disabled_rules
        content {
          rule_group_name = rule_group_override.key
          dynamic "rule" {
            for_each = rule_group_override.value
            content {
              id      = rule.value
              enabled = false
            }
          }
        }
      }
    }
  }

  custom_rules {
    name      = "BlockForeignHost"
    priority  = 1
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RequestHeaders"
        selector      = "Host"
      }
      operator           = "Equal"
      negation_condition = true
      match_values       = [var.hostname]
      transforms         = ["Lowercase"]
    }
  }

  # Default deny: anything that does not match a published route.
  custom_rules {
    name      = "BlockUnlistedPaths"
    priority  = 2
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RequestUri"
      }
      operator           = "Regex"
      negation_condition = true
      match_values       = [local.any_route_regex]
      transforms         = ["UrlDecode"]
    }
  }

  # Per route: block methods that are not published for that path. Matching
  # requests continue through the managed rule set (no Allow short-circuit).
  dynamic "custom_rules" {
    for_each = { for i, r in local.routes : r.name => merge(r, { priority = 10 + i }) }
    content {
      name      = "Methods${custom_rules.key}"
      priority  = custom_rules.value.priority
      rule_type = "MatchRule"
      action    = "Block"

      match_conditions {
        match_variables {
          variable_name = "RequestUri"
        }
        operator     = "Regex"
        match_values = [local.route_regex[custom_rules.key]]
        transforms   = ["UrlDecode"]
      }

      match_conditions {
        match_variables {
          variable_name = "RequestMethod"
        }
        operator           = "Equal"
        negation_condition = true
        match_values       = custom_rules.value.methods
      }
    }
  }
}

resource "azurerm_application_gateway" "this" {
  name                              = var.name
  resource_group_name               = var.resource_group_name
  location                          = var.location
  zones                             = var.zones
  http2_enabled                     = true
  firewall_policy_id                = azurerm_web_application_firewall_policy.this.id
  force_firewall_policy_association = true
  tags                              = var.tags

  sku {
    name = "WAF_v2"
    tier = "WAF_v2"
  }

  autoscale_configuration {
    min_capacity = var.autoscale.min_capacity
    max_capacity = var.autoscale.max_capacity
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [var.identity_id]
  }

  ssl_policy {
    policy_type = "Predefined"
    policy_name = var.ssl_policy_name
  }

  gateway_ip_configuration {
    name      = "gateway"
    subnet_id = var.subnet_id
  }

  frontend_ip_configuration {
    name                 = local.names.frontend_ip
    public_ip_address_id = local.public_ip_id
  }

  frontend_port {
    name = local.names.https_port
    port = 443
  }

  frontend_port {
    name = local.names.http_port
    port = 80
  }

  ssl_certificate {
    name                = local.names.ssl_cert
    key_vault_secret_id = var.ssl_certificate_secret_id
  }

  trusted_root_certificate {
    name = local.trusted_root_name
    data = local.trusted_root_der_b64
  }

  backend_address_pool {
    name  = local.names.ledger_pool
    fqdns = [var.backend_fqdn]
  }

  backend_address_pool {
    name  = local.names.acme_pool
    fqdns = [var.acme_backend_fqdn]
  }

  backend_http_settings {
    name                                = local.names.ledger_http
    protocol                            = "Https"
    port                                = 443
    cookie_based_affinity               = "Disabled"
    request_timeout                     = 30
    pick_host_name_from_backend_address = true
    trusted_root_certificate_names      = [local.trusted_root_name]
    probe_name                          = local.names.ledger_probe
  }

  # Storage static website endpoints are HTTPS-only and need SNI = account host.
  backend_http_settings {
    name                                = local.names.acme_http
    protocol                            = "Https"
    port                                = 443
    cookie_based_affinity               = "Disabled"
    request_timeout                     = 30
    pick_host_name_from_backend_address = true
    probe_name                          = local.names.acme_probe
  }

  probe {
    name                                      = local.names.ledger_probe
    protocol                                  = "Https"
    path                                      = var.health_probe_path
    pick_host_name_from_backend_http_settings = true
    interval                                  = 30
    timeout                                   = 30
    unhealthy_threshold                       = 3

    match {
      status_code = ["200-399"]
    }
  }

  # The static site has no index page; 404 on "/" still proves reachability.
  probe {
    name                                      = local.names.acme_probe
    protocol                                  = "Https"
    path                                      = "/"
    pick_host_name_from_backend_http_settings = true
    interval                                  = 60
    timeout                                   = 30
    unhealthy_threshold                       = 3

    match {
      status_code = ["200-499"]
    }
  }

  http_listener {
    name                           = local.names.https_listener
    frontend_ip_configuration_name = local.names.frontend_ip
    frontend_port_name             = local.names.https_port
    protocol                       = "Https"
    host_name                      = var.hostname
    ssl_certificate_name           = local.names.ssl_cert
  }

  # Port 80 serves only ACME HTTP-01 challenges; everything else is redirected.
  http_listener {
    name                           = local.names.http_listener
    frontend_ip_configuration_name = local.names.frontend_ip
    frontend_port_name             = local.names.http_port
    protocol                       = "Http"
    host_name                      = var.hostname
  }

  redirect_configuration {
    name                 = local.names.redirect
    redirect_type        = "Permanent"
    target_listener_name = local.names.https_listener
    include_path         = true
    include_query_string = true
  }

  url_path_map {
    name                                = local.names.path_map
    default_redirect_configuration_name = local.names.redirect

    path_rule {
      name                       = "acme-challenge"
      paths                      = ["/.well-known/acme-challenge/*"]
      backend_address_pool_name  = local.names.acme_pool
      backend_http_settings_name = local.names.acme_http
    }
  }

  rewrite_rule_set {
    name = local.names.rewrite_set

    rewrite_rule {
      name          = "security-headers"
      rule_sequence = 100

      response_header_configuration {
        header_name  = "Strict-Transport-Security"
        header_value = "max-age=31536000; includeSubDomains"
      }

      response_header_configuration {
        header_name  = "X-Content-Type-Options"
        header_value = "nosniff"
      }

      response_header_configuration {
        header_name  = "Server"
        header_value = ""
      }
    }
  }

  request_routing_rule {
    name                       = "https-ledger"
    priority                   = 100
    rule_type                  = "Basic"
    http_listener_name         = local.names.https_listener
    backend_address_pool_name  = local.names.ledger_pool
    backend_http_settings_name = local.names.ledger_http
    rewrite_rule_set_name      = local.names.rewrite_set
  }

  request_routing_rule {
    name               = "http-acme"
    priority           = 90
    rule_type          = "PathBasedRouting"
    http_listener_name = local.names.http_listener
    url_path_map_name  = local.names.path_map
  }
}

resource "azurerm_monitor_diagnostic_setting" "this" {
  count = var.enable_diagnostics ? 1 : 0

  name                       = "${var.name}-diagnostics"
  target_resource_id         = azurerm_application_gateway.this.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "ApplicationGatewayAccessLog"
  }

  enabled_log {
    category = "ApplicationGatewayFirewallLog"
  }

  enabled_log {
    category = "ApplicationGatewayPerformanceLog"
  }

  enabled_metric {
    category = "AllMetrics"
  }

  lifecycle {
    precondition {
      condition     = var.log_analytics_workspace_id != null
      error_message = "enable_diagnostics requires log_analytics_workspace_id."
    }
  }
}
