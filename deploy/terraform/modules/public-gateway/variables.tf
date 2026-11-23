variable "name" {
  description = "Name of the Application Gateway; related resources are derived from it."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group for the gateway, public IP and WAF policy."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "subnet_id" {
  description = "Dedicated Application Gateway subnet ID."
  type        = string
}

variable "zones" {
  description = "Availability zones for the gateway and its public IP. Empty for regions without zones."
  type        = list(string)
  default     = ["1", "2", "3"]
}

variable "autoscale" {
  description = "Autoscaling bounds (capacity units)."
  type = object({
    min_capacity = number
    max_capacity = number
  })
  default = {
    min_capacity = 1
    max_capacity = 4
  }

  validation {
    condition     = var.autoscale.min_capacity >= 0 && var.autoscale.max_capacity >= max(2, var.autoscale.min_capacity) && var.autoscale.max_capacity <= 125
    error_message = "autoscale requires 0 <= min_capacity <= max_capacity, 2 <= max_capacity <= 125."
  }
}

variable "public_ip_id" {
  description = "Existing Standard static public IP to reuse (keeps the DNS record stable across rebuilds). null creates one."
  type        = string
  default     = null
}

variable "hostname" {
  description = "Public hostname served by the gateway (e.g. kms.dc.example.org). Requests with any other Host header are blocked."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.hostname))
    error_message = "hostname must be a lowercase DNS name."
  }
}

variable "identity_id" {
  description = "User-assigned identity of the gateway; needs 'Key Vault Secrets User' on the frontend certificate secret."
  type        = string
}

variable "ssl_certificate_secret_id" {
  description = "Versionless Key Vault secret ID of the frontend TLS certificate. The gateway picks up new versions automatically (polling interval up to 4 h)."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+/secrets/[^/]+/?$", var.ssl_certificate_secret_id))
    error_message = "ssl_certificate_secret_id must be a versionless secret ID (https://<vault>/secrets/<name>)."
  }
}

variable "ssl_policy_name" {
  description = "Predefined TLS policy for the listener."
  type        = string
  default     = "AppGwSslPolicy20220101S"
}

variable "backend_fqdn" {
  description = "Ledger FQDN; must resolve to the ledger private endpoint inside the gateway VNet."
  type        = string
}

variable "backend_trusted_root_pem" {
  description = "Ledger TLS (CCF service identity) certificate in PEM; trusted root for backend TLS."
  type        = string

  validation {
    condition     = startswith(trimspace(var.backend_trusted_root_pem), "-----BEGIN CERTIFICATE-----")
    error_message = "backend_trusted_root_pem must be a PEM certificate."
  }
}

variable "health_probe_path" {
  description = "Backend health probe path (probes bypass the WAF)."
  type        = string
  default     = "/node/metrics"
}

variable "acme_backend_fqdn" {
  description = "Static website host of the ACME challenge storage account."
  type        = string
}

variable "public_routes" {
  description = <<-EOT
    The only requests forwarded to the ledger. `path_regex` is matched against the
    URL-decoded path (anchored; the query string is allowed). Everything else is
    blocked by WAF custom rules. ACL user-defined endpoints are served under /app.
  EOT
  type = list(object({
    name       = string
    path_regex = string
    methods    = list(string)
  }))

  validation {
    condition     = length(var.public_routes) > 0 && length(var.public_routes) <= 40 && alltrue([for r in var.public_routes : can(regex("^[A-Za-z][A-Za-z0-9]{0,40}$", r.name)) && startswith(r.path_regex, "/") && !strcontains(r.path_regex, "^") && !strcontains(r.path_regex, "$") && can(regexall(r.path_regex, "")) && length(r.methods) > 0 && alltrue([for m in r.methods : contains(["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"], m)])])
    error_message = "1-40 routes; name alphanumeric (<=41 chars); path_regex a valid regex starting with / without ^/$ anchors (added by the module); methods from GET/HEAD/POST/PUT/DELETE/PATCH/OPTIONS."
  }
}

variable "waf_mode" {
  description = "WAF mode. Custom allowlist rules only block in Prevention."
  type        = string
  default     = "Prevention"

  validation {
    condition     = contains(["Prevention", "Detection"], var.waf_mode)
    error_message = "waf_mode must be Prevention or Detection."
  }
}

variable "waf_managed_rule_set" {
  description = "Managed rule set type and version."
  type = object({
    type    = string
    version = string
  })
  default = {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
  }
}

variable "waf_disabled_rules" {
  description = "Managed rule IDs to disable, keyed by rule group name (false positives on JSON request bodies for POST routes)."
  type        = map(list(string))
  default     = {}
}

variable "max_request_body_size_kb" {
  description = "Maximum inspected request body size."
  type        = number
  default     = 128
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace for access/firewall/performance logs."
  type        = string
  default     = null
}

variable "enable_diagnostics" {
  description = "Send gateway logs to log_analytics_workspace_id (a separate flag so count does not depend on an unknown ID)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
