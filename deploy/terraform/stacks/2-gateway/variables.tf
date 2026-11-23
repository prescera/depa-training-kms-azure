variable "core" {
  description = "The `gateway_stack_inputs` output of stacks/1-core."
  type = object({
    resource_group_name          = string
    base_name                    = string
    gateway_hostname             = string
    virtual_network_name         = string
    gateway_subnet_name          = string
    private_endpoint_subnet_name = string
    key_vault_name               = string
    frontend_certificate_name    = string
    gateway_identity_name        = string
    ops_identity_principal_id    = string
    ledger_name                  = string
  })
}

variable "ledger_private_link_service_alias" {
  description = "Alias of the ledger Private Link Service created out of band after phase 1."
  type        = string
}

variable "runner_network" {
  description = "Optional self-hosted runner VNet/subnet that gets its own ledger and ACME blob private endpoints (renewal workflow, operator access without public endpoints)."
  type = object({
    subnet_id          = string
    virtual_network_id = string
  })
  default = null
}

variable "acme_storage_account_name" {
  description = "Override of the ACME challenge storage account name (default derived from the base name, max 24 characters)."
  type        = string
  default     = null
}

variable "acme_storage_allowed_ip_ranges" {
  description = "Public IPs allowed to write ACME tokens (e.g. CI egress). Empty: private endpoints only."
  type        = list(string)
  default     = []
}

variable "oidc_issuer_path" {
  description = "Path of the KMS OIDC issuer on the gateway (ACL user-defined endpoints are under /app)."
  type        = string
  default     = "/app/oidc"

  validation {
    condition     = can(regex("^(/[A-Za-z0-9._-]+)+$", var.oidc_issuer_path))
    error_message = "oidc_issuer_path must be an absolute path without a trailing slash."
  }
}

variable "public_routes" {
  description = "Requests forwarded to the ledger; everything else is blocked by the WAF. Default: OIDC discovery, JWKS and /info (read-only)."
  type = list(object({
    name       = string
    path_regex = string
    methods    = list(string)
  }))
  default = [
    { name = "OidcDiscovery", path_regex = "/app/oidc/\\.well-known/openid-configuration", methods = ["GET", "HEAD"] },
    { name = "OidcJwks", path_regex = "/app/oidc/jwks", methods = ["GET", "HEAD"] },
    { name = "Info", path_regex = "/app/info", methods = ["GET", "HEAD"] },
  ]
}

variable "waf_mode" {
  description = "WAF mode (Prevention enforces the route allowlist)."
  type        = string
  default     = "Prevention"
}

variable "waf_disabled_rules" {
  description = "Managed rule IDs to disable per rule group (only needed when POST routes are published)."
  type        = map(list(string))
  default     = {}
}

variable "gateway_autoscale" {
  description = "Application Gateway autoscaling bounds."
  type = object({
    min_capacity = number
    max_capacity = number
  })
  default = {
    min_capacity = 1
    max_capacity = 4
  }
}

variable "gateway_zones" {
  description = "Availability zones of the gateway (empty in regions without zones)."
  type        = list(string)
  default     = ["1", "2", "3"]
}

variable "gateway_public_ip_id" {
  description = "Existing static public IP to reuse; null creates one."
  type        = string
  default     = null
}

variable "log_analytics_workspace_id" {
  description = "Existing Log Analytics workspace for gateway logs and Application Insights; null creates one in the KMS resource group."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "Retention of the created Log Analytics workspace."
  type        = number
  default     = 90

  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 730
    error_message = "log_retention_days must be between 30 and 730."
  }
}

variable "alert_email_addresses" {
  description = "E-mail receivers for alerts, keyed by receiver name."
  type        = map(string)
  default     = {}
}

variable "additional_action_group_ids" {
  description = "Existing action groups to notify."
  type        = list(string)
  default     = []
}

variable "min_certificate_days" {
  description = "Alert when the public TLS certificate expires in fewer days than this."
  type        = number
  default     = 20
}

variable "tags" {
  description = "Additional tags for all resources."
  type        = map(string)
  default     = {}
}
