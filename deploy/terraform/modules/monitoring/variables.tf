variable "name" {
  description = "Name prefix for the action group, alerts, Application Insights and web test."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group for monitoring resources."
  type        = string
}

variable "location" {
  description = "Azure region of Application Insights and the web test."
  type        = string
}

variable "application_gateway_id" {
  description = "Application Gateway to alert on."
  type        = string
}

variable "ledger_backend_settings_pool" {
  description = "BackendSettingsPool dimension value of the ledger backend (\"<pool>~<http settings>\", output of public-gateway)."
  type        = string

  validation {
    condition     = can(regex("^[^~]+~[^~]+$", var.ledger_backend_settings_pool))
    error_message = "ledger_backend_settings_pool must look like <pool>~<http settings>."
  }
}

variable "alert_email_addresses" {
  description = "Receivers of the created action group, keyed by a receiver name."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for e in values(var.alert_email_addresses) : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", e))])
    error_message = "alert_email_addresses must contain email addresses."
  }
}

variable "additional_action_group_ids" {
  description = "Existing action groups (PagerDuty, Teams, ...) to notify in addition to the e-mail group."
  type        = list(string)
  default     = []
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace backing the workspace-based Application Insights component."
  type        = string
}

variable "public_check" {
  description = <<-EOT
    Availability test of the public endpoint (e.g. the OIDC discovery document).
    Fails when the status is not 200, the content does not contain
    `content_match`, the TLS certificate is invalid, or it expires in fewer than
    `min_certificate_days` days (catches failed Let's Encrypt renewals).
  EOT
  type = object({
    url                  = string
    content_match        = optional(string, "")
    min_certificate_days = optional(number, 20)
    frequency_seconds    = optional(number, 300)
    locations            = optional(list(string), ["emea-nl-ams-azr", "us-va-ash-azr", "apac-sg-sin-azr", "emea-gb-db3-azr", "us-ca-sjc-azr"])
    failed_locations     = optional(number, 2)
  })

  validation {
    condition = (
      startswith(var.public_check.url, "https://") &&
      var.public_check.min_certificate_days >= 1 && var.public_check.min_certificate_days <= 365 &&
      contains([300, 600, 900], var.public_check.frequency_seconds) &&
      length(var.public_check.locations) >= var.public_check.failed_locations && var.public_check.failed_locations >= 1
    )
    error_message = "public_check.url must be https; min_certificate_days 1-365; frequency_seconds 300/600/900; failed_locations between 1 and the number of locations."
  }
}

variable "severity" {
  description = "Alert severity (0 critical - 4 verbose)."
  type        = number
  default     = 1

  validation {
    condition     = var.severity >= 0 && var.severity <= 4
    error_message = "severity must be between 0 and 4."
  }
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
