variable "subscription_id" {
  description = "Azure subscription that hosts the KMS."
  type        = string
}

variable "tenant_id" {
  description = "Microsoft Entra tenant ID."
  type        = string
}

variable "core" {
  description = "`gateway_stack_inputs` output of ../1-core."
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
  description = "Alias of the ledger Private Link Service (manual step after phase 1)."
  type        = string
}

variable "runner_network" {
  description = "Optional self-hosted runner subnet/VNet that gets its own private endpoints."
  type = object({
    subnet_id          = string
    virtual_network_id = string
  })
  default = null
}

variable "acme_storage_allowed_ip_ranges" {
  description = "Public IPs allowed to write ACME tokens; empty = private endpoints only."
  type        = list(string)
  default     = []
}

variable "log_analytics_workspace_id" {
  description = "Existing Log Analytics workspace; null creates one."
  type        = string
  default     = null
}

variable "gateway_public_ip_id" {
  description = "Existing public IP to reuse; null creates one."
  type        = string
  default     = null
}

variable "gateway_zones" {
  description = "Availability zones of the gateway."
  type        = list(string)
  default     = ["1", "2", "3"]
}

variable "alert_email_addresses" {
  description = "Alert e-mail receivers keyed by name."
  type        = map(string)
  default     = {}
}

variable "additional_action_group_ids" {
  description = "Existing action groups to notify."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}
