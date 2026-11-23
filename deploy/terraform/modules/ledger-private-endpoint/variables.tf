variable "ledger_name" {
  description = "Name of the Confidential Ledger (<name>.confidential-ledger.azure.com)."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group for the private endpoints and DNS zone."
  type        = string
}

variable "location" {
  description = "Azure region of the private endpoints."
  type        = string
}

variable "private_link_service_alias" {
  description = "Alias of the ledger's Private Link Service, created out of band (e.g. <name>-pls.<guid>.<region>.azure.privatelinkservice)."
  type        = string

  validation {
    condition     = endswith(var.private_link_service_alias, ".azure.privatelinkservice")
    error_message = "private_link_service_alias must end with .azure.privatelinkservice."
  }
}

variable "endpoints" {
  description = <<-EOT
    Private endpoints to create against the ledger PLS, keyed by a short name.
    `primary` (the gateway VNet) is mandatory; add e.g. `runner` for a self-hosted
    CI runner VNet. Each VNet is linked to the ledger's private DNS zone.
  EOT
  type = map(object({
    subnet_id          = string
    virtual_network_id = string
  }))

  validation {
    condition     = contains(keys(var.endpoints), "primary") && alltrue([for k in keys(var.endpoints) : can(regex("^[a-z0-9-]{1,20}$", k))])
    error_message = "endpoints must contain a 'primary' entry and keys must be 1-20 lowercase alphanumerics/hyphens."
  }
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
