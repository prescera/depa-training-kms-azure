variable "name" {
  description = "Globally unique storage account name (3-24 lowercase letters and digits)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.name))
    error_message = "name must be 3-24 lowercase letters or digits."
  }
}

variable "resource_group_name" {
  description = "Resource group for the account, endpoints and DNS zones."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "endpoints" {
  description = <<-EOT
    Private endpoint placements keyed by a short name. `primary` (gateway VNet)
    gets a `web` endpoint for the gateway; every entry gets a `blob` endpoint so
    the renewal job (e.g. a self-hosted runner in `runner`) can upload tokens.
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

variable "allowed_ip_ranges" {
  description = "Public IPv4 addresses/CIDRs allowed to reach the blob endpoint (e.g. a GitHub-hosted runner egress or operator). Empty disables public network access entirely; Terraform and the renewal job must then run inside a linked VNet."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.allowed_ip_ranges : can(cidrhost(strcontains(c, "/") ? c : "${c}/32", 0))])
    error_message = "allowed_ip_ranges must contain IPv4 addresses or CIDRs."
  }
}

variable "blob_writer_principal_ids" {
  description = "Object IDs granted 'Storage Blob Data Contributor' on the account (the certificate renewal identity)."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
