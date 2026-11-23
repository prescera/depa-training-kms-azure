variable "name" {
  description = "Name of the virtual network. Subnets and the NSG are derived from it."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,60}$", var.name))
    error_message = "name must be 1-61 characters of letters, digits, '.', '_' or '-'."
  }
}

variable "resource_group_name" {
  description = "Resource group that hosts the network resources."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "address_space" {
  description = "Address space of the virtual network."
  type        = list(string)
  default     = ["10.40.0.0/16"]

  validation {
    condition     = length(var.address_space) > 0 && alltrue([for c in var.address_space : can(cidrhost(c, 0))])
    error_message = "address_space must contain at least one valid CIDR."
  }
}

variable "gateway_subnet_prefix" {
  description = "CIDR of the dedicated Application Gateway v2 subnet (/24 recommended, /26 minimum)."
  type        = string
  default     = "10.40.1.0/24"

  validation {
    condition     = can(cidrhost(var.gateway_subnet_prefix, 0)) && tonumber(split("/", var.gateway_subnet_prefix)[1]) <= 26
    error_message = "gateway_subnet_prefix must be a valid CIDR of size /26 or larger."
  }
}

variable "private_endpoint_subnet_prefix" {
  description = "CIDR of the subnet that hosts private endpoints (ledger, ACME storage)."
  type        = string
  default     = "10.40.2.0/24"

  validation {
    condition     = can(cidrhost(var.private_endpoint_subnet_prefix, 0))
    error_message = "private_endpoint_subnet_prefix must be a valid CIDR."
  }
}

variable "enable_ddos_protection" {
  description = "Create an Azure DDoS Network Protection plan and attach it to the VNet (significant fixed monthly cost)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
