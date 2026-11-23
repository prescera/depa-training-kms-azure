variable "name" {
  description = "Globally unique Key Vault name (3-24 characters, letters, digits and hyphens)."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$", var.name)) && !strcontains(var.name, "--")
    error_message = "name must be 3-24 characters, start with a letter, end with a letter or digit, and not contain '--'."
  }
}

variable "resource_group_name" {
  description = "Resource group that hosts the vault."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "tenant_id" {
  description = "Microsoft Entra tenant ID of the vault."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.tenant_id))
    error_message = "tenant_id must be a GUID."
  }
}

variable "soft_delete_retention_days" {
  description = "Soft-delete retention in days (purge protection is always enabled)."
  type        = number
  default     = 90

  validation {
    condition     = var.soft_delete_retention_days >= 7 && var.soft_delete_retention_days <= 90
    error_message = "soft_delete_retention_days must be between 7 and 90."
  }
}

variable "allowed_ip_ranges" {
  description = "Public IPv4 addresses/CIDRs allowed through the vault firewall (operator workstations or CI egress that run Terraform/renewal). The data plane is otherwise only reachable from allowed_subnet_ids."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.allowed_ip_ranges : can(cidrhost(strcontains(c, "/") ? c : "${c}/32", 0))])
    error_message = "allowed_ip_ranges must contain IPv4 addresses or CIDRs."
  }
}

variable "allowed_subnet_ids" {
  description = "Subnet IDs (with the Microsoft.KeyVault service endpoint) allowed through the vault firewall, e.g. the Application Gateway subnet and a self-hosted runner subnet."
  type        = list(string)
  default     = []
}

variable "administrator_principal_ids" {
  description = "Object IDs granted 'Key Vault Administrator'. Empty grants it to the identity running Terraform (needed to create the certificates)."
  type        = list(string)
  default     = []
}

variable "member_certificate" {
  description = <<-EOT
    Self-signed EC P-384 certificate registered on the Confidential Ledger as a
    certificate-based Administrator (CCF member identity). `exportable = false`
    keeps the private key in the HSM-backed vault; governance messages are then
    COSE-signed through the Key Vault sign API.
  EOT
  type = object({
    name               = string
    subject            = optional(string, "CN=DEPA DC Member")
    validity_in_months = optional(number, 12)
    exportable         = optional(bool, false)
  })

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]{1,127}$", var.member_certificate.name)) && var.member_certificate.validity_in_months >= 1 && var.member_certificate.validity_in_months <= 36
    error_message = "member_certificate.name must be 1-127 alphanumerics/hyphens and validity_in_months between 1 and 36."
  }
}

variable "frontend_certificate" {
  description = <<-EOT
    Optional bootstrap TLS certificate for the public gateway hostname. It is
    self-signed so the gateway can be created before the first Let's Encrypt
    issuance; renewals import new versions under the same name and Terraform
    ignores policy drift afterwards. null disables it.
  EOT
  type = object({
    name     = string
    hostname = string
  })
  default = null

  validation {
    condition     = var.frontend_certificate == null || (can(regex("^[a-zA-Z0-9-]{1,127}$", var.frontend_certificate.name)) && can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.frontend_certificate.hostname)))
    error_message = "frontend_certificate.name must be alphanumerics/hyphens and hostname a lowercase DNS name."
  }
}

variable "tags" {
  description = "Tags applied to the vault."
  type        = map(string)
  default     = {}
}
