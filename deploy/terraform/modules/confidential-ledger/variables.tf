variable "name" {
  description = "Name of the Azure Confidential Ledger; becomes <name>.confidential-ledger.azure.com."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}[a-z0-9]$", var.name))
    error_message = "name must be 3-32 lowercase letters, digits or hyphens, starting with a letter."
  }
}

variable "resource_group_name" {
  description = "Resource group that hosts the ledger."
  type        = string
}

variable "location" {
  description = "Azure region (must offer Azure Confidential Ledger with user-defined endpoints)."
  type        = string
}

variable "tenant_id" {
  description = "Microsoft Entra tenant of the AAD-based administrators."
  type        = string
}

variable "administrator_principal_ids" {
  description = "Object IDs of the ledger AAD Administrators (the DC operator identities that deploy the app bundle and call /gov/bootstrap)."
  type        = list(string)

  validation {
    condition     = length(var.administrator_principal_ids) > 0
    error_message = "At least one AAD administrator is required."
  }
}

variable "member_certificate_pem" {
  description = "PEM certificate registered as a certificate-based Administrator (DC member identity)."
  type        = string

  validation {
    condition     = startswith(trimspace(var.member_certificate_pem), "-----BEGIN CERTIFICATE-----")
    error_message = "member_certificate_pem must be a PEM certificate."
  }
}

variable "additional_certificate_principals" {
  description = "Additional certificate-based principals, e.g. read-only auditors."
  type = list(object({
    pem  = string
    role = string
  }))
  default = []

  validation {
    condition     = alltrue([for p in var.additional_certificate_principals : contains(["Administrator", "Contributor", "Reader"], p.role) && startswith(trimspace(p.pem), "-----BEGIN CERTIFICATE-----")])
    error_message = "role must be Administrator, Contributor or Reader and pem a PEM certificate."
  }
}

variable "tags" {
  description = "Tags applied to the ledger."
  type        = map(string)
  default     = {}
}
