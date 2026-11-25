variable "environment" {
  description = "Environment code used in names (e.g. prod, uat, dev)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{2,8}$", var.environment))
    error_message = "environment must be 2-8 lowercase letters or digits."
  }
}

variable "region" {
  description = "Azure region (must offer Azure Confidential Ledger, e.g. centralindia, eastus, westeurope)."
  type        = string
}

variable "region_short" {
  description = "Short region code used in names (e.g. cin)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{2,6}$", var.region_short))
    error_message = "region_short must be 2-6 lowercase letters or digits."
  }
}

variable "name_prefix" {
  description = "Prefix of all resource names; the base name is <name_prefix>-<environment>-<region_short>."
  type        = string
  default     = "depa-kms"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,13}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-15 lowercase letters, digits or hyphens."
  }
}

variable "tenant_id" {
  description = "Microsoft Entra tenant ID."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.tenant_id))
    error_message = "tenant_id must be a GUID."
  }
}

variable "resource_group_name" {
  description = "Override of the resource group name (default <base>-rg). The group is created by this stack."
  type        = string
  default     = null
}

variable "network" {
  description = "Address plan of the service VNet."
  type = object({
    address_space                  = optional(list(string), ["10.40.0.0/16"])
    gateway_subnet_prefix          = optional(string, "10.40.1.0/24")
    private_endpoint_subnet_prefix = optional(string, "10.40.2.0/24")
    enable_ddos_protection         = optional(bool, false)
  })
  default = {}
}

variable "gateway_hostname" {
  description = "Public DNS name of the KMS gateway; the OIDC issuer becomes https://<gateway_hostname>/app/oidc."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.gateway_hostname))
    error_message = "gateway_hostname must be a lowercase DNS name."
  }
}

variable "key_vault_name" {
  description = "Override of the Key Vault name (default: base name without hyphens + 'kv', max 24 characters)."
  type        = string
  default     = null
}

variable "key_vault_allowed_ip_ranges" {
  description = "Operator/CI egress IPs allowed through the Key Vault firewall (Terraform needs data-plane access to create certificates)."
  type        = list(string)
  default     = []
}

variable "key_vault_additional_subnet_ids" {
  description = "Extra subnets (with the Microsoft.KeyVault service endpoint) allowed through the Key Vault firewall, e.g. a self-hosted runner subnet used by the certificate renewal workflow."
  type        = list(string)
  default     = []
}

variable "key_vault_purge_protection_enabled" {
  description = "Key Vault purge protection. Keep true in production; demos set false (with purge_soft_delete_on_destroy in the azurerm provider) so a teardown frees the vault name."
  type        = bool
  default     = true
}

variable "key_vault_soft_delete_retention_days" {
  description = "Key Vault soft-delete retention in days."
  type        = number
  default     = 90
}

variable "member_certificate" {
  description = "ACL member (certificate-based Administrator) certificate settings."
  type = object({
    subject            = optional(string, "CN=DEPA DC KMS Member")
    validity_in_months = optional(number, 12)
    exportable         = optional(bool, false)
  })
  default = {}
}

variable "ledger_name" {
  description = "Override of the Confidential Ledger name (default: base name)."
  type        = string
  default     = null
}

variable "ledger_administrator_principal_ids" {
  description = "AAD Administrators of the ledger (deploy the app bundle, call /gov/bootstrap). Empty uses the identity running Terraform."
  type        = list(string)
  default     = []
}

variable "ledger_additional_certificate_principals" {
  description = "Additional certificate principals on the ledger (e.g. Reader certificates for auditors)."
  type = list(object({
    pem  = string
    role = string
  }))
  default = []
}

variable "ops_github_oidc_subjects" {
  description = "GitHub OIDC subjects federated to the operations identity (certificate renewal workflow), e.g. repo:prescera/depa-training-kms-azure:environment:dc-prod."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional tags for all resources."
  type        = map(string)
  default     = {}
}

variable "key_vault_network_default_action" {
  description = "Key Vault firewall default action: Deny (production; run Terraform from key_vault_allowed_ip_ranges or key_vault_additional_subnet_ids) or Allow (pilots on GitHub-hosted runners; RBAC still applies)."
  type        = string
  default     = "Deny"
}
