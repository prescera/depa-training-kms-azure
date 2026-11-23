variable "subscription_id" {
  description = "Azure subscription that hosts the KMS."
  type        = string
}

variable "tenant_id" {
  description = "Microsoft Entra tenant ID."
  type        = string
}

variable "environment" {
  description = "Environment code (e.g. prod, uat)."
  type        = string
}

variable "region" {
  description = "Azure region offering Azure Confidential Ledger."
  type        = string
}

variable "region_short" {
  description = "Short region code used in names."
  type        = string
}

variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
  default     = "depa-kms"
}

variable "gateway_hostname" {
  description = "Public DNS name of the KMS gateway (OIDC issuer host)."
  type        = string
}

variable "key_vault_allowed_ip_ranges" {
  description = "Operator/CI egress IPs allowed through the Key Vault firewall."
  type        = list(string)
  default     = []
}

variable "key_vault_additional_subnet_ids" {
  description = "Extra subnets allowed through the Key Vault firewall (self-hosted runner)."
  type        = list(string)
  default     = []
}

variable "ledger_administrator_principal_ids" {
  description = "AAD Administrators of the ledger; empty uses the identity running Terraform."
  type        = list(string)
  default     = []
}

variable "ops_github_oidc_subjects" {
  description = "GitHub OIDC subjects federated to the operations identity."
  type        = list(string)
  default     = []
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

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}
