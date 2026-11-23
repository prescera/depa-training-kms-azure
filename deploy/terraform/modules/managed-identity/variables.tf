variable "name" {
  description = "Name of the user-assigned managed identity."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9_-]{2,127}$", var.name))
    error_message = "name must be 3-128 characters of letters, digits, '-' or '_'."
  }
}

variable "resource_group_name" {
  description = "Resource group that hosts the identity."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "github_oidc_subjects" {
  description = <<-EOT
    GitHub Actions OIDC subjects allowed to sign in as this identity, e.g.
    "repo:prescera/depa-training-kms-azure:environment:dc-prod" (preferred: binds to a
    protected GitHub environment) or "repo:<owner>/<repo>:ref:refs/heads/main".
    Empty disables federation.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for s in var.github_oidc_subjects : can(regex("^repo:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:(environment:[^:]+|ref:refs/(heads|tags)/.+)$", s))])
    error_message = "Each subject must look like repo:<owner>/<repo>:environment:<name> or repo:<owner>/<repo>:ref:refs/heads/<branch>."
  }
}

variable "tags" {
  description = "Tags applied to the identity."
  type        = map(string)
  default     = {}
}
