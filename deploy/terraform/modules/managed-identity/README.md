# managed-identity

User-assigned managed identity with optional GitHub Actions OIDC federated
credentials (no client secrets). Used for the gateway (Key Vault secret read)
and the operations identity (certificate renewal, bundle deployment).

Inputs: `name`, `resource_group_name`, `location`, `github_oidc_subjects`
(prefer `repo:<owner>/<repo>:environment:<env>` bound to a protected GitHub
environment), `tags`. Outputs: `id`, `name`, `client_id`, `principal_id`.

> A vendored copy lives in `contract-service/deploy/terraform/modules/managed-identity`; keep the `.tf` files identical.
