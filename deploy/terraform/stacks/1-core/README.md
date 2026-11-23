# stacks/1-core (KMS)

Phase 1 of the DEPA KMS deployment (provider-less; instantiated by
`environments/*/1-core` or the DC composition in `prescera/depa-training`):

| Resource | Notes |
|---|---|
| Resource group | `<name_prefix>-<env>-<region_short>-rg` |
| VNet | gateway subnet (KV service endpoint, NSG) + private-endpoint subnet |
| Managed identities | `-agw-mi` (gateway: *Key Vault Secrets User* on the frontend secret only), `-ops-mi` (renewal workflow: *Key Vault Certificates Officer* on the frontend certificate only; GitHub OIDC federation) |
| Key Vault | premium, RBAC, purge protection, firewall (operator IPs + gateway subnet); EC P-384 HSM member certificate; self-signed bootstrap frontend certificate for `gateway_hostname` |
| Confidential Ledger | Public; certificate Administrator = member cert; AAD Administrators = `ledger_administrator_principal_ids` (default: deployer) |

No role grants above certificate scope; no Contributor grants.

`gateway_stack_inputs` is the `core` input of `stacks/2-gateway`. The phase-2
prerequisite is manual: create the ledger's Private Link Service (not exposed by
ARM/Terraform) and record its alias.
