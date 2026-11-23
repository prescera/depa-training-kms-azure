# confidential-ledger

Azure Confidential Ledger (`Public` type) hosting a DEPA CCF JavaScript app
(KMS or Contract Service) through user-defined endpoints.

- AAD Administrators: `administrator_principal_ids` (operators that run
  `PUT /app/userDefinedEndpoints` and `POST /gov/bootstrap`, spec §3.3).
  Changes after creation are ignored (ACL adds the creator itself), as in
  DEPA-inferencing.
- Certificate Administrator: `member_certificate_pem` (from the key-vault module).
- `additional_certificate_principals`: e.g. Reader certificates for auditors.

The ledger TLS certificate is read from the public ACL identity service (`http`
data source with a postcondition) and exported for the gateway trusted root and
for client pinning (`DEPA_TRUST_BUNDLE`).

Outputs: `id`, `name`, `ledger_endpoint`, `ledger_fqdn`,
`identity_service_endpoint`, `ledger_tls_certificate_pem`.

> A vendored copy lives in `contract-service/deploy/terraform/modules/confidential-ledger`; keep the `.tf` files identical.
