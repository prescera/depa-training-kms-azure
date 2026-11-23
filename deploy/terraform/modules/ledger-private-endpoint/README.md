# ledger-private-endpoint

Private endpoints (manual connection) to an Azure Confidential Ledger's Private
Link Service, plus a private DNS zone named after the ledger FQDN with an apex A
record, linked to each endpoint's VNet. The gateway therefore keeps using the
real ledger FQDN (TLS/SNI unchanged) but traffic stays on Private Link.

Differences from the DEPA-inferencing `ledger_networking` module: endpoints are
a map (`primary` + optional `runner`, …) and the zone is scoped to one ledger
instead of the whole `confidential-ledger.azure.com` domain, so other ledgers
(e.g. the Contract Service) still resolve publicly from the same VNet.

Prerequisite (manual, not exposed by ARM/Terraform): create the ledger PLS and
record its alias; after apply, approve each pending connection on the PLS.

Outputs: `private_endpoint_ids`, `private_ip_addresses`, `ledger_fqdn`,
`private_dns_zone_id`.

> A vendored copy lives in `contract-service/deploy/terraform/modules/ledger-private-endpoint`; keep the `.tf` files identical.
