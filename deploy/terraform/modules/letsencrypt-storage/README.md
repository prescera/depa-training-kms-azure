# letsencrypt-storage

Private StorageV2 account whose static website (`$web`) serves Let's Encrypt
HTTP-01 tokens. The Application Gateway's port-80 listener path-routes
`/.well-known/acme-challenge/*` to the `web` private endpoint; the renewal job
writes tokens through a `blob` private endpoint (one per entry in `endpoints`)
or, if `allowed_ip_ranges` is set, through the firewalled public endpoint.
DNS uses `privatelink.{web,blob}.core.windows.net` zone groups.

`blob_writer_principal_ids` (the operations identity) get *Storage Blob Data
Contributor* on this account only. Mirrors DEPA-inferencing
`letsencrypt_storage`, with PE DNS zone groups instead of NIC lookups.

Outputs: `id`, `name`, `web_endpoint_host`.

> A vendored copy lives in `contract-service/deploy/terraform/modules/letsencrypt-storage`; keep the `.tf` files identical.
