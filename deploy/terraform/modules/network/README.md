# network

VNet for the DC service front end: a dedicated Application Gateway v2 subnet
(with the `Microsoft.KeyVault` service endpoint so the gateway can read its TLS
certificate through the vault firewall, and an NSG with the inbound rules App
Gateway v2 requires plus public 80/443) and a private-endpoint subnet for the
Confidential Ledger and ACME storage private endpoints. Optional DDoS Network
Protection plan.

| Input | Notes |
|---|---|
| `name`, `resource_group_name`, `location` | |
| `address_space`, `gateway_subnet_prefix`, `private_endpoint_subnet_prefix` | gateway subnet must be /26 or larger |
| `enable_ddos_protection` | default `false` |

Outputs: `id`, `name`, `gateway_subnet_id/name`, `private_endpoint_subnet_id/name`.

> A vendored copy lives in `contract-service/deploy/terraform/modules/network`; keep the `.tf` files identical.
