# depa-kms infrastructure (Azure)

Terraform for the DEPA Training v2 KMS: an Azure Confidential Ledger instance
hosting the KMS CCF JavaScript app, with an Application Gateway WAF_v2 that
gives the KMS OIDC issuer (spec §10) a publicly trusted TLS endpoint. Modelled on
the production DEPA-inferencing KMS deployment.

```
modules/        building blocks (provider-less)
  network  managed-identity  key-vault  confidential-ledger
  ledger-private-endpoint  letsencrypt-storage  public-gateway  monitoring
stacks/
  1-core        RG, VNet, identities, Key Vault + certificates, ledger
  2-gateway     ledger private endpoint, ACME storage, gateway, monitoring
environments/
  example/      root modules per phase; see environments/example/README.md
scripts/validate.sh   fmt -check + init -backend=false + validate for every dir
```

Phases are separated by a manual step (creating the ledger Private Link
Service, which ARM does not expose). The stacks are also consumed by the DC
composition in `prescera/depa-training` (`deploy/terraform/environments/dc`).

Static checks (no cloud access): `./scripts/validate.sh .`

Conventions: Terraform >= 1.9, azurerm `~> 4.81` (same major as the production
DEPA-inferencing stack), certificate conversion done natively (no external
programs), role assignments scoped to the individual certificate/secret/account,
no Contributor grants, no private keys in state.
