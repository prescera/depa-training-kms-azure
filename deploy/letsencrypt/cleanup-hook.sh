#!/usr/bin/env bash
# certbot --manual-cleanup-hook: remove the token published by auth-hook.sh.
set -euo pipefail

: "${STORAGE_ACCOUNT:?STORAGE_ACCOUNT must be set}"
: "${CERTBOT_TOKEN:?CERTBOT_TOKEN must be set by certbot}"

az storage blob delete \
  --account-name "${STORAGE_ACCOUNT}" \
  --container-name '$web' \
  --name ".well-known/acme-challenge/${CERTBOT_TOKEN}" \
  --auth-mode login \
  --only-show-errors || true
