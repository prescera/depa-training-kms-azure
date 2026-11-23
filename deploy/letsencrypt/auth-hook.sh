#!/usr/bin/env bash
# certbot --manual-auth-hook: publish the HTTP-01 token in the private ACME
# storage account's $web container. The Application Gateway routes
# http://<domain>/.well-known/acme-challenge/* to that static website over a
# private endpoint.
#
# Env: STORAGE_ACCOUNT (workflow), CERTBOT_TOKEN and CERTBOT_VALIDATION (certbot).
set -euo pipefail

: "${STORAGE_ACCOUNT:?STORAGE_ACCOUNT must be set}"
: "${CERTBOT_TOKEN:?CERTBOT_TOKEN must be set by certbot}"
: "${CERTBOT_VALIDATION:?CERTBOT_VALIDATION must be set by certbot}"

if [[ ! "${CERTBOT_TOKEN}" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "unexpected ACME token format" >&2
  exit 1
fi

az storage blob upload \
  --account-name "${STORAGE_ACCOUNT}" \
  --container-name '$web' \
  --name ".well-known/acme-challenge/${CERTBOT_TOKEN}" \
  --data "${CERTBOT_VALIDATION}" \
  --content-type text/plain \
  --auth-mode login \
  --overwrite \
  --only-show-errors

# Wait until the token is served through the gateway before letting the ACME
# server validate (up to 2 minutes).
for _ in $(seq 1 24); do
  if [[ "$(curl -fsS "http://${CERTBOT_DOMAIN}/.well-known/acme-challenge/${CERTBOT_TOKEN}" 2>/dev/null || true)" == "${CERTBOT_VALIDATION}" ]]; then
    exit 0
  fi
  sleep 5
done
echo "token not reachable via http://${CERTBOT_DOMAIN}; continuing, ACME validation may fail" >&2
