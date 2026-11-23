#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Copyright (c) iSPIRT Foundation.
# Licensed under the MIT license.
#
# Deploy this repository's bundle to an Azure Confidential Ledger instance via
# PUT /app/userDefinedEndpoints (the only way to install a JS app on ACL).
#
# Usage: scripts/deploy-acl.sh [--no-build]
#
# Environment:
#   ACL_NAME     ledger name (URL https://<name>.confidential-ledger.azure.com), or
#   ACL_URL      full ledger URL (overrides ACL_NAME)
#   ACL_TOKEN    bearer token for an Administrator principal; if unset, obtained with
#                `az account get-access-token --resource https://confidential-ledger.azure.com`
#   ACL_CACERT   PEM file with the ledger TLS identity; if unset and ACL_NAME is set, it
#                is fetched from the ACL identity service
#   ACL_API_VERSION  default 2024-08-22-preview
#
# The caller must hold the ACL Administrator role. The bundle digest printed
# here must match a governance-approved digest (approve_app_digest) and the
# value served by GET /app/info.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_VERSION="${ACL_API_VERSION:-2024-08-22-preview}"
log() { echo "[deploy-acl] $*" >&2; }
die() { log "error: $*"; exit 1; }

BUILD=1
[[ "${1:-}" == "--no-build" ]] && BUILD=0

if [[ -n "${ACL_URL:-}" ]]; then
  URL="${ACL_URL%/}"
elif [[ -n "${ACL_NAME:-}" ]]; then
  URL="https://${ACL_NAME}.confidential-ledger.azure.com"
else
  die "set ACL_NAME or ACL_URL"
fi

if [[ $BUILD -eq 1 ]]; then
  (cd "$REPO_ROOT" && npm ci --no-audit --no-fund >&2 && npm run --silent build >&2)
fi
BUNDLE="$REPO_ROOT/dist/bundle.json"
[[ -f "$BUNDLE" ]] || die "dist/bundle.json missing"
DIGEST="$(tr -d '\n' < "$REPO_ROOT/dist/bundle_digest.txt")"

TOKEN="${ACL_TOKEN:-}"
if [[ -z "$TOKEN" ]]; then
  command -v az >/dev/null || die "ACL_TOKEN not set and az CLI not found"
  TOKEN="$(az account get-access-token --resource https://confidential-ledger.azure.com --query accessToken -o tsv)"
fi

CACERT="${ACL_CACERT:-}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
if [[ -z "$CACERT" ]]; then
  [[ -n "${ACL_NAME:-}" ]] || die "set ACL_CACERT when using ACL_URL"
  curl -sf "https://identity.confidential-ledger.core.azure.com/ledgerIdentity/${ACL_NAME}" \
    | jq -r '.ledgerTlsCertificate' > "$TMP/ledger.pem"
  CACERT="$TMP/ledger.pem"
fi

log "deploying bundle $DIGEST to $URL"
status="$(curl -sS -o "$TMP/resp" -w '%{http_code}' --cacert "$CACERT" \
  -X PUT "$URL/app/userDefinedEndpoints?api-version=${API_VERSION}" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data-binary "@$BUNDLE")"
if [[ "$status" != 2* ]]; then
  cat "$TMP/resp" >&2
  die "deployment failed with HTTP $status"
fi

for _ in $(seq 1 60); do
  served="$(curl -sf --cacert "$CACERT" "$URL/app/info" | jq -r '.bundle_digest' 2>/dev/null || true)"
  if [[ "$served" == "$DIGEST" ]]; then
    log "deployed; /app/info reports $served"
    jq -cn --arg url "$URL/app" --arg d "$DIGEST" '{app_url: $url, bundle_digest: $d}'
    exit 0
  fi
  sleep 2
done
die "deployment accepted but /app/info does not report $DIGEST"
