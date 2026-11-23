#!/usr/bin/env bash
# Copyright (c) iSPIRT Foundation.
# Licensed under the MIT license.
#
# Stop and remove local sandbox containers started by scripts/sandbox-up.sh.
#
# Usage: scripts/sandbox-down.sh [<port> | --all] [--purge]
#   <port>   remove the sandbox for that port (depa2-dc-<svc>-<port>)
#   --all    remove every sandbox of this service (depa2-dc-<svc>-*)
#   --purge  also delete the sandbox workspace directory (ledger, certs)
# Only containers created by sandbox-up.sh for this service are touched.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(jq -r .name "$REPO_ROOT/package.json")" in
  depa-training-kms) SHORT=kms ;;
  depa-contract-service) SHORT=cs ;;
  *) echo "unknown service in package.json" >&2; exit 1 ;;
esac
BASE="${DEPA_SANDBOX_DIR:-$REPO_ROOT/workspace}"

TARGET="${1:---all}"
PURGE=0
[[ "${2:-}" == "--purge" || "${1:-}" == "--purge" ]] && PURGE=1
[[ "$TARGET" == "--purge" ]] && TARGET="--all"

if [[ "$TARGET" == "--all" ]]; then
  mapfile -t names < <(docker ps -a --format '{{.Names}}' | grep -E "^depa2-dc-${SHORT}-[0-9]+$" || true)
else
  [[ "$TARGET" =~ ^[0-9]+$ ]] || { echo "usage: $0 [<port> | --all] [--purge]" >&2; exit 1; }
  names=("depa2-dc-${SHORT}-${TARGET}")
fi

for n in "${names[@]}"; do
  if docker inspect "$n" >/dev/null 2>&1; then
    docker rm -f "$n" >/dev/null
    echo "[sandbox-down] removed $n" >&2
  fi
  if [[ $PURGE -eq 1 ]]; then
    rm -rf "$BASE/sandbox-${n##*-}"
  fi
done
if [[ $PURGE -eq 1 && "$TARGET" == "--all" ]]; then
  rm -rf "$BASE"/sandbox-*
fi
