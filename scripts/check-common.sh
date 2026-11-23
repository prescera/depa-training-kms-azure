#!/usr/bin/env bash
# Copyright (c) iSPIRT Foundation.
# Licensed under the MIT license.
#
# Fail if the shared code differs between the KMS and contract-service
# repositories. Paths are listed in scripts/common-paths.txt (identical in both
# repositories). Run from either repository.
#
# Usage: scripts/check-common.sh [<path-to-other-repo>]

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(jq -r .name "$REPO_ROOT/package.json")" in
  depa-training-kms) DEFAULT_OTHER="$REPO_ROOT/../contract-service"; ENV_OTHER="${DEPA_CS_REPO:-}" ;;
  depa-contract-service) DEFAULT_OTHER="$REPO_ROOT/../depa-training-kms-azure"; ENV_OTHER="${DEPA_KMS_REPO:-}" ;;
  *) echo "unknown repository" >&2; exit 2 ;;
esac
OTHER="${1:-${ENV_OTHER:-$DEFAULT_OTHER}}"
[[ -d "$OTHER" ]] || { echo "other repository not found: $OTHER" >&2; exit 2; }

status=0
if ! diff -q "$REPO_ROOT/scripts/common-paths.txt" "$OTHER/scripts/common-paths.txt" >/dev/null; then
  echo "scripts/common-paths.txt differs" >&2
  status=1
fi
while IFS= read -r p; do
  [[ -z "$p" || "$p" == \#* ]] && continue
  if ! diff -r -q -x node_modules -x __pycache__ "$REPO_ROOT/$p" "$OTHER/$p" >&2; then
    status=1
  fi
done < "$REPO_ROOT/scripts/common-paths.txt"
if [[ $status -ne 0 ]]; then
  echo "shared code is out of sync; run scripts/sync-common.sh in contract-service" >&2
  exit 1
fi
echo "shared code in sync with $OTHER" >&2
