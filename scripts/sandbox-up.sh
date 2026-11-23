#!/usr/bin/env bash
# Copyright (c) iSPIRT Foundation.
# Licensed under the MIT license.
#
# Start a local CCF virtual sandbox in Docker with this repository's app
# bundle deployed, and print connection details as one JSON object on stdout.
#
# Usage: scripts/sandbox-up.sh <port> [--jwt-issuer <issuer.json>] [--no-build] [--recreate]
#
#   <port>          host port in 18000-18199; the node listens on 127.0.0.1:<port>
#   --jwt-issuer F  register a JWT issuer at network start (CCF set_jwt_issuer;
#                   F = {"issuer": "...", "auto_refresh": false, "jwks": {"keys": [...]}})
#   --no-build      deploy the existing dist/ bundle instead of running `npm run build`
#   --recreate      always start a fresh network
#
# Idempotent: if a sandbox for <port> is already running with the same bundle
# digest and issuer file, it is reused (state preserved). Otherwise any previous
# sandbox container for <port> is replaced by a fresh network.
#
# Output (stdout, single line JSON):
#   {"url": "https://127.0.0.1:<port>", "app_url": "https://127.0.0.1:<port>/app",
#    "service_cert": "<dir>/service_cert.pem", "user_cert": ..., "user_key": ...,
#    "member_cert": ..., "member_key": ..., "container": "...", "bundle_digest": "sha256:...",
#    "workspace": "<dir>"}
# <dir> = ${DEPA_SANDBOX_DIR:-<repo>/workspace}/sandbox-<port>
# Logs go to stderr. Container/image names are prefixed "depa2-dc-".

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DEPA_SANDBOX_IMAGE:-depa2-dc-ccf-sandbox:6.0.0-rc1}"

log() { echo "[sandbox-up] $*" >&2; }
die() { log "error: $*"; exit 1; }

PORT="${1:-}"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "usage: $0 <port> [--jwt-issuer <file>] [--no-build] [--recreate]"
(( PORT >= 18000 && PORT <= 18199 )) || die "port must be in 18000-18199"
shift

JWT_ISSUER=""
BUILD=1
RECREATE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --jwt-issuer) JWT_ISSUER="$(realpath "$2")"; shift 2 ;;
    --no-build) BUILD=0; shift ;;
    --recreate) RECREATE=1; shift ;;
    *) die "unknown argument $1" ;;
  esac
done

case "$(jq -r .name "$REPO_ROOT/package.json")" in
  depa-training-kms) SHORT=kms ;;
  depa-contract-service) SHORT=cs ;;
  *) die "unknown service in package.json" ;;
esac
CONTAINER="depa2-dc-${SHORT}-${PORT}"
WORKDIR="$(mkdir -p "${DEPA_SANDBOX_DIR:-$REPO_ROOT/workspace}" && cd "${DEPA_SANDBOX_DIR:-$REPO_ROOT/workspace}" && pwd)/sandbox-${PORT}"

if [[ $BUILD -eq 1 ]]; then
  log "building bundle"
  (cd "$REPO_ROOT" && { [[ -d node_modules ]] || npm ci --no-audit --no-fund >&2; } && npm run --silent build >&2)
fi
[[ -f "$REPO_ROOT/dist/bundle.json" ]] || die "dist/bundle.json missing (run npm run build)"
DIGEST="$(tr -d '\n' < "$REPO_ROOT/dist/bundle_digest.txt")"
ISSUER_HASH="none"
[[ -n "$JWT_ISSUER" ]] && ISSUER_HASH="$(sha256sum "$JWT_ISSUER" | cut -d' ' -f1)"

emit() {
  jq -cn --arg port "$PORT" --arg dir "$WORKDIR" --arg c "$CONTAINER" --arg d "$DIGEST" '{
    url: ("https://127.0.0.1:" + $port), app_url: ("https://127.0.0.1:" + $port + "/app"),
    service_cert: ($dir + "/service_cert.pem"), user_cert: ($dir + "/user0_cert.pem"),
    user_key: ($dir + "/user0_privk.pem"), member_cert: ($dir + "/member0_cert.pem"),
    member_key: ($dir + "/member0_privk.pem"), container: $c, bundle_digest: $d, workspace: $dir }'
}

if [[ $RECREATE -eq 0 ]] && [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" == "true" ]] \
  && [[ "$(docker inspect -f '{{index .Config.Labels "depa2.bundle"}}' "$CONTAINER")" == "$DIGEST" ]] \
  && [[ "$(docker inspect -f '{{index .Config.Labels "depa2.issuer"}}' "$CONTAINER")" == "$ISSUER_HASH" ]] \
  && [[ -f "$WORKDIR/service_cert.pem" ]]; then
  log "reusing running sandbox $CONTAINER"
  emit
  exit 0
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "building image $IMAGE"
  docker build -q -t "$IMAGE" -f "$REPO_ROOT/docker/Dockerfile.ccf-sandbox" "$REPO_ROOT/docker" >&2
fi

if docker inspect "$CONTAINER" >/dev/null 2>&1; then
  log "replacing existing $CONTAINER"
  docker rm -f "$CONTAINER" >/dev/null
fi

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/bundle/src"
cp "$REPO_ROOT/app.json" "$WORKDIR/bundle/app.json"
cp "$REPO_ROOT"/dist/src/*.js "$WORKDIR/bundle/src/"
EXTRA=()
if [[ -n "$JWT_ISSUER" ]]; then
  cp "$JWT_ISSUER" "$WORKDIR/jwt_issuer.json"
  EXTRA+=(--jwt-issuer /sandbox/jwt_issuer.json)
fi

log "starting $CONTAINER on 127.0.0.1:$PORT"
docker run -d --name "$CONTAINER" \
  --label "depa2.bundle=$DIGEST" --label "depa2.issuer=$ISSUER_HASH" \
  --user "$(id -u):$(id -g)" -e HOME=/sandbox \
  -p "127.0.0.1:${PORT}:${PORT}" \
  -v "$WORKDIR:/sandbox" \
  "$IMAGE" bash -c ". /opt/ccf-venv/bin/activate && cd /sandbox && exec /opt/ccf_virtual/bin/sandbox.sh \
    --js-app-bundle /sandbox/bundle -n local://0.0.0.0:${PORT},127.0.0.1:${PORT} \
    --initial-member-count 1 --initial-user-count 1 --workspace /sandbox/ws ${EXTRA[*]:-}" >/dev/null

for _ in $(seq 1 180); do
  if [[ -f "$WORKDIR/ws/sandbox_common/user0_privk.pem" ]] \
    && curl -sf --cacert "$WORKDIR/ws/sandbox_common/service_cert.pem" "https://127.0.0.1:${PORT}/app/info" >/dev/null 2>&1; then
    for f in service_cert.pem user0_cert.pem user0_privk.pem member0_cert.pem member0_privk.pem; do
      cp "$WORKDIR/ws/sandbox_common/$f" "$WORKDIR/$f"
    done
    log "ready: https://127.0.0.1:${PORT}/app (bundle $DIGEST)"
    emit
    exit 0
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" != "true" ]]; then
    docker logs "$CONTAINER" 2>&1 | tail -40 >&2
    die "sandbox container exited"
  fi
  sleep 1
done
docker logs "$CONTAINER" 2>&1 | tail -40 >&2
die "sandbox did not become ready in 180 s"
