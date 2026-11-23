#!/usr/bin/env bash
# Format-check and validate every Terraform module/environment under a root.
#
#   scripts/validate.sh [ROOT_DIR] [--only <subdir>...]
#
# For each directory containing *.tf files (excluding .terraform/ and tests/):
#   terraform init -backend=false && terraform validate
#   + terraform test when the directory has tests/*.tftest.hcl (mocked providers only)
# Never touches remote state or cloud APIs.
#
# Directories that consume modules from other repositories (git sources) ship a
# `local_override.tf.tpl`. When the variables it references are set, it is
# rendered to `local_override.tf` (gitignored) for the duration of the run so the
# directory validates against local checkouts:
#   DEPA_KMS_AZURE_DIR         absolute path of a depa-training-kms-azure checkout
#   DEPA_CONTRACT_SERVICE_DIR  absolute path of a contract-service checkout
# If they are unset, the pinned git sources are used as-is.
set -euo pipefail

root="$(cd "${1:-$(dirname "$0")/..}" && pwd)"
shift || true
only=()
if [[ "${1:-}" == "--only" ]]; then
  shift
  only=("$@")
fi

tf="${TERRAFORM:-terraform}"
export TF_IN_AUTOMATION=1
export TF_INPUT=0
export CHECKPOINT_DISABLE=1
export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-${HOME}/.terraform.d/plugin-cache}"
mkdir -p "${TF_PLUGIN_CACHE_DIR}"

work="$(mktemp -d)"
cleanup_files=()
cleanup() {
  for f in "${cleanup_files[@]}"; do rm -f "$f"; done
  rm -rf "${work}"
}
trap cleanup EXIT

echo "==> terraform fmt -check (${root})"
fmt_status=0
"${tf}" fmt -check -recursive -diff "${root}" || fmt_status=$?

mapfile -t dirs < <(find "${root}" -name '*.tf' -not -path '*/.terraform/*' -not -path '*/tests/*' -printf '%h\n' | sort -u)

declare -a results=()
failed=0
for dir in "${dirs[@]}"; do
  rel="${dir#"${root}"/}"
  if [[ ${#only[@]} -gt 0 ]]; then
    match=0
    for o in "${only[@]}"; do [[ "${rel}" == "${o}"* ]] && match=1; done
    [[ ${match} -eq 1 ]] || continue
  fi

  if [[ -f "${dir}/local_override.tf.tpl" && -n "${DEPA_KMS_AZURE_DIR:-}${DEPA_CONTRACT_SERVICE_DIR:-}" ]]; then
    envsubst '${DEPA_KMS_AZURE_DIR} ${DEPA_CONTRACT_SERVICE_DIR}' \
      <"${dir}/local_override.tf.tpl" >"${dir}/local_override.tf"
    cleanup_files+=("${dir}/local_override.tf")
  fi

  had_lock=0
  [[ -f "${dir}/.terraform.lock.hcl" ]] && had_lock=1
  data_dir="${work}/$(echo "${rel}" | tr '/' '_')"
  log="${data_dir}.log"
  status="ok"
  if ! TF_DATA_DIR="${data_dir}" "${tf}" -chdir="${dir}" init -backend=false -no-color >"${log}" 2>&1; then
    status="init-failed"
  elif ! TF_DATA_DIR="${data_dir}" "${tf}" -chdir="${dir}" validate -no-color >>"${log}" 2>&1; then
    status="invalid"
  elif compgen -G "${dir}/tests/*.tftest.hcl" >/dev/null &&
    ! TF_DATA_DIR="${data_dir}" "${tf}" -chdir="${dir}" test -no-color >>"${log}" 2>&1; then
    status="test-failed"
  fi
  [[ ${had_lock} -eq 0 ]] && rm -f "${dir}/.terraform.lock.hcl"
  if [[ "${status}" != "ok" ]]; then
    failed=1
    echo "---- ${rel}: ${status}"
    sed 's/^/    /' "${log}" | tail -n 40
  fi
  results+=("$(printf '%-60s %s' "${rel}" "${status}")")
done

echo
echo "==> summary"
printf '%s\n' "${results[@]}"
if [[ ${fmt_status} -ne 0 ]]; then
  echo "terraform fmt -check: FAILED (run: terraform fmt -recursive ${root})"
  failed=1
else
  echo "terraform fmt -check: ok"
fi
exit "${failed}"
