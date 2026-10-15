#!/usr/bin/env bash

set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/run_verification.sh --list
  scripts/run_verification.sh [--dry-run] APPLICATION [-- EXTRA_OPTIONS...]

Runs runtime verification for one application using its reproduced static
report. Extra options after -- are passed to `persispector-verify delegate`.
EOF
}

if [[ "${1:-}" == "--list" ]]; then
  list_applications
  exit 0
fi
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

dry_run=0
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=1
  shift
fi
[[ $# -ge 1 ]] || { usage >&2; exit 2; }

application="$1"
shift
if [[ "${1:-}" == "--" ]]; then
  shift
fi

require_application "$application"
task_directory="$(resolve_task_directory "$application")"
project_directory="$task_directory/application"
static_directory="$REPRODUCED_DIR/$application/static"
constraint_report="$static_directory/persistence-constraints.json"
taint_report="$static_directory/persistence-taint.json"
[[ -f "$constraint_report" ]] || die "missing static report: $constraint_report; run run_persistence.sh first"
[[ -f "$taint_report" ]] || die "missing taint report: $taint_report; run run_persistence.sh first"

run_id="${PERSISPECTOR_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ "$run_id" =~ ^[A-Za-z0-9._-]+$ ]] || die "PERSISPECTOR_RUN_ID contains unsafe characters"
runtime_directory="$REPRODUCED_DIR/$application/runtime-$run_id"
verification_model="${PERSISPECTOR_VERIFY_MODEL:-claude-opus-5-5}"
verification_bin="$(resolve_executable \
  "${PERSISPECTOR_VERIFY_BIN:-}" \
  "$ARTIFACT_ROOT/.venv/bin/persispector-verify" \
  "persispector-verify")"

command=(
  "$verification_bin" delegate
  "$project_directory"
  "$constraint_report"
  --taint-report "$taint_report"
  --task-directory "$runtime_directory"
  --application "$application"
)
read -r -a allowed_ports <<< "${APPLICATION_PORTS[$application]}"
for port in "${allowed_ports[@]}"; do
  command+=(--allowed-port "$port")
done
command+=(--allow-dependency-downloads --model "$verification_model")
command+=("$@")

if [[ "$dry_run" -eq 1 ]]; then
  print_command "${command[@]}"
  exit 0
fi

[[ ! -e "$runtime_directory" ]] || die "runtime task already exists: $runtime_directory; choose another PERSISPECTOR_RUN_ID"

printf 'Running runtime verification for %s\n' "$application"
printf 'Task output: %s\n' "$runtime_directory"
(cd -- "$ARTIFACT_ROOT" && "${command[@]}")
