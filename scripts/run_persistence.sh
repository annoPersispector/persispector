#!/usr/bin/env bash

set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/run_persistence.sh --list
  scripts/run_persistence.sh [--dry-run] APPLICATION [-- EXTRA_OPTIONS...]

Runs the complete static persistence pipeline for one dataset application.
Extra options after -- are passed to `persispector-persistence run`.
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
output_directory="$REPRODUCED_DIR/$application/static"
persistence_bin="$(resolve_executable \
  "${PERSISPECTOR_PERSISTENCE_BIN:-}" \
  "$ARTIFACT_ROOT/.venv/bin/persispector-persistence" \
  "persispector-persistence")"

command=(
  "$persistence_bin" run "$project_directory"
  --output-dir "$output_directory"
  --codeql-taint
)
command+=("$@")

if [[ "$dry_run" -eq 1 ]]; then
  print_command "${command[@]}"
  exit 0
fi

if [[ -e "$output_directory" ]]; then
  die "output already exists: $output_directory; move it or set PERSISPECTOR_REPRODUCED_DIR"
fi

printf 'Running static analysis for %s\n' "$application"
(cd -- "$ARTIFACT_ROOT" && "${command[@]}")
