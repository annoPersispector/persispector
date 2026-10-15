#!/usr/bin/env bash

set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

usage() {
  cat <<'EOF'
Usage: scripts/run_persistence_all.sh [--dry-run] [--yes] [-- EXTRA_OPTIONS...]

Runs the static persistence pipeline sequentially for all ten applications.
Extra options after -- are passed to each invocation.
EOF
}

dry_run=0
assume_yes=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    --yes) assume_yes=1; shift ;;
    --) shift; break ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown wrapper option: $1" ;;
  esac
done
extra_options=("$@")

single_runner="$SCRIPTS_DIR/run_persistence.sh"
for application in "${APPLICATIONS[@]}"; do
  arguments=(--dry-run "$application")
  if [[ ${#extra_options[@]} -gt 0 ]]; then
    arguments+=(-- "${extra_options[@]}")
  fi
  "$single_runner" "${arguments[@]}" >/dev/null
done

if [[ "$dry_run" -eq 1 ]]; then
  for application in "${APPLICATIONS[@]}"; do
    arguments=(--dry-run "$application")
    if [[ ${#extra_options[@]} -gt 0 ]]; then
      arguments+=(-- "${extra_options[@]}")
    fi
    "$single_runner" "${arguments[@]}"
  done
  exit 0
fi

if [[ "$assume_yes" -ne 1 ]]; then
  confirm_batch "Run static analysis, including model and CodeQL calls, for all ten applications?"
fi

for application in "${APPLICATIONS[@]}"; do
  arguments=("$application")
  if [[ ${#extra_options[@]} -gt 0 ]]; then
    arguments+=(-- "${extra_options[@]}")
  fi
  "$single_runner" "${arguments[@]}"
done
