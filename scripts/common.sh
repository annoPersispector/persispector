#!/usr/bin/env bash

# Shared configuration and helpers for the artifact runners.

set -euo pipefail

readonly SCRIPTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ARTIFACT_ROOT="$(cd -- "$SCRIPTS_DIR/.." && pwd)"
readonly DATASET_DIR="${PERSISPECTOR_DATASET_DIR:-$ARTIFACT_ROOT/dataset}"
readonly REPRODUCED_DIR="${PERSISPECTOR_REPRODUCED_DIR:-$ARTIFACT_ROOT/reproduced}"

readonly -a APPLICATIONS=(
  "Baeldung_spring-security-registration"
  "apache_seatunnel-web"
  "ddd-by-examples_all-things-cqrs__in-one-class"
  "eclipse-jifa_jifa"
  "eventuate-tram_eventuate-tram-examples-customers-and-orders"
  "funtl_MyShopPlus"
  "gothinkster_spring-boot-realworld-example-app"
  "spinnaker_kayenta"
  "vipshop_Saturn"
  "yanagishima_yanagishima"
)

declare -Ar APPLICATION_PORTS=(
  ["Baeldung_spring-security-registration"]="18206"
  ["apache_seatunnel-web"]="18200"
  ["ddd-by-examples_all-things-cqrs__in-one-class"]="18207"
  ["eclipse-jifa_jifa"]="18201"
  ["eventuate-tram_eventuate-tram-examples-customers-and-orders"]="18202"
  ["funtl_MyShopPlus"]="18205 20882"
  ["gothinkster_spring-boot-realworld-example-app"]="18208"
  ["spinnaker_kayenta"]="18204 16379"
  ["vipshop_Saturn"]="18205 2181"
  ["yanagishima_yanagishima"]="18209"
)

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

list_applications() {
  printf '%s\n' "${APPLICATIONS[@]}"
}

require_application() {
  local requested="$1"
  local application
  for application in "${APPLICATIONS[@]}"; do
    if [[ "$requested" == "$application" ]]; then
      return 0
    fi
  done
  die "unknown application '$requested'; use --list to see valid identifiers"
}

resolve_task_directory() {
  local application="$1"
  local application_root="$DATASET_DIR/$application"
  local candidate=""
  local found=""
  local count=0

  [[ -d "$application_root" ]] || die "dataset application is missing: $application_root"
  for candidate in "$application_root"/*; do
    if [[ -d "$candidate/application" && -f "$candidate/task.json" ]]; then
      found="$candidate"
      ((count += 1))
    fi
  done
  [[ "$count" -eq 1 ]] || die "expected one task bundle under $application_root; found $count"
  printf '%s\n' "$found"
}

resolve_executable() {
  local override="$1"
  local environment_path="$2"
  local fallback="$3"
  local resolved=""

  if [[ -n "$override" ]]; then
    resolved="$(command -v -- "$override" 2>/dev/null || true)"
    [[ -n "$resolved" ]] || die "configured executable not found: $override"
    printf '%s\n' "$resolved"
    return
  fi
  if [[ -x "$environment_path" ]]; then
    printf '%s\n' "$environment_path"
    return
  fi
  resolved="$(command -v -- "$fallback" 2>/dev/null || true)"
  [[ -n "$resolved" ]] || die "$fallback is not installed; complete the README environment setup"
  printf '%s\n' "$resolved"
}

print_command() {
  local argument
  printf 'cd %q && ' "$ARTIFACT_ROOT"
  for argument in "$@"; do
    printf '%q ' "$argument"
  done
  printf '\n'
}

confirm_batch() {
  local prompt="$1"
  if [[ ! -t 0 ]]; then
    die "batch confirmation requires a terminal; pass --yes for non-interactive use"
  fi
  local answer=""
  read -r -p "$prompt [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || die "cancelled"
}
