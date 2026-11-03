#!/usr/bin/env bash
# The repository gate: formatting, lints, tests (native, wasm, web, end-to-end), supply chain.
# Stops at the first failing stage and names it. CI runs this script as is.
# Usage: scripts/check.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ "$#" -ne 0 ]; then
  echo "usage: scripts/check.sh" >&2
  exit 2
fi

SUMMARY=()

stage() {
  local name="$1"
  shift
  printf '\n==> %s\n' "$name"
  local start=$SECONDS
  if ! "$@"; then
    printf '\ncheck: FAILED at stage "%s"\n' "$name" >&2
    exit 1
  fi
  SUMMARY+=("$(printf '%-14s %4ds' "$name" $((SECONDS - start)))")
}

need_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "check: $1 is not installed; $2" >&2
    return 1
  fi
}

supply_chain() {
  need_tool cargo-deny "cargo install cargo-deny" || return 1
  need_tool cargo-audit "cargo install cargo-audit" || return 1
  cargo deny check && cargo audit
}

wasm_test() {
  wasm-pack test --node crates/otpx-wasm
}

web_checks() {
  (cd web && bunx biome ci . && bunx tsc --noEmit -p . && bun test)
}

e2e() {
  (cd web && bunx playwright test)
}

lint_workflows() {
  need_tool actionlint "brew install actionlint" || return 1
  actionlint
}

lint_scripts() {
  need_tool shellcheck "brew install shellcheck" || return 1
  shellcheck scripts/*.sh
}

stage fmt cargo fmt --all --check
stage clippy cargo clippy --workspace --all-targets --locked -- -D warnings
stage clippy-wasm32 cargo clippy -p otpx-core -p otpx-wasm --target wasm32-unknown-unknown --locked -- -D warnings
stage build-web scripts/build-web.sh
stage test cargo test --workspace --locked --features otpx/embed-web
stage wasm-test wasm_test
stage web web_checks
stage e2e e2e
stage deny-audit supply_chain
stage actionlint lint_workflows
stage shellcheck lint_scripts

printf '\ncheck: all stages passed\n'
printf '  %s\n' "${SUMMARY[@]}"
printf '  %-14s %4ds\n' total "$SECONDS"
