#!/usr/bin/env bash
# Builds the browser core (crates/otpx-wasm) into web/pkg, then the web app into web/dist.
# Usage: scripts/build-web.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ "$#" -ne 0 ]; then
  echo "usage: scripts/build-web.sh" >&2
  exit 2
fi

for tool in cargo wasm-pack bun; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "build-web: $tool is required" >&2
    exit 1
  fi
done

# Size over speed for the browser build only; Argon2 stays well under 200 ms at 64 MiB.
CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_PANIC=abort \
  wasm-pack build crates/otpx-wasm --target web --release --out-dir ../../web/pkg --out-name otpx --no-pack

cd web
bun install --frozen-lockfile
bun run build.ts
