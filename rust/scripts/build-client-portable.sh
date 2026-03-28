#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET="${1:-}"

cd "${RUST_DIR}"

if [[ -n "${TARGET}" ]]; then
  cargo build --release --package opaque-ffi --target "${TARGET}"
else
  cargo build --release --package opaque-ffi
fi
