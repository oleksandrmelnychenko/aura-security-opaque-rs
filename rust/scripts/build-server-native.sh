#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET="${1:-}"
OLD_RUSTFLAGS="${RUSTFLAGS:-}"

cleanup() {
  export RUSTFLAGS="${OLD_RUSTFLAGS}"
}
trap cleanup EXIT

if [[ -n "${OLD_RUSTFLAGS}" ]]; then
  export RUSTFLAGS="${OLD_RUSTFLAGS} -C target-cpu=native"
else
  export RUSTFLAGS="-C target-cpu=native"
fi

cd "${RUST_DIR}"

if [[ -n "${TARGET}" ]]; then
  cargo build --release --package opaque-ffi --target "${TARGET}"
else
  cargo build --release --package opaque-ffi
fi
