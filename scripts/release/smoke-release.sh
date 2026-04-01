#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUST_DIR="$ROOT/rust"

cargo fmt --manifest-path "$RUST_DIR/Cargo.toml" --all --check
cargo clippy --manifest-path "$RUST_DIR/Cargo.toml" --workspace --all-targets --locked -- -D warnings
cargo test --manifest-path "$RUST_DIR/Cargo.toml" --workspace --tests --lib --locked
cargo build --manifest-path "$RUST_DIR/Cargo.toml" --package opaque-ffi --locked

test -f "$RUST_DIR/target/debug/libopaque_ffi.a"

cc "$ROOT/tests/c/ffi_smoke.c" \
  -I "$RUST_DIR/include" \
  -L "$RUST_DIR/target/debug" \
  -lopaque_ffi \
  -o /tmp/ecliptix_opaque_ffi_smoke
/tmp/ecliptix_opaque_ffi_smoke

swift build --package-path "$ROOT"

echo "Release smoke checks passed."
