#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUST_DIR="$ROOT/rust"
DIST_DIR="$ROOT/dist/apple"
INCLUDE_DIR="$RUST_DIR/target/include"

mkdir -p "$DIST_DIR"
rm -rf "$INCLUDE_DIR"
mkdir -p "$INCLUDE_DIR"

cp "$RUST_DIR"/include/*.h "$INCLUDE_DIR"/
cp "$RUST_DIR"/include/module.modulemap "$INCLUDE_DIR"/module.modulemap

cargo build --release --package opaque-ffi --target aarch64-apple-darwin --manifest-path "$RUST_DIR/Cargo.toml"
cargo build --release --package opaque-ffi --target aarch64-apple-ios --manifest-path "$RUST_DIR/Cargo.toml"
cargo build --release --package opaque-ffi --target aarch64-apple-ios-sim --manifest-path "$RUST_DIR/Cargo.toml"
cargo build --release --package opaque-ffi --target x86_64-apple-ios --manifest-path "$RUST_DIR/Cargo.toml"
cargo build --release --package opaque-ffi --target aarch64-apple-ios-macabi --manifest-path "$RUST_DIR/Cargo.toml"
cargo build --release --package opaque-ffi --target x86_64-apple-ios-macabi --manifest-path "$RUST_DIR/Cargo.toml"

lipo -create \
  "$RUST_DIR/target/aarch64-apple-ios-sim/release/libopaque_ffi.a" \
  "$RUST_DIR/target/x86_64-apple-ios/release/libopaque_ffi.a" \
  -output "$RUST_DIR/target/libopaque_ffi_sim.a"

lipo -create \
  "$RUST_DIR/target/aarch64-apple-ios-macabi/release/libopaque_ffi.a" \
  "$RUST_DIR/target/x86_64-apple-ios-macabi/release/libopaque_ffi.a" \
  -output "$RUST_DIR/target/libopaque_ffi_maccatalyst.a"

rm -rf "$DIST_DIR/AuraOPAQUE.xcframework" "$DIST_DIR/AuraOPAQUE.xcframework.zip"

xcodebuild -create-xcframework \
  -library "$RUST_DIR/target/aarch64-apple-darwin/release/libopaque_ffi.a" -headers "$INCLUDE_DIR" \
  -library "$RUST_DIR/target/aarch64-apple-ios/release/libopaque_ffi.a" -headers "$INCLUDE_DIR" \
  -library "$RUST_DIR/target/libopaque_ffi_sim.a" -headers "$INCLUDE_DIR" \
  -library "$RUST_DIR/target/libopaque_ffi_maccatalyst.a" -headers "$INCLUDE_DIR" \
  -output "$DIST_DIR/AuraOPAQUE.xcframework"

# Aura Messenger links OPAQUE through @_silgen_name and does not import the
# packaged C module directly. Dropping the module map avoids an Xcode 26
# ProcessXCFramework collision when multiple local binary packages ship a
# top-level module.modulemap into the same derived include directory.
find "$DIST_DIR/AuraOPAQUE.xcframework" -name module.modulemap -delete

test -f "$DIST_DIR/AuraOPAQUE.xcframework/macos-arm64/Headers/opaque_api.h"
test -f "$DIST_DIR/AuraOPAQUE.xcframework/macos-arm64/Headers/opaque_relay.h"

(
  cd "$DIST_DIR"
  zip -r AuraOPAQUE.xcframework.zip AuraOPAQUE.xcframework >/dev/null
  swift package compute-checksum AuraOPAQUE.xcframework.zip > AuraOPAQUE.xcframework.zip.checksum
)

echo "Built: $DIST_DIR/AuraOPAQUE.xcframework.zip"
echo "Checksum: $(tr -d '[:space:]' < "$DIST_DIR/AuraOPAQUE.xcframework.zip.checksum")"
