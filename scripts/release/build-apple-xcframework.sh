#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
RUST_DIR="$ROOT/rust"
DIST_DIR="${AURA_APPLE_DIST_DIR:-$ROOT/dist/apple}"
if [[ "$DIST_DIR" != /* ]]; then
  DIST_DIR="$ROOT/$DIST_DIR"
fi

if [[ -n "${RUSTFLAGS:-}" || -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
  echo "Refusing ambient Rust compiler flags for an Apple release artifact." >&2
  exit 2
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aura-opaque-apple-release.XXXXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM
WORK_DIR="$(cd "$WORK_DIR" && pwd -P)"
INCLUDE_DIR="$WORK_DIR/include"
export CARGO_TARGET_DIR="$WORK_DIR/cargo-target"

RUST_HOST="$(rustc -vV | sed -n 's/^host: //p')"
RUST_SYSROOT="$(cd "$(rustc --print sysroot)" && pwd -P)"
AURA_CARGO_HOME_PATH="${CARGO_HOME:-${HOME:?HOME is required when CARGO_HOME is unset}/.cargo}"
[[ -d "$AURA_CARGO_HOME_PATH" ]] || {
  echo "Cargo home is unavailable: $AURA_CARGO_HOME_PATH" >&2
  exit 2
}
AURA_CARGO_HOME_PATH="$(cd "$AURA_CARGO_HOME_PATH" && pwd -P)"

remap_flags=(
  "--remap-path-prefix=$ROOT=/aura/opaque/source"
  "--remap-path-prefix=$WORK_DIR=/aura/opaque/build"
  "--remap-path-prefix=$AURA_CARGO_HOME_PATH=/aura/cargo"
  "--remap-path-prefix=$RUST_SYSROOT=/aura/rust"
)
printf -v CARGO_ENCODED_RUSTFLAGS '%s\x1f' "${remap_flags[@]}"
CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS%$'\x1f'}"
export CARGO_ENCODED_RUSTFLAGS

LLVM_STRIP="${AURA_LLVM_STRIP:-$RUST_SYSROOT/lib/rustlib/$RUST_HOST/bin/llvm-strip}"
[[ -x "$LLVM_STRIP" ]] || {
  echo "Rust llvm-strip is required; install llvm-tools-preview." >&2
  exit 2
}

mkdir -p "$DIST_DIR"
mkdir -p "$INCLUDE_DIR"

cp "$RUST_DIR"/include/*.h "$INCLUDE_DIR"/
cp "$RUST_DIR"/include/module.modulemap "$INCLUDE_DIR"/module.modulemap

cargo build --release --locked --package opaque-ffi --target aarch64-apple-darwin --manifest-path "$RUST_DIR/Cargo.toml"
cargo build --release --locked --package opaque-ffi --target aarch64-apple-ios --manifest-path "$RUST_DIR/Cargo.toml"
cargo build --release --locked --package opaque-ffi --target aarch64-apple-ios-sim --manifest-path "$RUST_DIR/Cargo.toml"
cargo build --release --locked --package opaque-ffi --target x86_64-apple-ios --manifest-path "$RUST_DIR/Cargo.toml"
cargo build --release --locked --package opaque-ffi --target aarch64-apple-ios-macabi --manifest-path "$RUST_DIR/Cargo.toml"
cargo build --release --locked --package opaque-ffi --target x86_64-apple-ios-macabi --manifest-path "$RUST_DIR/Cargo.toml"

MACOS_LIB="$WORK_DIR/libopaque_ffi_macos.a"
DEVICE_LIB="$WORK_DIR/libopaque_ffi_ios.a"
SIM_LIB="$WORK_DIR/libopaque_ffi_sim.a"
MACABI_LIB="$WORK_DIR/libopaque_ffi_maccatalyst.a"

cp "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/libopaque_ffi.a" "$MACOS_LIB"
cp "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libopaque_ffi.a" "$DEVICE_LIB"

lipo -create \
  "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libopaque_ffi.a" \
  "$CARGO_TARGET_DIR/x86_64-apple-ios/release/libopaque_ffi.a" \
  -output "$SIM_LIB"

lipo -create \
  "$CARGO_TARGET_DIR/aarch64-apple-ios-macabi/release/libopaque_ffi.a" \
  "$CARGO_TARGET_DIR/x86_64-apple-ios-macabi/release/libopaque_ffi.a" \
  -output "$MACABI_LIB"

for archive in "$MACOS_LIB" "$DEVICE_LIB" "$SIM_LIB" "$MACABI_LIB"; do
  "$LLVM_STRIP" -S "$archive"
  strings "$archive" >"$WORK_DIR/$(basename "$archive").strings"
  for forbidden_path in "$ROOT" "$WORK_DIR" "$AURA_CARGO_HOME_PATH" "$RUST_SYSROOT"; do
    if grep -F "$forbidden_path" "$WORK_DIR/$(basename "$archive").strings" >/dev/null; then
      echo "Release archive contains a local build path: $forbidden_path" >&2
      exit 1
    fi
  done
done

rm -rf "$DIST_DIR/AuraOPAQUE.xcframework" "$DIST_DIR/AuraOPAQUE.xcframework.zip"

xcodebuild -create-xcframework \
  -library "$MACOS_LIB" -headers "$INCLUDE_DIR" \
  -library "$DEVICE_LIB" -headers "$INCLUDE_DIR" \
  -library "$SIM_LIB" -headers "$INCLUDE_DIR" \
  -library "$MACABI_LIB" -headers "$INCLUDE_DIR" \
  -output "$DIST_DIR/AuraOPAQUE.xcframework"

# xcodebuild does not guarantee AvailableLibraries ordering. Canonicalize the
# plist so provenance hashes compare release content rather than host ordering.
python3 - "$DIST_DIR/AuraOPAQUE.xcframework/Info.plist" <<'PY'
import os
import plistlib
import sys
import tempfile

path = sys.argv[1]
with open(path, "rb") as source:
    document = plistlib.load(source)
document["AvailableLibraries"] = sorted(
    document["AvailableLibraries"],
    key=lambda library: library["LibraryIdentifier"],
)
directory = os.path.dirname(path)
descriptor, temporary = tempfile.mkstemp(prefix="Info.", suffix=".plist", dir=directory)
try:
    with os.fdopen(descriptor, "wb") as destination:
        plistlib.dump(document, destination, fmt=plistlib.FMT_XML, sort_keys=True)
    os.replace(temporary, path)
except BaseException:
    os.unlink(temporary)
    raise
PY

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
