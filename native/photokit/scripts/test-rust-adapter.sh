#!/bin/bash
set -euo pipefail

NATIVE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$NATIVE_ROOT/../.." && pwd)"
BIN_PATH="$(swift build \
  --disable-sandbox \
  --package-path "$NATIVE_ROOT" \
  --show-bin-path)"
TOOLCHAIN="$(cd "$(dirname "$(xcrun --find swiftc)")/.." && pwd)"
SDK="$(xcrun --sdk macosx --show-sdk-path)"

test -f "$BIN_PATH/libWardrobePhotoKit.a"

export MACOSX_DEPLOYMENT_TARGET=15.0
export RUSTFLAGS="\
-Lnative=$BIN_PATH \
-Lnative=$TOOLCHAIN/lib/swift/macosx \
-Lnative=$SDK/usr/lib/swift \
-lstatic=WardrobePhotoKit \
-lframework=AppKit \
-lframework=Foundation \
-lframework=ImageIO \
-lframework=Photos \
-lframework=PhotosUI \
-lframework=UniformTypeIdentifiers \
-Clink-arg=-Wl,-rpath,/usr/lib/swift"

cargo test \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  -p wardrobe-platform \
  --features photokit-native \
  --test photokit_native_adapter
