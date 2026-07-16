#!/bin/bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_ROOT="${1:-"$ROOT/dist"}"
APP="$OUTPUT_ROOT/P00PhotoKitNativeProbe.app"
SCRATCH_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/wardrobe-p00-photokit-swift.XXXXXX")"
trap 'rm -rf "$SCRATCH_ROOT"' EXIT

export CLANG_MODULE_CACHE_PATH="$SCRATCH_ROOT/clang-module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$SCRATCH_ROOT/swift-module-cache"

if [[ -e "$APP" ]]; then
    echo "refusing to replace existing bundle: $APP" >&2
    exit 73
fi

swift build \
    --package-path "$ROOT" \
    --scratch-path "$SCRATCH_ROOT/build" \
    --configuration release \
    --product P00PhotoKitProbe

BIN_DIR="$(swift build \
    --package-path "$ROOT" \
    --scratch-path "$SCRATCH_ROOT/build" \
    --configuration release \
    --show-bin-path)"

mkdir -p "$APP/Contents/MacOS"
install -m 0755 "$BIN_DIR/P00PhotoKitProbe" "$APP/Contents/MacOS/P00PhotoKitProbe"
install -m 0644 "$ROOT/AppInfo.plist" "$APP/Contents/Info.plist"

codesign \
    --force \
    --sign - \
    --entitlements "$ROOT/PhotoKitProbe.entitlements" \
    "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

echo "$APP"
