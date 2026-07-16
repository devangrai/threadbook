#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HEADER_DIR="$ROOT/Sources/WardrobePhotoKitObjC/include"

xcrun clang \
  -std=c11 \
  -Wall \
  -Wextra \
  -Werror \
  -fblocks \
  -I "$HEADER_DIR" \
  -fsyntax-only \
  "$ROOT/Tests/CABIHeaderTests.c"

swift test --disable-sandbox --package-path "$ROOT"
swift build \
  --disable-sandbox \
  --package-path "$ROOT" \
  --product WardrobePhotoKit
swift build \
  --disable-sandbox \
  --package-path "$ROOT" \
  --product WardrobePhotoKitLiveSmoke

BIN_PATH="$(swift build \
  --disable-sandbox \
  --package-path "$ROOT" \
  --show-bin-path)"
ARCHIVE="$BIN_PATH/libWardrobePhotoKit.a"
test -f "$ARCHIVE"

SYMBOLS="$(nm -gj "$ARCHIVE")"
for symbol in \
  _wk_photokit_create_v1 \
  _wk_photokit_send_v1 \
  _wk_photokit_next_v1 \
  _wk_photokit_frame_free_v1 \
  _wk_photokit_quiesce_v1 \
  _wk_photokit_destroy_v1 \
  _wk_photokit_validate_image_fd_v1 \
  _wk_detect_people_rgb_v1
do
  grep -qx "$symbol" <<<"$SYMBOLS"
done
UNDEFINED_SYMBOLS="$(nm -u "$ARCHIVE")"
grep -q '_OBJC_CLASS_\$_VNDetectHumanRectanglesRequest' \
  <<<"$UNDEFINED_SYMBOLS"

SWIFTC="$(xcrun --find swiftc)"
TOOLCHAIN="$(cd "$(dirname "$SWIFTC")/.." && pwd)"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
RUST_SMOKE="$(mktemp "${TMPDIR:-/tmp}/wk-photokit-rust.XXXXXX")"
trap 'rm -f "$RUST_SMOKE"' EXIT

MACOSX_DEPLOYMENT_TARGET=15.0 rustc \
  --edition=2021 \
  "$ROOT/Tests/RustLinkSmoke.rs" \
  -L "native=$BIN_PATH" \
  -L "native=$TOOLCHAIN/lib/swift/macosx" \
  -L "native=$SDK/usr/lib/swift" \
  -l static=WardrobePhotoKit \
  -l framework=AppKit \
  -l framework=Foundation \
  -l framework=ImageIO \
  -l framework=Photos \
  -l framework=PhotosUI \
  -l framework=UniformTypeIdentifiers \
  -l framework=Vision \
  -C link-arg=-Wl,-rpath,/usr/lib/swift \
  -o "$RUST_SMOKE"
"$RUST_SMOKE"
