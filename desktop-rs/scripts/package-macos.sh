#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT_DIR="$(cd "${PROJECT_DIR}/.." && pwd)"

UNIVERSAL=0
VERSION=""
for arg in "$@"; do
  if [[ "${arg}" == "--universal" ]]; then
    UNIVERSAL=1
  else
    VERSION="${arg#v}"
  fi
done
if [[ -z "${VERSION}" ]]; then
  VERSION="$(awk -F'=' '/^version[[:space:]]*=/{gsub(/["[:space:]]/, "", $2); print $2; exit}' "${PROJECT_DIR}/Cargo.toml")"
  VERSION="${VERSION:-0.4.6}"
fi
export MACOSX_DEPLOYMENT_TARGET=11.0

DIST_DIR="${ROOT_DIR}/dist"
mkdir -p "${DIST_DIR}"

if [[ "${UNIVERSAL}" -eq 1 ]]; then
  echo "==> Building tachyon-desktop for Apple Silicon (aarch64-apple-darwin)..."
  cargo build --release --target aarch64-apple-darwin --manifest-path "${PROJECT_DIR}/Cargo.toml"
  echo "==> Building tachyon-desktop for Intel (x86_64-apple-darwin)..."
  cargo build --release --target x86_64-apple-darwin --manifest-path "${PROJECT_DIR}/Cargo.toml"
  BIN_PATH="${DIST_DIR}/tachyon-desktop-macos-universal"
  lipo -create \
    "${PROJECT_DIR}/target/aarch64-apple-darwin/release/tachyon" \
    "${PROJECT_DIR}/target/x86_64-apple-darwin/release/tachyon" \
    -output "${BIN_PATH}"
  chmod 0755 "${BIN_PATH}"
else
  BIN_PATH="${PROJECT_DIR}/target/release/tachyon"
  if [[ ! -f "${BIN_PATH}" ]]; then
    echo "==> Building tachyon-desktop (release)..."
    cargo build --release --manifest-path "${PROJECT_DIR}/Cargo.toml"
  fi
  cp "${BIN_PATH}" "${DIST_DIR}/tachyon-desktop-macos-universal"
  chmod 0755 "${DIST_DIR}/tachyon-desktop-macos-universal"
fi
APP_BUNDLE="${DIST_DIR}/Tachyon.app"
rm -rf "${APP_BUNDLE}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

cp "${BIN_PATH}" "${APP_BUNDLE}/Contents/MacOS/tachyon"
chmod 0755 "${APP_BUNDLE}/Contents/MacOS/tachyon"

ICON_SRC_PNG="${PROJECT_DIR}/assets/AppIcon.png"
if [[ ! -s "${ICON_SRC_PNG}" ]] && [[ -f "${ROOT_DIR}/src/app.ico" ]] && command -v python3 >/dev/null 2>&1; then
  mkdir -p "$(dirname "${ICON_SRC_PNG}")"
  python3 - "${ROOT_DIR}/src/app.ico" "${ICON_SRC_PNG}" << 'PYEOF'
import struct, sys
data = open(sys.argv[1], "rb").read()
cnt = struct.unpack("<HHH", data[:6])[2]
sz, off = max(struct.unpack("<II", data[6+i*16+8:6+i*16+16]) for i in range(cnt))
chunk = data[off:off+sz]
assert chunk[:8] == b"\x89PNG\r\n\x1a\n", "app.ico largest entry is not PNG"
open(sys.argv[2], "wb").write(chunk)
PYEOF
fi
if [[ -s "${ICON_SRC_PNG}" ]] && command -v sips >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
  ICONSET_DIR="${DIST_DIR}/AppIcon.iconset"
  rm -rf "${ICONSET_DIR}"
  mkdir -p "${ICONSET_DIR}"
  for sz in 16 32 128 256 512; do
    sips -s format png -z "${sz}" "${sz}" "${ICON_SRC_PNG}" --out "${ICONSET_DIR}/icon_${sz}x${sz}.png" >/dev/null
    sz2=$((sz * 2))
    sips -s format png -z "${sz2}" "${sz2}" "${ICON_SRC_PNG}" --out "${ICONSET_DIR}/icon_${sz}x${sz}@2x.png" >/dev/null
  done
  iconutil -c icns "${ICONSET_DIR}" -o "${APP_BUNDLE}/Contents/Resources/AppIcon.icns"
  test -s "${APP_BUNDLE}/Contents/Resources/AppIcon.icns"
  rm -rf "${ICONSET_DIR}"
else
  echo "ERROR: failed to build AppIcon.icns (missing AppIcon.png, sips, or iconutil)" >&2
  exit 1
fi

cat > "${APP_BUNDLE}/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>Tachyon</string>
    <key>CFBundleExecutable</key>
    <string>tachyon</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon.icns</string>
    <key>CFBundleIconName</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>io.tachyon.desktop</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Tachyon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleURLTypes</key>
    <array>
      <dict>
        <key>CFBundleURLName</key>
        <string>Tachyon Protocol</string>
        <key>CFBundleURLSchemes</key>
        <array>
          <string>tachyon</string>
        </array>
      </dict>
    </array>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

# Ad-hoc sign the bundle so macOS Gatekeeper allows local execution cleanly
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "${APP_BUNDLE}"
fi

DMG_STAGE="${DIST_DIR}/dmg-stage"
rm -rf "${DMG_STAGE}"
mkdir -p "${DMG_STAGE}"
cp -R "${APP_BUNDLE}" "${DMG_STAGE}/"
ln -s /Applications "${DMG_STAGE}/Applications"

DMG_OUT="${DIST_DIR}/Tachyon-${VERSION}-macOS.dmg"
rm -f "${DMG_OUT}"
if command -v hdiutil >/dev/null 2>&1; then
  hdiutil create -volname "Tachyon" -srcfolder "${DMG_STAGE}" -ov -format UDZO "${DMG_OUT}"
  echo "==> Created macOS DMG: ${DMG_OUT}"
fi
