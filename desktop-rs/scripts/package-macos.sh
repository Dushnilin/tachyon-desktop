#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT_DIR="$(cd "${PROJECT_DIR}/.." && pwd)"

UNIVERSAL=0
VERSION="0.3.7"
for arg in "$@"; do
  if [[ "${arg}" == "--universal" ]]; then
    UNIVERSAL=1
  else
    VERSION="${arg#v}"
  fi
done

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

cat > "${APP_BUNDLE}/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>Tachyon</string>
    <key>CFBundleExecutable</key>
    <string>tachyon</string>
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
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

# Ad-hoc sign the bundle so macOS Gatekeeper allows local execution cleanly
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "${APP_BUNDLE}" || true
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
