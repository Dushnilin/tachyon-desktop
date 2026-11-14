#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT_DIR="$(cd "${PROJECT_DIR}/.." && pwd)"

VERSION="${1:-0.3.8}"
ARCH_RAW="$(uname -m)"
case "${ARCH_RAW}" in
  x86_64|amd64) DEB_ARCH="amd64" ;;
  aarch64|arm64) DEB_ARCH="arm64" ;;
  *) DEB_ARCH="${ARCH_RAW}" ;;
esac

BIN_PATH="${PROJECT_DIR}/target/release/tachyon"
if [[ ! -f "${BIN_PATH}" ]]; then
  echo "==> Building tachyon-desktop (release)..."
  cargo build --release --manifest-path "${PROJECT_DIR}/Cargo.toml"
fi

DIST_DIR="${ROOT_DIR}/dist"
STAGE_DEB="${DIST_DIR}/deb-stage"
rm -rf "${STAGE_DEB}"
mkdir -p "${STAGE_DEB}/DEBIAN"
mkdir -p "${STAGE_DEB}/usr/bin"
mkdir -p "${STAGE_DEB}/usr/share/applications"
mkdir -p "${STAGE_DEB}/usr/share/icons/hicolor/scalable/apps"

cp "${BIN_PATH}" "${DIST_DIR}/tachyon-desktop-linux-${DEB_ARCH}"
chmod 0755 "${DIST_DIR}/tachyon-desktop-linux-${DEB_ARCH}"
cp "${BIN_PATH}" "${STAGE_DEB}/usr/bin/tachyon"
chmod 0755 "${STAGE_DEB}/usr/bin/tachyon"

cat > "${STAGE_DEB}/usr/share/applications/tachyon.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=Tachyon VPN
GenericName=VPN & Routing Client
Comment=Нативный клиент маршрутизации и туннелирования Tachyon (Desync)
Exec=/usr/bin/tachyon
Icon=tachyon
Terminal=false
Categories=Network;Security;VPN;
StartupWMClass=tachyon
EOF

cat > "${STAGE_DEB}/usr/share/icons/hicolor/scalable/apps/tachyon.svg" << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#17152b"/>
      <stop offset="100%" stop-color="#0b0b0f"/>
    </linearGradient>
    <linearGradient id="bolt" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#c4b5fd"/>
      <stop offset="100%" stop-color="#7c5cff"/>
    </linearGradient>
  </defs>
  <rect width="256" height="256" rx="56" fill="url(#bg)"/>
  <path d="M146 36L68 140h54l-12 80 78-104h-54L146 36z" fill="url(#bolt)"/>
</svg>
EOF

cat > "${STAGE_DEB}/DEBIAN/control" << EOF
Package: tachyon
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Depends: libxkbcommon0, libxkbcommon-x11-0, libxcb1, libvulkan1 | mesa-vulkan-drivers, libcap2-bin, policykit-1
Maintainer: Dushnilin <https://github.com/Dushnilin>
Description: Tachyon Routing & Tunneling Client (tachyon-core embedded)
 Нативный кроссплатформенный клиент Tachyon со встроенным движком tachyon-core,
 адаптивной десинхронизацией пакетов (Desync AdaptiveBrain) и маршрутизацией tachyon-lists.
EOF

cat > "${STAGE_DEB}/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e
if command -v setcap >/dev/null 2>&1 && [ -f /usr/bin/tachyon ]; then
    setcap cap_net_admin,cap_net_raw+eip /usr/bin/tachyon || true
fi
exit 0
EOF
chmod 0755 "${STAGE_DEB}/DEBIAN/postinst"

DEB_OUT="${DIST_DIR}/tachyon_${VERSION}_${DEB_ARCH}.deb"
dpkg-deb --build --root-owner-group "${STAGE_DEB}" "${DEB_OUT}"
echo "==> Created Debian package: ${DEB_OUT}"

# Also create portable .tar.gz with install.sh for Arch / Fedora / other distros
STAGE_TAR="${DIST_DIR}/tachyon-linux-${DEB_ARCH}"
rm -rf "${STAGE_TAR}"
mkdir -p "${STAGE_TAR}"
cp "${BIN_PATH}" "${STAGE_TAR}/tachyon"
cp "${STAGE_DEB}/usr/share/applications/tachyon.desktop" "${STAGE_TAR}/"
cp "${STAGE_DEB}/usr/share/icons/hicolor/scalable/apps/tachyon.svg" "${STAGE_TAR}/"

cat > "${STAGE_TAR}/install.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sudo install -Dm755 "${DIR}/tachyon" /usr/bin/tachyon
sudo install -Dm644 "${DIR}/tachyon.desktop" /usr/share/applications/tachyon.desktop
sudo install -Dm644 "${DIR}/tachyon.svg" /usr/share/icons/hicolor/scalable/apps/tachyon.svg
if command -v setcap >/dev/null 2>&1; then
  sudo setcap cap_net_admin,cap_net_raw+eip /usr/bin/tachyon || true
fi
echo "Tachyon установлен в /usr/bin/tachyon (с правами CAP_NET_ADMIN для TUN и Desync)!"
EOF
chmod 0755 "${STAGE_TAR}/install.sh"

TAR_OUT="${DIST_DIR}/tachyon-linux-${DEB_ARCH}.tar.gz"
tar -C "${DIST_DIR}" -czf "${TAR_OUT}" "tachyon-linux-${DEB_ARCH}"
echo "==> Created portable tarball: ${TAR_OUT}"
