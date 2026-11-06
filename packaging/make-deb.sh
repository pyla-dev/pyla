#!/bin/sh
# Costruisce il pacchetto .deb di Pyla: app + helper privilegiato + policy polkit
# + desktop file e icone, poi genera gli hash sha256/sha512 del pacchetto.
# Uso (dalla radice del repo): packaging/make-deb.sh
# Richiede: cargo, dpkg-deb. Output in target/dist/.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ID=space.pyla.app
ARCH=amd64
OUT="$ROOT/target/dist"

VERSION=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$ROOT/src-tauri/tauri.conf.json" | head -1)
[ -n "$VERSION" ] || { echo "versione non trovata in tauri.conf.json" >&2; exit 1; }

# Build da una copia pulita fuori dalla home: l'identificatore ACL generato da
# Tauri incorpora il percorso del progetto e --remap-path-prefix non lo tocca.
# --remap-path-prefix copre il resto (codice, registry, stdlib nei panic).
BUILD_ROOT=${MAKE_DEB_BUILD_DIR:-/tmp/opencode/pyla-deb-build}
rsync -a --delete --exclude=target --exclude=.git --exclude=.github "$ROOT/" "$BUILD_ROOT/"
RUSTFLAGS="--remap-path-prefix=$BUILD_ROOT=/build/pyla --remap-path-prefix=$HOME=/build/home" \
    cargo build --release --manifest-path "$BUILD_ROOT/Cargo.toml"
BIN="$BUILD_ROOT/target/release/pyla"
HELPER="$BUILD_ROOT/target/release/pyla-helper"
[ -x "$BIN" ] && [ -x "$HELPER" ] || { echo "binari mancanti in target/release" >&2; exit 1; }

PKG="pyla_${VERSION}_${ARCH}"
STAGE="$OUT/$PKG"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN"

install -Dm0755 "$BIN" "$STAGE/usr/bin/pyla"
# stesso path di packaging/install-helper.sh (HELPER_PATH in pyla-core): il .deb lo possiede
install -Dm0755 "$HELPER" "$STAGE/usr/local/libexec/pyla/pyla-helper"
install -Dm0644 "$ROOT/packaging/$ID.policy" "$STAGE/usr/share/polkit-1/actions/$ID.policy"

mkdir -p "$STAGE/usr/share/applications"
cat > "$STAGE/usr/share/applications/$ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Pyla
GenericName=Firewall
Comment=Graphical manager for the UFW firewall
Exec=/usr/bin/pyla
Icon=$ID
Terminal=false
Categories=System;Security;
Keywords=firewall;ufw;rules;network;security;
StartupNotify=true
StartupWMClass=pyla
EOF

install -Dm0644 "$ROOT/ui/icon.svg" "$STAGE/usr/share/icons/hicolor/scalable/apps/$ID.svg"
install -Dm0644 "$ROOT/src-tauri/icons/32x32.png" "$STAGE/usr/share/icons/hicolor/32x32/apps/$ID.png"
install -Dm0644 "$ROOT/src-tauri/icons/128x128.png" "$STAGE/usr/share/icons/hicolor/128x128/apps/$ID.png"
install -Dm0644 "$ROOT/src-tauri/icons/128x128@2x.png" "$STAGE/usr/share/icons/hicolor/256x256/apps/$ID.png"
install -Dm0644 "$ROOT/src-tauri/icons/icon.png" "$STAGE/usr/share/icons/hicolor/512x512/apps/$ID.png"

SIZE=$(du -sk "$STAGE" --exclude=DEBIAN | cut -f1)
cat > "$STAGE/DEBIAN/control" <<EOF
Package: pyla
Version: $VERSION
Architecture: $ARCH
Maintainer: PYLA Project <maintainers@pyla.space>
Installed-Size: $SIZE
Depends: libwebkit2gtk-4.1-0, polkitd, ufw
Section: utils
Priority: optional
Homepage: https://pyla.space
Description: Graphical manager for the UFW firewall
 Rule sets with preview, apply and automatic rollback, live UFW status,
 a read-only nftables ruleset viewer and Ubuntu kernel CVE tracking with
 one-click kernel module mitigations.
EOF

mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true
fi
# le dir dei backup dell'helper (le regole vengono copiate qui prima di ogni apply)
install -d -o root -g root -m 0700 /var/lib/pyla /var/lib/pyla/backups
EOF
cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
EOF
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"

( cd "$STAGE" && find . -type f ! -path './DEBIAN/*' -exec md5sum {} + | sed 's|^\(\S*\)  \./|\1  |' | sort -k2 > DEBIAN/md5sums )

mkdir -p "$OUT"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT/$PKG.deb" >/dev/null
( cd "$OUT" && sha256sum "$PKG.deb" > "$PKG.deb.sha256" && sha512sum "$PKG.deb" > "$PKG.deb.sha512" )

echo "pacchetto: $OUT/$PKG.deb"
echo "hash:      $OUT/$PKG.deb.sha256"
cat "$OUT/$PKG.deb.sha256"
