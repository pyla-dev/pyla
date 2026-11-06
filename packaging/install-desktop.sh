#!/bin/sh
# Mette Pyla tra le applicazioni di GNOME per l'utente corrente (non serve sudo).
# Usa il binario release del repo: compilalo prima con `cargo tauri build --no-bundle`.
#   packaging/install-desktop.sh
#   packaging/install-desktop.sh --uninstall
set -eu

ID=space.pyla.app
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/target/release/pyla"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$APPS/$ID.desktop" "$ICONS/scalable/apps/$ID.svg"
    update-desktop-database "$APPS" 2>/dev/null || true
    gtk-update-icon-cache -q -t "$ICONS" 2>/dev/null || true
    echo "rimosso"
    exit 0
fi

[ -x "$BIN" ] || { echo "manca $BIN: esegui prima cargo tauri build --no-bundle" >&2; exit 1; }

install -Dm0644 "$ROOT/ui/icon.svg" "$ICONS/scalable/apps/$ID.svg"
install -d "$APPS"
cat > "$APPS/$ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Pyla
GenericName=Firewall
Comment=Gestione grafica del firewall UFW con set di regole
Exec=$BIN
Icon=$ID
Terminal=false
Categories=System;Security;
Keywords=firewall;ufw;regole;rete;sicurezza;
StartupNotify=true
StartupWMClass=pyla
EOF
desktop-file-validate "$APPS/$ID.desktop" 2>/dev/null || true
update-desktop-database "$APPS" 2>/dev/null || true
gtk-update-icon-cache -q -t "$ICONS" 2>/dev/null || true
echo "installato: $APPS/$ID.desktop"
