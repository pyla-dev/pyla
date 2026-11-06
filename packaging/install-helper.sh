#!/bin/sh
# Installa l'helper privilegiato di PYLA e la sua policy polkit.
# Uso (dalla radice del repo, dopo `cargo build --release -p pyla-helper`):
#   sudo packaging/install-helper.sh
#   sudo packaging/install-helper.sh --uninstall
set -eu

HELPER_DIR=/usr/local/libexec/pyla
POLICY=/usr/share/polkit-1/actions/space.pyla.app.policy
HERE=$(cd "$(dirname "$0")" && pwd)
BIN="$HERE/../target/release/pyla-helper"

if [ "$(id -u)" -ne 0 ]; then
    echo "va eseguito con sudo" >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$HELPER_DIR/pyla-helper" "$POLICY"
    rmdir "$HELPER_DIR" 2>/dev/null || true
    echo "helper e policy rimossi (backup in /var/lib/pyla lasciati al loro posto)"
    exit 0
fi

[ -x "$BIN" ] || { echo "manca $BIN: esegui prima cargo build --release -p pyla-helper" >&2; exit 1; }

install -d -o root -g root -m 0755 "$HELPER_DIR"
install -o root -g root -m 0755 "$BIN" "$HELPER_DIR/pyla-helper"
install -o root -g root -m 0644 "$HERE/space.pyla.app.policy" "$POLICY"
install -d -o root -g root -m 0700 /var/lib/pyla /var/lib/pyla/backups

echo "installato: $HELPER_DIR/pyla-helper"
echo "policy:     $POLICY"
echo "prova:      pkexec $HELPER_DIR/pyla-helper status"
