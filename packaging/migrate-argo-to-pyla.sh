#!/bin/sh
# Migra l'installazione di Argo a PYLA: helper, policy polkit, stato delle
# mitigazioni, backup e dati utente. Da eseguire DOPO `cargo build --release -p
# pyla-helper` e prima di avviare la prima copia di PYLA.
#   sudo packaging/migrate-argo-to-pyla.sh <vecchio-id> --dry-run  (mostra soltanto)
#   sudo packaging/migrate-argo-to-pyla.sh <vecchio-id>            (applica)
# <vecchio-id>: ls /usr/share/polkit-1/actions | grep -i argo  (senza .policy)
set -eu

# OLD_ID: identificatore legacy presente sulla macchina (varia da installazione a
# installazione). Va passato come argomento, perche' non e' un identificatore del
# progetto: NEW_ID invece e' fisso.
DRY=0
OLD_ID=""
for a in "$@"; do
    case "$a" in
        --dry-run) DRY=1 ;;
        -*) echo "opzione sconosciuta: $a" >&2; exit 2 ;;
        *) [ -z "$OLD_ID" ] || { echo "un solo identificatore ammesso" >&2; exit 2; }
           OLD_ID="$a" ;;
    esac
done
NEW_ID=space.pyla.app
NEW_HELPER_DIR=/usr/local/libexec/pyla
POLKIT_DIR=/usr/share/polkit-1/actions
OLD_HELPER_DIR=/usr/local/libexec/${OLD_ID##*.}
HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN="$HERE/target/release/pyla-helper"
if [ -z "$OLD_ID" ]; then
    echo "uso: sudo $0 <vecchio-identificatore-polkit> [--dry-run]" >&2
    echo "     es. sudo $0 <id-trovato-con: ls /usr/share/polkit-1/actions | grep -i argo> --dry-run" >&2
    exit 1
fi

case "$OLD_ID" in
    *[!A-Za-z0-9._-]*|*..*|.*) echo "identificatore non valido: $OLD_ID" >&2; exit 2 ;;
esac
POLKIT_DIR_CHECK=/usr/share/polkit-1/actions
if [ ! -f "$POLKIT_DIR_CHECK/$OLD_ID.policy" ]; then
    echo "non trovo $POLKIT_DIR_CHECK/$OLD_ID.policy: identificatore sbagliato?" >&2
    exit 2
fi
if [ "$OLD_HELPER_DIR" = /usr/local/libexec/ ] || [ "$OLD_HELPER_DIR" = /usr/local/libexec/pyla ]; then
    echo "cartella helper legacy non valida: $OLD_HELPER_DIR" >&2; exit 2
fi

if [ "$(id -u)" -ne 0 ]; then echo "serve sudo" >&2; exit 1; fi
USER=$(id -un "$SUDO_USER" 2>/dev/null || echo "")
HOME_DIR=$(getent passwd "$USER" 2>/dev/null | cut -d: -f6)

run() {
    if [ "$DRY" = 1 ]; then echo "  [dry] $*"; else "$@"; fi
}

if pgrep -u "${USER:-root}" -f "target/release/(argo|pyla)( |$)" >/dev/null 2>&1; then
    echo "chiudi l'app prima di migrare" >&2; exit 1
fi

echo "== 1. helper e policy polkit"
if [ ! -x "$BIN" ]; then
    echo "manca $BIN: esegui cargo build --release -p pyla-helper" >&2; exit 1
fi
run install -d -o root -g root -m 0755 "$NEW_HELPER_DIR"
run install -o root -g root -m 0755 "$BIN" "$NEW_HELPER_DIR/pyla-helper"
run install -o root -g root -m 0644 "$HERE/packaging/$NEW_ID.policy" "$POLKIT_DIR/$NEW_ID.policy"
run rm -f "$POLKIT_DIR/$OLD_ID.policy"
run rm -rf "$OLD_HELPER_DIR"

echo "== 2. stato delle mitigazioni (marcatore # argo: -> # pyla:)"
for pair in "etc/sysctl.d/90-argo-mitigations.conf etc/sysctl.d/90-pyla-mitigations.conf" \
            "etc/modprobe.d/argo-mitigations.conf etc/modprobe.d/pyla-mitigations.conf"; do
    old=/${pair%% *}
    new=/${pair#* }
    [ -f "$old" ] || continue
    if [ "$DRY" = 1 ]; then
        echo "  [dry] $old -> $new (righe '# argo:' riscritte)"
    else
        sed 's/^# argo:/# pyla:/; s/^# Gestito da Argo/# Gestito da PYLA/' "$old" > "$new"
        rm -f "$old"
        echo "  migrato $new"
    fi
done

echo "== 3. dir dei backup delle regole"
if [ -d /var/lib/argo ] && [ -e /var/lib/pyla ]; then
    echo "  esiste gia' /var/lib/pyla: lascio /var/lib/argo al suo posto (confronta a mano)"
elif [ -d /var/lib/argo ]; then
    run mv /var/lib/argo /var/lib/pyla
    run install -d -o root -g root -m 0700 /var/lib/pyla /var/lib/pyla/backups
fi

echo "== 4. dati utente (regole, storico, cache CVE)"
if [ -n "$USER" ] && [ -n "$HOME_DIR" ]; then
    for base in .local/share .config .cache; do
        old="$HOME_DIR/$base/$OLD_ID"
        new="$HOME_DIR/$base/$NEW_ID"
        [ -d "$old" ] || continue
        if [ -d "$new" ]; then
            # se la dir nuova esiste ma non ha ancora un db con dati, la dati vecchi
            # hanno piu' valore: sposta comunque i file argo.* (regole, storico, cache CVE).
            if [ ! -s "$new/pyla.db" ] && [ -s "$old/argo.db" ]; then
                if [ "$DRY" = 1 ]; then
                    echo "  [dry] $new esiste ma e' vuota: i dati di $old/argo.db* la sostituiscono"
                else
                    mv "$new" "$new.smoketest-$(date +%s)"
                    mv "$old" "$new"
                    echo "  $new era vuota: usati i dati reali di $old"
                fi
            else
                echo "  esiste gia' $new con dati: lascio $old al suo posto (confronta a mano)"
            fi
        else
            run mv "$old" "$new"
            [ "$DRY" = 1 ] || echo "  spostato $new"
        fi
        if [ "$DRY" = 0 ]; then
            for ext in db db-wal db-shm; do
                [ -f "$new/argo.$ext" ] && mv "$new/argo.$ext" "$new/pyla.$ext" && echo "  $new/argo.$ext -> pyla.$ext"
            done
        fi
    done
    if [ -f "$HOME_DIR/.local/share/applications/$OLD_ID.desktop" ]; then
        run rm -f "$HOME_DIR/.local/share/applications/$OLD_ID.desktop" \
                 "$HOME_DIR/.local/share/icons/hicolor/scalable/apps/$OLD_ID.svg"
        run update-desktop-database "$HOME_DIR/.local/share/applications"
    fi
fi

echo
if [ "$DRY" = 1 ]; then
    echo "dry-run: nessuna modifica applicata. Riesegui senza --dry-run per applicare."
else
    echo "migrazione completata. Verifica:"
    echo "  ls -l $NEW_HELPER_DIR  &&  ls $POLKIT_DIR | grep pyla"
    echo "  ls ~/.local/share/$NEW_ID/          # deve contenere pyla.db"
    echo "  pkexec $NEW_HELPER_DIR/pyla-helper status"
    echo "Poi reinstalla il desktop file: packaging/install-desktop.sh"
fi
