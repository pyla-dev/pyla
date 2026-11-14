#!/usr/bin/env bash
# I fixture di tests/fixtures/profiles sono una copia di lavoro dei profili del
# repository dei profili. Se il repository cambia e la copia no, il parser viene
# testato su file che nessun utente importa piu': questo script lo dice.
#
# Uso: packaging/check-profile-fixtures.sh [ref]     (ref default: main)
# Uscita: 0 = fixture allineati al repository, 1 = deriva o rete giu.
set -euo pipefail

REF="${1:-${PROFILES_REF:-main}}"
REPO="${PROFILES_REPO:-pyla-dev/pyla-profiles}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$HERE/tests/fixtures/profiles"

[ -d "$FIX" ] || { echo "ERRORE: cartella fixture assente: $FIX" >&2; exit 1; }

status=0
printf '%-22s %-14s %-14s %s\n' PROFILO FIXTURE REPOSITORY ESITO
for path in "$FIX"/*.jsonc; do
    name="$(basename "$path" .jsonc)"
    url="https://raw.githubusercontent.com/$REPO/$REF/profiles/$name/profile.jsonc"
    remote="$(curl -fsS -m 20 "$url" 2>/dev/null | sha256sum | cut -c1-12 || true)"
    local_sha="$(sha256sum "$path" | cut -c1-12)"
    if [ -z "$remote" ]; then
        printf '%-22s %-14s %-14s %s\n' "$name" "$local_sha" "-" "RETE GIU o profilo non trovato"
        status=1
    elif [ "$remote" = "$local_sha" ]; then
        printf '%-22s %-14s %-14s %s\n' "$name" "$local_sha" "$remote" "allineato"
    else
        printf '%-22s %-14s %-14s %s\n' "$name" "$local_sha" "$remote" "DERIVA: aggiornare il fixture"
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "OK: i fixture rispecchiano $REPO@$REF"
else
    echo "NOTA: copiare i file nuovi e rilanciare cargo test -p pyla-core" >&2
fi
exit "$status"
