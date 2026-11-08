#!/bin/sh
# Allinea l'archivio privato (self-hosted, raggiungibile solo dalla rete privata)
# ai commit presenti su disco. Il repository pubblico (github.com/pyla-dev/pyla)
# NON viene toccato: riceve snapshot senza storia tramite publish-public.sh.
#
# Uso (dalla radice del repo):
#   packaging/sync-private.sh              # push di main + tag
#   packaging/sync-private.sh --dry-run    # mostra senza spingere
#
# Perche' esiste: la storia reale (refactor, rinomine, commit con l'autore
# locale) vive SOLO qui. Se il disco va, l'unica copia e' il bundle dei backup:
# questo script rende l'allineamento un comando ripetibile, non un'intenzione.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
REMOTE=${PYLA_PRIVATE_REMOTE:-origin}
DRY=""
[ "${1:-}" = "--dry-run" ] && DRY="--dry-run"

# il remote deve portare le credenziali: GCM con provider generic non ne ha di
# valide in contesto non interattivo (nessuna voce in secretservice) e pkexec/
# prompt in shell non funzionano. Formato usato anche dagli altri repo GitLab.
URL=$(git remote get-url "$REMOTE")
case "$URL" in
    *://*:*@*) : ;;
    *) echo "ATTENZIONE: $REMOTE non ha credenziali nell'URL ($URL)." >&2
       echo "i push non interattivi falliscono con 'could not read Username'." >&2
       echo "usa: git remote set-url $REMOTE http://<user>:<pass>@<host>/<group>/<repo>.git" >&2
       exit 1 ;;
esac

CUR=$(git rev-parse --abbrev-ref HEAD)
if [ "$CUR" != "main" ]; then
    echo "ramo corrente: $CUR. L'archivio si allinea da main." >&2
    echo "(per forzare: BRANCH_OK=1 $0)" >&2
    [ "${BRANCH_OK:-0}" = 1 ] || exit 1
fi

git fetch "$REMOTE" main --quiet || true
echo "== stato: locale vs $REMOTE"
git rev-list --left-right --count "$REMOTE/main"...main 2>/dev/null \
    | awk '{print "  solo sul remoto: " $1 " | solo su disco: " $2}'
echo "== contenuto diverso (vuoto = allineato)"
git diff --stat "$REMOTE/main" main | tail -3

echo "== push $REMOTE main $DRY"
git push $DRY "$REMOTE" main

# --tags (non --follow-tags): allinea anche i tag che non sono antenati del
# branch, come v0.2.0/v0.2.1 quando il branch controllato e' feat/*.
echo "== push tag $DRY"
git push $DRY --tags "$REMOTE"

[ -n "$DRY" ] && { echo "[dry-run] niente push"; exit 0; }
echo "allineato: $REMOTE/main = $(git rev-parse --short main), tag: $(git tag -l | tr '\n' ' ')"
