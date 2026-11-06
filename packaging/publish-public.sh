#!/bin/sh
# Pubblica l'albero di lavoro di Pyla sul repository pubblico pyla-dev/pyla.
# La storia locale NON viene mai spinta: il repository pubblico riceve un commit
# nuovo figlio del suo ultimo commit, con il contenuto dell'albero corrente.
#   packaging/publish-public.sh            (pubblica)
#   packaging/publish-public.sh --dry-run  (mostra cosa cambierebbe)
set -eu

REMOTE=${PYLA_PUBLIC_REMOTE:-https://github.com/pyla-dev/pyla.git}
BRANCH=${PYLA_PUBLIC_BRANCH:-main}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=${PYLA_PUBLIC_WORKTREE:-/tmp/pyla-public-publish}
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

SRC=$(git -C "$ROOT" rev-parse --short HEAD)
git -C "$ROOT" fetch "$REMOTE" "$BRANCH"
rm -rf "$WORK"
git -C "$ROOT" worktree add -f "$WORK" FETCH_HEAD >/dev/null 2>&1

rsync -a --delete --exclude=.git --exclude=target --exclude=.idea "$ROOT/" "$WORK/"
# la landing page vive nel repository pyla-dev/pyla.space (pyla.space): il
# repository di codice non deve contenere ne' CNAME ne' la documentazione del sito
rm -f "$WORK/CNAME"
rm -rf "$WORK/docs"

git -C "$WORK" add -A
if git -C "$WORK" diff --cached --quiet; then
    echo "nessuna differenza rispetto a $REMOTE#$BRANCH"
    git -C "$ROOT" worktree remove --force "$WORK"
    exit 0
fi
echo "== diff verso il repository pubblico:"
git -C "$WORK" diff --cached --stat | tail -5
git -C "$WORK" diff --cached --name-status | grep -E "^(A|D)" | head -20

if [ "$DRY" = 1 ]; then
    echo "[dry-run] nessun commit, nessun push"
    exit 0
fi

git -C "$WORK" commit -q -m "Snapshot da $SRC: Pyla (crate pyla-core/pyla-helper, helper polkit space.pyla.app, exposure per famiglia)"
git -C "$WORK" push "$REMOTE" "HEAD:$BRANCH"
git -C "$ROOT" worktree remove --force "$WORK"
echo "pubblicato: $REMOTE#$BRANCH (contenuto di $SRC)"
