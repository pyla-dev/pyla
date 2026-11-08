#!/bin/sh
# Pubblica l'albero di lavoro di PYLA sul repository pubblico pyla-dev/pyla.
# La storia locale NON viene mai spinta: il repository pubblico riceve un commit
# nuovo figlio del suo ultimo commit, con il contenuto dell'albero corrente.
#
# Attenzione: le due storie sono INTENZIONALMENTE scollegate (il pubblico e' stato
# ricostruito il 2026-11-08 in 2 commit firmati "PYLA Project" per esporre solo il
# progetto). Quindi NON fare `git pull github main` su un branch locale: unirebbe
# due storie senza antenato comune. Per pubblicare si usa sempre questo script.
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

# Lo script pubblica l'ALBERO DI LAVORO corrente, qualunque ramo sia controllato:
# pubblicare un ramo di lavoro esporrebbe codice incompleto. Su ramo diverso da
# main serve una scelta esplicita (BRANCH_OK=1).
CUR=$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)
if [ "$CUR" != "main" ] && [ "${BRANCH_OK:-0}" != 1 ]; then
    echo "ramo controllato: $CUR (non main): verrebbe pubblicato il lavoro in corso." >&2
    echo "ripeti con BRANCH_OK=1 se e' voluto." >&2
    exit 1
fi
git -C "$ROOT" fetch "$REMOTE" "$BRANCH"
rm -rf "$WORK"
git -C "$ROOT" worktree add -f "$WORK" FETCH_HEAD >/dev/null 2>&1

rsync -a --delete --exclude=.git --exclude=target --exclude=.idea "$ROOT/" "$WORK/"
# La landing page vive nel repository pyla-dev/pyla.space (pyla.space): il repository
# di codice non deve contenere gli artefatti del sito (CNAME, pagine HTML di root).
# docs/ invece RESTA: contiene gli ADR, che appartengono al codice (il README li cita).
rm -f "$WORK/CNAME" "$WORK/index.html" "$WORK/privacy.html"
rm -rf "$WORK/assets"

# identita' del repository pubblico: il progetto, non una persona (evita di
# esporre l'email di lavoro dell'autore dei commit locali)
git -C "$WORK" config user.name "PYLA Project"
git -C "$WORK" config user.email "maintainers@pyla.space"

# Gate di sanitizzazione: il repository pubblico deve essere pubblico anche se
# l'archivio privato (GitLab) non lo e'. Fail-closed: senza check superato non si
# committa e non si pusha. Con SKIP_CHECK=1 si salta solo la storia, mai l'albero.
if [ "${SKIP_CHECK:-0}" != 1 ]; then
    echo "== gate di sanitizzazione: contenuto dell'albero che verra' pubblicato"
    "$ROOT/packaging/check-public.sh" --content-only
    echo "== gate di sanitizzazione: autori della storia gia' pubblica"
    # La storia locale NON viene pubblicata (il commit nuovo e' firmato "PYLA
    # Project"), quindi qui si controlla cio' che e' gia' visibile su GitHub.
    "$ROOT/packaging/check-public.sh" --authors-only --refs FETCH_HEAD || {
        echo "NOTA: gli autori dei commit gia' pubblici non sono rimuovibili senza" >&2
        echo "riscrivere la storia (force-push). Valuta tu se accettarli: per saltare" >&2
        echo "il gate usa SKIP_CHECK=1, ma solo dopo averli letti." >&2
        exit 1; }
fi

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

# Messaggio: generico e sovrascrivibile (PYLA_SNAPSHOT_MESSAGE). Il messaggio
# fisso della v0.2 citava contenuti che cambiano release per release.
MSG=${PYLA_SNAPSHOT_MESSAGE:-"Snapshot from $SRC: PYLA (working tree contents, history not included)"}
git -C "$WORK" commit -q --author="PYLA Project <maintainers@pyla.space>" -m "$MSG"
git -C "$WORK" push "$REMOTE" "HEAD:$BRANCH"
git -C "$ROOT" worktree remove --force "$WORK"
echo "pubblicato: $REMOTE#$BRANCH (contenuto di $SRC)"
