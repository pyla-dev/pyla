#!/bin/sh
# Gate di sanitizzazione per il repository pubblico pyla-dev/pyla.
#
# Perche' esiste: "pubblico" non riguarda solo l'ultimo commit. Su un repository
# pubblico ogni commit e ogni blob restano consultabili per sempre, e i metadati
# degli autori non si possono togliere senza riscrivere la storia. Quindi la
# sanitizzazione va verificata, non presupposta.
#
# Uso (dalla radice del repo):
#   packaging/check-public.sh                  # albero + autori raggiungibili da HEAD
#   packaging/check-public.sh --content-only   # solo contenuto (la storia locale non
#                                              # viene pubblicata: i suoi autori non
#                                              # sono una violazione)
#   packaging/check-public.sh --authors-only   # solo metadati degli autori
#   packaging/check-public.sh --history        # contenuto di OGNI commit di HEAD
#   packaging/check-public.sh --history --refs github/main
#   packaging/check-public.sh --strict         # tratta da errore anche gli handle
#                                              # "noreply" di GitHub (pseudonimo,
#                                              # non email reale)
# Esce 1 se trova qualcosa. publish-public.sh lo invoca prima di committare.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

HISTORY=0
AUTHORS_ONLY=0
CONTENT_ONLY=0
STRICT=0
REFS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --history) HISTORY=1 ;;
        --authors-only) AUTHORS_ONLY=1 ;;
        --content-only) CONTENT_ONLY=1 ;;
        --strict) STRICT=1 ;;
        --refs) shift; REFS=${1:-} ;;
        *) echo "opzione sconosciuta: $1" >&2; exit 2 ;;
    esac
    shift
done
[ -n "$REFS" ] || REFS=$(git rev-parse --abbrev-ref HEAD)

# Identita' personali/professionali e topologia interna. "argo" NON e' in lista:
# e' il nome del progetto precedente, citato dallo script di migrazione.
# I segreti sono solo assegnazioni con valore verosimilmente opaco (>= 8 caratteri),
# altrimenti il gate scatta su frasi come "7 token = regola semplice".
# I pattern specifici (nome, dominio del datore di lavoro, hostname, host interno)
# NON stanno in questo file: questo script viene pubblicato, e pubblicare l'elenco
# delle cose da nascondere le rivelerebbe. Stanno in packaging/sanitize-patterns.local
# (gitignored), una regex per riga; il file puo' essere altrove con SANITIZE_PATTERNS.
PATTERN_LOCAL=${SANITIZE_PATTERNS:-"$(dirname "$0")/sanitize-patterns.local"}
PATTERN_GENERIC='/home/[a-z]|/Users/[a-z]|@[A-Za-z0-9.-]+\.(tv|com\.br|corp)|BEGIN [A-Z]* PRIVATE KEY|ghp_[A-Za-z0-9]{20}|glpat-[A-Za-z0-9_-]{20}|xox[baprs]-[A-Za-z0-9-]{10}|(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY)[A-Z0-9_]*[^A-Za-z0-9]{0,2}={1,2}[^A-Za-z0-9]{0,2}[A-Za-z0-9_./+=-]{8,}' # sanitize-ignore
if [ -f "$PATTERN_LOCAL" ]; then
    LOCAL_RE=$(paste -sd'|' "$PATTERN_LOCAL")
    PATTERN="$LOCAL_RE|$PATTERN_GENERIC"
    AUTH_PATTERN="$LOCAL_RE|@[A-Za-z0-9.-]+\.(tv|com\.br|corp)"
else
    # fail-visible: senza file locale il gate e' piu' debole, va detto ad alta voce
    PATTERN="$PATTERN_GENERIC"
    AUTH_PATTERN='@[A-Za-z0-9.-]+\.(tv|com\.br|corp)'
    echo "NOTA: $PATTERN_LOCAL non presente: il gate usa solo i pattern generici" >&2
    echo "(nome, dominio aziendale e hostname interni NON vengono cercati)." >&2
fi

FOUND=$(mktemp)
SORTED=$(mktemp)
trap 'rm -f "$FOUND" "$SORTED" "$FOUND.a"' EXIT

# --- 1) metadati dei commit -------------------------------------------------
if [ "$CONTENT_ONLY" != 1 ]; then
    git log --format='AUTORE %h %an <%ae> | %cn <%ce>' "$REFS" | sort -u >"$SORTED"
    # ERRORE: nome o email reali. AVVERTIMENTO: solo l'handle pubblico di GitHub
    # (<user>@users.noreply.github.com), che e' uno pseudonimo e non rivela l'email.
    grep -iE "$AUTH_PATTERN" "$SORTED" >"$FOUND.a" || true
    grep -iE "$AUTH_PATTERN" "$SORTED" | grep -viE "users\.noreply\.github\.com" >>"$FOUND" || true
    NH=$(grep -icE "users\.noreply\.github\.com" "$FOUND.a" || true)
    if [ "$NH" != 0 ]; then
        echo "NOTA: $NH commit in $REFS usano l'handle pubblico di GitHub (noreply):" >&2
        echo "e' uno pseudonimo, non un'email reale. Con --strict diventa un errore." >&2
        grep -iE "users\.noreply\.github\.com" "$FOUND.a" | sed 's/^/  /' >&2
    fi
    if [ "$STRICT" = 1 ]; then
        grep -iE "$AUTH_PATTERN" "$SORTED" >>"$FOUND" || true
        sort -u -o "$FOUND" "$FOUND"
    fi
    if [ "$AUTHORS_ONLY" = 1 ]; then
        NA=$(grep -c "" "$FOUND" || true)
        if [ "$NA" = 0 ]; then
            echo "autori puliti: nessun nome/email reale in $REFS ($(git rev-list --count "$REFS") commit)"
            exit 0
        fi
        echo "TROVATI $NA commit con autore/committer personale in $REFS:" >&2
        cat "$FOUND" >&2
        exit 1
    fi
fi

# --- 2) contenuto -----------------------------------------------------------
if [ "$HISTORY" = 1 ]; then
    for c in $(git rev-list "$REFS"); do
        git grep -InE "$PATTERN" "$c" -- . 2>/dev/null | sed 's/^[0-9a-f]*://' >>"$FOUND" || true
    done
else
    grep -rInE --exclude-dir=.git --exclude-dir=target --exclude-dir=.idea \
        --exclude=Cargo.lock --exclude=sanitize-patterns.local \
        -e "$PATTERN" . >>"$FOUND" || true
grep -v "sanitize-ignore" "$FOUND" >"$SORTED" || true
mv "$SORTED" "$FOUND"
fi

# Nessun file e' escluso dallo scan: il gate stesso deve essere pubblicabile.
# Le righe che DEVONO contenere un pattern (la definizione qui sotto, il grep di
# make-deb.sh) si marcano con il commento 'sanitize-ignore': eccezione esplicita,
# una riga alla volta, rivedibile in diff. Non esiste piu' l'auto-esclusione del
# gate: pubblicare l'elenco di cosa nascondere lo rivelerebbe.
# I pattern specifici vivono in un file gitignored: le sue occorrenze non sono
# una violazione (e' il file che li contiene, non un leak nel pubblicato).
if [ -f "$PATTERN_LOCAL" ]; then
    grep -v -F "${PATTERN_LOCAL#./}" "$FOUND" >"$SORTED" || true
    mv "$SORTED" "$FOUND"
fi

N=$(grep -c "" "$FOUND" || true)
if [ "$N" = 0 ]; then
    echo "pulito: nessun riferimento personale, di infrastruttura interna o segreto"
    [ "$HISTORY" = 1 ] && echo "(storia ispezionata: $(git rev-list --count "$REFS") commit)"
    exit 0
fi

echo "TROVATE $N occorrenze da rivedere prima di pubblicare:" >&2
head -30 "$FOUND" >&2
[ "$N" -gt 30 ] && echo "... altre $((N - 30))" >&2
exit 1
