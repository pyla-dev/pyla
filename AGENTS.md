# PYLA — regole per gli agenti che lavorano su questo repo

Due remote, **due meccanismi diversi**. Non sono due copie dello stesso repo e
non sono interscambiabili. Confonderli è l'errore più costoso possibile qui.

| | Archivio (privato) | Pubblico |
|---|---|---|
| Cosa | self-hosted nella rete privata, `origin` | GitHub, `github` = `pyla-dev/pyla` |
| Contenuto | la **storia reale**: tutti i commit, autori reali, branch WIP | **snapshot** senza storia: 1 commit per rilascio, autore `PYLA Project` |
| Chi ci scrive | `packaging/sync-private.sh` | `packaging/publish-public.sh` |
| Storia | 20+ commit, discendenti lineari | 2 commit sintetici, **nessun antenato comune con l'archivio** |

## La regola

**Mai `git push github main` (o `--all`/`--tags` verso `github`) di riflesso.**
Pubblicherebbe in un colpo la storia dell'archivio: 15 commit firmati con il
nome e l'email di lavoro dell'autore, più ogni blob transitato nei commit storici
(messaggi, path, note interne). È esattamente ciò che è stato rimosso con la
ricostruzione della history pubblica del 2026-11-08. Per l'elenco esatto:
`git log main --format='%an <%ae>' | sort | uniq -c`.

- Pubblicare = `packaging/publish-public.sh` (prima `--dry-run`). Costruisce un
  commit nuovo **figlio dell'ultimo commit pubblico**, con l'albero corrente:
  la storia locale non viene mai spinta.
- Allineare l'archivio = `packaging/sync-private.sh` (prima `--dry-run`).
- Le due storie sono **intenzionalmente scollegate**: mai `git pull github main`
  su un branch locale (creerebbe un merge fra storie senza base comune).
- `git config remote.github.tagOpt --no-tags` è già impostato: senza, un
  `git push --tags` spedirebbe al pubblico i tag che puntano ai commit reali.
- Guardia meccanica: `.git/hooks/pre-push` (`agent-directives/hooks/pre-push-public-identity.sh`)
  rifiuta push verso il pubblico di commit il cui autore non è `PYLA Project`.
- Prima di pubblicare: `packaging/check-public.sh --content-only` (path, email,
  segreti, host interni) e `--authors-only`. Il gate nomina anche l'archivio:
  un file che finisce nello snapshot non deve nominarlo.

## Identità

- Nei commit **pubblici** solo `PYLA Project <maintainers@pyla.space>`.
  `publish-public.sh` lo impone; negli script di packaging non citare mai
  l'autore reale o il suo dominio.
- Licenza: "Copyright (c) 2026 The PYLA Project Authors".
- Identifier `space.pyla.app`, azione polkit `space.pyla.app.helper`. Il **file**
  di policy deve chiamarsi `packaging/space.pyla.app.policy`: `install-helper.sh`,
  `make-deb.sh` e `migrate-argo-to-pyla.sh` usano `$ID.policy` con `ID=space.pyla.app`.
  Dopo ogni rinomina dell'identifier, rinominare il file e rigenerare il `.deb`.

## Binari e `.deb`

`packaging/make-deb.sh` builda da una copia pulita fuori dalla home con
`--remap-path-prefix` e poi **verifica con `strings`** che `pyla` e `pyla-helper`
non contengano path della home di build (`/home/<user>`, `/Users/`, directory del
progetto dell'IDE). Non bypassare la
verifica: `target/release/pyla` (build di lavoro) ha ~448 path locali e non deve
mai diventare un asset.

## Verifiche di fine sessione

```sh
cargo test --workspace
packaging/check-public.sh --content-only
packaging/sync-private.sh --dry-run     # "solo su disco: 0" = allineato
```

`git status` deve essere pulito: i commit vanno fatti, non lasciati in sospeso.
