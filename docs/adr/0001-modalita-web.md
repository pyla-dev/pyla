# ADR-0001: Modalita' web/headless di PYLA (GUI da browser su macchina remota)

**Status:** Accepted — implementazione in corso (branch `feat/web-mode`)
**Date:** 2026-11-06 (accettato), verificato il 2026-11-08
**Deciders:** PYLA Project (maintainers@pyla.space)

> **Stato di implementazione al 2026-11-08** — cosa esiste e cosa no, misurato sul repository:
> *esiste*: le dipendenze (`axum`, `include_dir`, `clap`, `tokio`, `tokio-stream`, `futures-util`),
> `src-tauri/src/state.rs` e `src-tauri/src/events.rs`.
> *non esiste ancora*: `src-tauri/src/commands.rs`, `src-tauri/src/web.rs`,
> `packaging/pyla-web.service`, `packaging/install-web-service.sh`.
> `main.rs` non ha ancora clap e `helper.rs` invoca ancora sempre `pkexec`.
> **Attenzione**: `state.rs` e `events.rs` non sono dichiarati come moduli in `main.rs`
> (che dichiara solo `cve`, `db`, `helper`), quindi **non fanno parte del grafo di compilazione**:
> nessun warning e nessun test su di essi finche' non vengono collegati. Il crate e' un
> binario, non una libreria: un modulo non dichiarato e' codice morto, non un errore.
> La release pubblicata (v0.2.1) **non contiene nulla di questa ADR**.

---

## Context

PYLA oggi esiste in una sola forma: **applicazione desktop Tauri 2**. Il flusso e' quello descritto in
`README.md` (sezione *Architecture*):

```
ui/ (WebView) --invoke--> src-tauri (comandi Tauri + SQLite) --pkexec--> pyla-helper (root) --> ufw/nft/sysctl
```

I pezzi in gioco, con i loro riferimenti puntuali:

| Pezzo | Riferimento nel repo | Vincolo rilevante per una modalita' remota |
|---|---|---|
| Comandi applicativi | `src-tauri/src/main.rs:390` (`tauri::generate_handler![...]`, 25 comandi: `app_info`, `local_status`, `list_rulesets`, …, `mitigate`) | Sono legati al framework: attributo `#[tauri::command]` + `State<AppState>` |
| Front end | `ui/app.js:3` (`const invoke = window.__TAURI__.core.invoke;`), `ui/app.js:5` (`listenEvent`) | Assume `window.__TAURI__` presente: in un browser normale e' `undefined` e la UI muore all'avvio |
| Canale privilegiato | `src-tauri/src/helper.rs` (`Command::new("pkexec").arg(HELPER_PATH)`) | `pkexec` richiede una sessione interattiva con GUI |
| Costanti di identita' | `crates/pyla-core/src/lib.rs:19` (`HELPER_PATH = /usr/local/libexec/pyla/pyla-helper`), `src-tauri/tauri.conf.json` (`identifier: space.pyla.app`), `packaging/space.pyla.app.policy` (action `space.pyla.app.helper`, `allow_active=auth_admin_keep`, `annotate …exec.path`) | Il percorso dell'helper e l'id polkit sono fissi e condivisi fra app, helper, policy e pacchetti |
| Persistenza | `src-tauri/src/main.rs:379-381` (`app.path().app_data_dir()` + `pyla.db`) → `~/.local/share/space.pyla.app/pyla.db` | Risolta da Tauri: in modalita' headless serve una risoluzione propria (XDG) |
| Pacchetti | `packaging/make-deb.sh` (`Depends: libwebkit2gtk-4.1-0, polkitd, ufw`) | Il binario `.deb` porta dentro WebView e X11/polkit anche su un server headless |

### Forze in campo

1. **PYLA e' pensato per macchine remote.** Un firewall si amministra piu' spesso su un host senza monitor
   (server, mini-PC, workstation in ufficio a cui si accede via SSH) che su una laptop con GUI. Oggi
   l'utente che vuole la GUI sul proprio server deve usare X11 forwarding, VNC o una VM.
2. **Un tool di firewalling non puo' essere riscritto in una UI web separata.** Due UI significano due
   modelli di regole, due validazioni, due superfici di bug: in un componente di sicurezza e' inaccettabile.
   La UI deve restare **una sola** (`ui/`).
3. **Il privilegio separato e' il cuore del modello di sicurezza** (`README.md`, sezione *Security model*):
   la GUI non fa mai root, tutto passa da `pyla-helper` autorizzato da polkit. Qualsiasi modalita' remota
   deve preservare questo confine, non aggirarlo.
4. **Vincolo reale, gia' osservato su una workstation Ubuntu con polkit 127:** in una shell non interattiva senza
   `XDG_SESSION_ID` / `XDG_SEAT` (sessione SSH non systemd-tracked, unit systemd di sistema, cron) `pkexec`
   **non funziona**: polkit non riesce a identificare la sessione attiva e in log compare
   `pam_unix(polkit-1:auth): conversation failed`. Non e' un bug da correggere: e' il funzionamento di
   polkit. Ne discende che **`pkexec` non puo' essere il canale privilegiato del processo web**.
5. **Costo di mantenimento basso:** un progetto piccolo, maintainer unico, UI senza framework ne' bundler
   (`ui/index.html`, `ui/app.js`, `ui/style.css`). La soluzione non deve introdurre un secondo stack
   frontend ne' una pipeline di build npm.

### Requisiti

| # | Requisito | Priorita' |
|---|---|---|
| R1 | Stessa identica UI di `ui/` nel browser, senza duplicazione ne' fork | deve |
| R2 | Stesso core di regole/validazione/piano: `crates/pyla-core`, nessuna logica di firewall duplicata | deve |
| R3 | Il confine di privilegio (helper allow-listed, no shell, input validato) resta identico | deve |
| R4 | Funziona su host headless, avviabile come unit systemd di sistema | deve |
| R5 | Un solo artefatto da compilare, rilasciare e pacchettizzare | deve |
| R6 | Accessibile da laptop remoto senza aprire porte firewall aggiuntive (tunnel SSH) | deve |
| R7 | Difesa dal DNS rebinding e dall'accesso non autorizzato quando l'ascolto non e' loopback | deve |
| R8 | Possibile build server-only (senza webkit2gtk) in futuro | should |
| R9 | Multi-utenza con ruoli distinti | could (non in questa iterazione) |

---

## Decision

**Un unico binario `pyla` con dispatch di sottocomandi (clap) e un layer di comandi condiviso dietro i due
trasporti.** `pyla` senza argomenti = desktop (compatibilita' con `Exec=/usr/bin/pyla` in
`packaging/make-deb.sh`), `pyla desktop` = desktop esplicito, `pyla web` = server HTTP headless. Lo schema
e' lo stesso di un altro tool Rust dell'ecosistema interno (binario con enum `Mode { Desktop, Web { host, port } }`, default `Desktop`) e del suo modulo `web.rs` (asset incorporati con `include_dir!`, router axum, controllo `Host`/`Origin`).

### 1. CLI

```
pyla                       # desktop (default, invariato rispetto a oggi)
pyla desktop               # desktop esplicito
pyla web [--host H] [--port P] [--data-dir D] [--token T]
```

| Flag | Default | Override via ambiente | Note |
|---|---|---|---|
| `--host` | `127.0.0.1` | `PYLA_WEB_HOST` | su loopback il token non e' obbligatorio: la fiducia e' la macchina locale |
| `--port` | `8723` | `PYLA_WEB_PORT` | porta dedicata, non 80/443/8080, per non collidere con servizi esistenti |
| `--data-dir` | `$XDG_DATA_HOME/space.pyla.app` (fallback `~/.local/share/space.pyla.app`) | — | contiene `pyla.db`; identico path del desktop, quindi le regole create a desktop si ritrovano in web |
| `--token` | — | `PYLA_WEB_TOKEN` | obbligatorio **solo** se l'ascolto non e' loopback; se manca e l'ascolto e' non-loopback il server **rifiuta di partire** (fail-closed) |

Scelta deliberata: il default di ascolto e' **loopback**. `pyla web` avviato a mano non espone nulla alla
rete; l'esposizione richiede una scelta esplicita (flag/env) piu' un token.

### 2. Server HTTP (axum)

| Rotta | Metodo | Corpo | Risposta |
|---|---|---|---|
| `/api/invoke` | `POST` | `{"cmd": "apply", "args": {...}}` | `{"ok": true, "data": ...}` oppure `{"ok": false, "error": "..."}` |
| `/api/events` | `GET` | — | `text/event-stream`; un `event: cve-refreshed` quando il refresh CVE in background termina |
| `/api/info` | `GET` | — | `{version, helper_installed, helper_path, db_path, mode: "web", token_required}` |
| `/`, `/{*path}` | `GET` | — | asset statici di `ui/` incorporati nel binario con `include_dir!`; percorso sconosciuto → `index.html` (SPA fallback) |

Il contratto `{ok,data}|{ok,error}` e' la stessa forma dell'invoke Tauri (che risolve/reject su `Promise`),
quindi l'adattatore del frontend non deve rimappare gli errori.

**Difesa DNS rebinding** — identica alla `allowed()` di quel `web.rs` di riferimento: se il bind e' su
loopback si accettano **solo** `Host` = `localhost`, `127.0.0.1`, `::1` (con gestione della forma `[::1]:porta`);
se arriva `Origin`, la sua autorita' deve coincidere con `Host`. In piu', quando l'ascolto **non** e'
loopback ogni richiesta deve portare l'header **`X-Pyla-Token`** (perche' un browser non puo' impostare
`Host` a piacimento, il controllo di `Host` da solo non basta quando il server e' raggiungibile da nome).

**CSP servita** (la stessa gia' dichiarata in `src-tauri/tauri.conf.json` → `app.security.csp`, per non avere
due politiche diverse fra desktop e web):

```
default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'
```

Niente CDN, nessun asset esterno: gli asset sono quelli incorporati, quindi `default-src 'self'` e'
sufficiente e la UI resta offline-capable.

### 3. Frontend: un solo `ui/`, con adattatore di trasporto

In `ui/app.js` (oggi hardcoded su `window.__TAURI__` alle righe 3 e 5) si introduce un unico punto di
astrazione, `call()` esiste gia' (`ui/app.js:462`) e diventa il confine:

```js
const transport = window.__TAURI__
  ? { invoke: (cmd, args) => window.__TAURI__.core.invoke(cmd, args),
      events: (name, cb) => window.__TAURI__.event.listen(name, ({payload}) => cb(payload)) }
  : { invoke: (cmd, args) => fetch("/api/invoke", {method:"POST", headers, body: JSON.stringify({cmd,args})})
                            .then(r => r.json()).then(j => j.ok ? j.data : Promise.reject(j.error)),
      events: (name, cb) => { const es = new EventSource("/api/events"); es.addEventListener(name, cb); return () => es.close(); } };
```

Conseguenze: **una sola codebase UI**, nessuna UI duplicata, il trasporto web usa `fetch`/`EventSource`
(servizio web standard, niente WebSocket proprietarie) e il desktop resta invariato.

### 4. Layer di dispatch dei comandi condiviso

I 25 comandi di `src-tauri/src/main.rs:390` diventano funzioni `commands::xxx(&AppState, args) -> Res<T>`
indipendenti da Tauri; `generate_handler!` resta un elenco di wrapper sottili che delegano allo stesso layer,
e `POST /api/invoke` smista su `cmd` con un `match`. Il `Router` axum e l'`invoke_handler` Tauri diventano
due **facce** dello stesso catalogo: se si aggiunge un comando in un punto, e' visibile nell'altro.

### 5. Canale privilegiato in headless (sotto-decisione)

`src-tauri/src/helper.rs::call()` oggi fa sempre `pkexec HELPER_PATH`. Diventa una **risoluzione a tre passi**,
documentata qui perche' e' la parte piu' delicata dell'intera proposta:

```
1) PYLA_HELPER_CMD impostato  -> esegui quel comando, SENZA pkexec (canale gia' privilegiato "out of band")
2) euid == 0                  -> esegui HELPER_PATH direttamente (nessun pkexec: siamo gia' root)
3) altrimenti                 -> pkexec HELPER_PATH  (comportamento desktop di oggi, invariato)
```

Perche' serve: il vincolo del punto 4 del *Context*. In una unit systemd di sistema o in una sessione SSH
non systemd-tracked mancano `XDG_SESSION_ID`/`XDG_SEAT`, polkit non associa la richiesta a una sessione
attiva, `allow_active` (unico valore abilitato in `packaging/space.pyla.app.policy`) non si applica e
pkexec fallisce con `pam_unix(polkit-1:auth): conversation failed`. Quindi **il web non puo' usare pkexec**:
serve un canale privilegiato alternativo, e va scelto esplicitamente, non improvvisato.

| # | Variante | Meccanismo | Pro | Contro | Stato |
|---|---|---|---|---|---|
| **1** | **sudoers `NOPASSWD` per la sola `HELPER_PATH`** | file in `/etc/sudoers.d/pyla` con `pyla ALL=(root) NOPASSWD: /usr/local/libexec/pyla/pyla-helper`; unit con `User=pyla` e `PYLA_HELPER_CMD=sudo /usr/local/libexec/pyla/pyla-helper` | il processo web **non** e' root; il privilegio resta confinato a un binario singolo, allow-listed per percorso assoluto; l'helper continua a pretendere euid 0 (`crates/pyla-helper/src/main.rs`, `is_root()`) e a parlare JSON in/out | un file sudoers in piu' da auditare; se l'helper fosse sostituibile da utente non root avrebbe escalation (mitigato da `install -o root -g root -m 0755` in `packaging/install-helper.sh`) | **subito** |
| **2** | **unit systemd con `User=root`** | ExecStart del solo `pyla web`, helper invocato direttamente (passo 2 della risoluzione) | zero configurazione extra, un solo processo, nessuna dipendenza da sudoers/polkit | il processo web intere' (HTTP, SQLite, parsing di output esterno) gira come root: superficie di attacco piu' ampia; il DB resta sotto `/var/lib/pyla` di proprieta' di root | **subito** (default dell'unit fornita) |
| **3** | **socket systemd-activated AF_UNIX con `SO_PEERCRED`** | `pyla-helper.socket` + helper a richiesta; il web apre lo unix socket e verifica `SO_PEERCRED` (uid/gid del peer) prima di spedire la richiesta | canale autenticato crittograficamente **dalle sole credenziali kernel**, senza sudoers ne' root nel web; separazione reale e misurabile | richiede di passare da "figlio del processo" a "servizio a richiesta", quindi modificare il contratto stdin/stdout di `crates/pyla-helper/src/main.rs`, la gestione dei timeout e il packaging; lavoro non banale | **follow-up** |

**Scelta: 1 + 2 subito, 3 come follow-up.** Motivazione: 1 e 2 sono due configurazioni dello **stesso**
meccanismo (il passo 1/2 della risoluzione in `helper.rs`) e si implementano in poche righe, senza toccare il
contratto JSON stdin/stdout dell'helper, che e' quello che funziona gia' oggi su macchine reali. La variante
3 introduce un secondo protocollo di trasporto e tocca l'helper, che e' il componente piu' critico e meno
coperto da test: introdurlo insieme alla modalita' web significherebbe cambiare in un colpo solo superficie
di rete *e* canale privilegiato. La 3 resta pero' la destinazione corretta, perche' e' l'unica che da'
autenticazione del canale **senza** allargare il privilegio (variante 2) **e** senza sudoers (variante 1).

Regola di sicurezza non negoziabile che discende dalla scelta: **il canale privilegiato non puo' mai essere
raggiunto direttamente dal browser.** Il web invoca `pyla-helper` con un `argv` costruito in Rust a partire
da argomenti validati da `pyla-core`; nessun parametro controllore di `argv` arriva dal client senza
validazione (principio gia' espresso in `README.md`: *No shell, no free-form input*).

### 6. Packaging e unit systemd

- `packaging/pyla-web.service`: unit di sistema che avvia `pyla web` in bind su `127.0.0.1:8723` con
  `PYLA_HELPER_CMD=/usr/local/libexec/pyla/pyla-helper`.
- `packaging/install-web-service.sh`: installer POSIX coerente con `packaging/install-helper.sh`
  (`set -eu`, controllo root, `--uninstall`, path hardcoded).
- `packaging/make-deb.sh`: in follow-up, `pyla-web` come pacchetto separato (o metapacchetto) che **non**
  richiede `libwebkit2gtk-4.1-0`, con il servizio abilitato ma in bind loopback.

---

## Options Considered

### Option A: binario separato `pyla-server` (axum) in un crate dedicato

| Dimensione | Valutazione |
|---|---|
| Complessita' | **Media**: nuovo crate `crates/pyla-server`, nuovo Cargo.toml, ma nessuna logica duplicata se il layer comandi viene estratto |
| Costi | **Medi**: due binari da compilare, due target di test, due artefatti `.deb` (o un `.deb` con due eseguibili), due pipeline di rilascio |
| Sicurezza | **Buona**: il binario server puo' essere compilato **senza** webkit2gtk/GTK → meno dipendenze esposte su un server; il desktop resta identico |
| Manutenibilita' | **Media**: il rischio reale e' la **deriva dei due transport layer** nel tempo (un comando aggiunto a Tauri e dimenticato nel server), perche' le due superfici sono due file diversi |
| Riuso UI | **Totale**: la UI servita e' la stessa `ui/` |
| Distribuzione | **Peggiore**: l'utente deve scegliere *quale* binario eseguire; il percorso `/usr/bin/pyla` del desktop e `pyla-server` convivono |

**Pros:** separazione netta; build server-only senza dipendenze GUI; il binario desktop non cresce.
**Cons:** due artefatti e due release; la tentazione di "aggiustare" una delle due superfici porta a logiche
differenziate; `packaging/make-deb.sh` va riscritto in parte; l'utente deve ricordare due nomi.

### Option B: stesso binario, sottocomando `pyla web`, layer di dispatch comandi condiviso — **SCELTA PRESA**

| Dimensione | Valutazione |
|---|---|
| Complessita' | **Bassa/Media**: un `main.rs` con clap + un modulo `web.rs` + estrazione del layer `commands`; il lavoro grosso e' lo spostamento dei 25 comandi fuori dall'attributo `#[tauri::command]` |
| Costi | **Bassi**: un solo binario, un solo `.deb`, un solo `cargo build`, un solo set di test |
| Sicurezza | **Media**: il binario linka comunque webkit2gtk (mitigato in follow-up dalla feature cargo `desktop`); superficie di rete aggiuntiva mitigata da loopback default + `Host`/`Origin` + token |
| Manutenibilita' | **Alta**: un solo catalogo di comandi; l'elenco di `generate_handler!` e il `match` di `/api/invoke` puntano alle stesse funzioni, quindi un comando nuovo e' automaticamente disponibile su entrambe le strade |
| Riuso UI | **Totale**, e la UI e' **una sola** (adattatore di trasporto, non due interfacce) |
| Distribuzione | **Ottima**: `pyla web` su un server gia' installato; nessun secondo pacchetto; coerente con `Exec=/usr/bin/pyla` gia' nel `.deb` |
| Coerenza col progetto | **Alta**: ricalca un pattern gia' validato su un altro tool dell'ecosistema (stesso schema `tool` / `tool desktop` / `tool web`) |

**Pros:** un artefatto; una UI; un layer di comandi; nessuna biforcazione di comportamento fra desktop e web;
il desktop di oggi non cambia comportamento (nessun sottocomando = desktop).
**Cons:** il binario web porta dentro librerie GUI inutili finche' non arriva la feature cargo; un bug in
una dipendenza comune (serde_json, rusqlite) impatta entrambe le modalita' — ma e' anche il vantaggio di
non avere codice duplicato.

### Option C: Tauri in modalita' remote / `devUrl` con sidecar HTTP

| Dimensione | Valutazione |
|---|---|
| Complessita' | **Alta**: Tauri 2 serve la UI dentro una WebView; esporla via HTTP richiede un sidecar che replica l'invoke (in pratica serve comunque un `POST /api/invoke`) e la risoluzione dell'asset `frontendDist` a runtime |
| Costi | **Medi/Alti**: sidecar o plugin, piu' configurazione `build.devUrl`/`beforeDevCommand` in `src-tauri/tauri.conf.json` |
| Sicurezza | **Peggiore**: Tauri non e' pensato come web server di produzione (asset serviti in dev, CSP applicata dalla WebView e non dal server, nessuna gestione nativa di `Host`/`Origin`) |
| Manutenibilita' | **Bassa**: si dipende dal comportamento interno di Tauri (asset protocol, `withGlobalTauri`), che non e' un'API stabile per il serving HTTP |
| Riuso UI | **Totale**, ma con `window.__TAURI__` **inesistente** nel browser: l'adattatore serve comunque |
| Headless | **Peggiore**: Tauri su host senza display richiede `xvfb`/WebKitGTK in modalita' offscreen, non un vero headless |

**Pros:** quasi zero codice nuovo per servire gli asset; la UI resta identica "per costruzione".
**Cons:** Tauri non e' un web server: si finisce comunque per scrivere il bridge HTTP, quindi si paga la
complessita' di due trasporti **e** si resta dipendenti da WebViewGTK su un server. Il punto decisivo:
l'"esporre Tauri via `devUrl`" resolve solo il 20% del problema (dove sono gli asset) e lascia aperto
l'80% (dove finiscono gli invoke e come si autenticano).

### Option D (non-web): remoto classico — X11 forwarding / VNC / Wayland

| Dimensione | Valutazione |
|---|---|
| Complessita' | **Bassa** per PYLA: zero codice nuovo |
| Costi | **Alti operationalmente**: `xauth`, X11 forwarding su SSH (spesso disabilitato per hardening), server X/Wayland e display manager attivi **sul server**, oppure VNC + risoluzione/screenshot |
| Sicurezza | **Discutibile**: X11 forwarding espone un canale noto; VNC su porta dedicata deve essere protetto a sua volta da tunnel; `pkexec` **funziona** (c'e' una sessione attiva), il che e' l'unico vero vantaggio |
| Manutenibilita' | **Media**: non tocca il codice, ma ogni variazione di UI/tema va riverificata su ogni stack grafico |
| Riuso UI | **Totale** |
| UX | **Peggiore**: latenza, niente adattamento a schermi diversi, sessione che cade con la rete; su un server headless servono comunque X/Wayland installati |
| Scalabilita' | **Pessima**: una sessione grafica per amministratore |

**Pros:** non richiede modifiche a PYLA; il canale polkit resta quello esistente.
**Cons:** non risolve il caso d'uso reale — un server headless non ha (e non dovrebbe avere) una sessione
grafica; porta display manager e librerie grafiche su macchine dove non servono; la GUI via X11 su rete
lenta e' inutilizzabile. Scartata perche' sposta il problema (GUI remota) invece di risolverlo.

---

## Trade-off Analysis

### Matrice comparativa

| Criterio | A: `pyla-server` separato | **B: `pyla web` (scelta)** | C: Tauri remote/`devUrl` | D: X11/VNC/Wayland |
|---|---|---|---|---|
| Complessita' implementativa | Media | **Bassa/Media** | Alta | Bassa (nel repo) |
| Complessita' operativa (chi installa) | Media (2 binari) | **Bassa (1 binario)** | Alta | Alta (stack grafico) |
| Costi di build | x2 artefatti | **x1** | x1 + sidecar | n/a |
| Costi di rilascio/packaging | 2 pacchetti o 1 con 2 eseguibili | **1 pacchetto** | 1 pacchetto | 1 pacchetto invariato |
| Superficie di attacco del binario | **Minima** (no GUI libs) | Media (webkit2gtk linkato) | Alta (GUI libs sempre) | Alta (GUI libs sempre) |
| Superficie di rete | 1 porta | 1 porta | 1 porta + dev server | 6000/5900 (X11/VNC) |
| Difesa DNS rebinding | da implementare | **replicata dal pattern di riferimento** | non nativa | n/a |
| Autenticazione | da implementare | token su bind non-loopback | assente | credenziali di sessione |
| Compatibilita' con headless puro | **Si** | **Si** | No (serve WebView/X) | No (serve sessione grafica) |
| `pkexec` funzionante | No → canale alternativo | No → canale alternativo | No | **Si** |
| Riuso UI | 100% | **100%, UI unica** | 100% | 100% |
| Rischio deriva fra le due superfici | **Alto** (2 cataloghi comandi) | **Basso** (1 catalogo) | Basso | Molto basso |
| Dipendenza da API instabili | No | No | **Si** (interni Tauri) | Si (stack grafico distro) |
| UX su connessione remota lenta | Buona (HTTP) | **Buona (HTTP)** | Buona | Scarsa |
| Sforzo di migrazione | 1–2 settimane | **1–2 settimane** | 1 settimana + incognite | 0 |
| Coerenza con la traiettoria del progetto | Media | **Alta** (stesso pattern gia' usato altrove) | Bassa | Bassa |

### Conflitti chiave e perche' si e' scelto cosi'

1. **Superficie di attacco del binario vs un solo artefatto.** La variante A da' il binario piu' piccolo;
   la B da' il prodotto piu' semplice da gestire. Si e' scelta B perche' il costo di A (due release, due
   superfici di comandi) e' **permanente**, mentre il suo vantaggio (niente webkit2gtk sul server) si puo'
   recuperare dopo con una **feature cargo `desktop`** senza cambiare architettura: la decisione e' quindi
   reversibile, e questo la rende preferibile a A, che e' irreversibile appena il packaging si divide.
2. **Unita' della UI vs autonomia del client web.** Un client web dedicato avrebbe potuto fare a meno di
   `window.__TAURI__` e modellare un'API REST "pulita". Ma la validazione delle regole e il piano di apply
   vivono in `pyla-core` e la UI contiene gia' la presentazione dei report (`preview`, `ApplyReport`,
   rollback): una seconda UI sarebbe una seconda opportunita' di errore **su un tool che modifica il
   firewall in produzione**. Il costo accettato e' un'API a comandi (non REST resource-oriented), che e'
   anche il contratto nativo di Tauri.
3. **Privilegio minimo vs semplicita' operativa.** L'unit fornita parte con `User=root` (variante 2): e' la
   scelta meno sicura ma immediatamente funzionante e senza file sudoers. La variante 1 (sudoers
   `NOPASSWD` sulla sola `HELPER_PATH`) e' quella raccomandata in produzione perche' toglie root al processo
   HTTP, e per attivarla **non serve codice nuovo**: basta il file sudoers e `User=pyla`. La 3
   (socket AF_UNIX + `SO_PEERCRED`) e' l'obiettivo finale.
4. **HTTP pulito vs TLS.** Non si implementa TLS dentro PYLA: sarebbe un altro componente da validare e
   ruotare (certificati). Si raccomanda un reverse proxy TLS esistente o il tunnel SSH
   `ssh -L 8723:127.0.0.1:8723 host`, che **non richiede di aprire porte** e quindi non contraddice lo
   scopo del prodotto (essere uno strumento di hardening). Il token, quando serve, protegge dall'accesso
   non autorizzato; il TLS lo mette il canale, non l'applicazione.
5. **SSE vs WebSocket.** SSE e' sufficiente: il flusso in uscita e' un solo evento (`cve-refreshed`,
   `src-tauri/src/main.rs:282`) e il flusso in entrata e' request/response. `EventSource` riconnette da
   solo e passa attraverso un reverse proxy senza handshake di upgrade. Il costo: niente canale bidirezionale,
   che pero' oggi non serve. (Nel tool di riferimento il WebSocket esiste perche' li il flusso e' bidirezionale e
   continuo.)

---

## Consequences

### Cosa diventa possibile

- La stessa UI di PYLA su un server Ubuntu senza display, senza X11/VNC e senza display manager.
- Un solo `cargo build --release` e un solo `.deb` per entrambe le modalita'; un comando aggiunto nel layer
  condiviso e' disponibile subito su desktop e su web.
- `~/.local/share/space.pyla.app/pyla.db` e' condiviso per percorso: i set creati a desktop si rivedono in
  web (sullo stesso host), e la migrazione gia' esistente (`packaging/migrate-argo-to-pyla.sh`) non cambia.
- L'accesso remoto senza aprire porte: `ssh -L 8723:127.0.0.1:8723 host` + `http://localhost:8723`.
- Il confine privilegiato resta ispezionabile: `sudoers.d/pyla` (variante 1) e' un file di 1 riga da
  rivedere in audit, e l'helper continua a pretendere euid 0.

### Cosa diventa piu' difficile / costo accettato

- **Due trasporti da tenere allineati.** Il `match` di `/api/invoke` e l'elenco di
  `tauri::generate_handler!` (`src-tauri/src/main.rs:390`) devono restare in sincronia: serve un test che
  confronta i due cataloghi, altrimenti la deriva e' silenziosa.
- **Il web non ha la sessione utente**: niente dialoghi polkit. Le azioni che nel desktop chiedono
  `auth_admin_keep` qui sono autorizzate **a priori** dal canale systemd/sudoers. E' un cambio di postura di
  sicurezza da documentare all'utente: chi puo' raggiungere la porta puo' modificare il firewall.
- **Nessuna autenticazione multiutente**: un solo token, un solo livello di privilegio. Non c'e' "read-only"
  per un secondo operatore, e non c'e' audit di *chi* ha applicato una regola (la history di `apply` non
  distingue gli operatori).
- **HTTP senza TLS**: il token viaggia in chiaro se il canale non e' protetto. Mitigazioni documentate:
  bind loopback di default, reverse proxy TLS, tunnel SSH.
- **Il binario `pyla web` linka comunque webkit2gtk** (dipendenza attuale in `src-tauri/Cargo.toml` via
  `tauri`, dichiarata anche in `Depends` in `packaging/make-deb.sh`): su un server significa installare
  librerie GUI. Follow-up: feature cargo `desktop` per build server-only.
- **`pkexec` non e' un'opzione in headless** (vincolo, non scelta): ogni documentazione operativa deve
  spiegare che il canale privilegiato va configurato, non dato per scontato.
- **SQLite su un servizio di sistema**: il DB in modalita' web vive sotto il path di chi esegue il servizio
  (`/var/lib/pyla` con `User=root`/`User=pyla`, oppure `~/.local/share/space.pyla.app` per un utente). Va
  chiarito perche' desktop e web sullo stesso host potrebbero altrimenti usare **due DB diversi**.

### Da rivedere

- Variante 3 (socket systemd-activated + `SO_PEERCRED`) come canale privilegiato definitivo.
- Feature cargo `desktop` / pacchetto `pyla-web` senza webkit2gtk.
- Se l'esposizione non-loopback servira' davvero: TLS nel binario (rustls) o obbligo di reverse proxy.
- Audit multi-operatore e ruoli (read-only vs apply), se emergono esigenze di team.

---

## Limiti noti

| Limite | Dettaglio | Mitigazione |
|---|---|---|
| HTTP senza TLS | il token e i payload viaggiano in chiaro sul tratto di rete | reverse proxy TLS (nginx/caddy) **oppure** tunnel SSH `ssh -L 8723:127.0.0.1:8723 host` (nessuna porta aperta) |
| `pkexec` non funziona in headless | shell non interattiva senza `XDG_SESSION_ID`/`XDG_SEAT` → polkit non identifica la sessione → `pam_unix(polkit-1:auth): conversation failed` (osservato su hardware reale) | unit systemd con `PYLA_HELPER_CMD`, oppure `User=root`, oppure sudoers `NOPASSWD` per la sola `HELPER_PATH` |
| Binario con dipendenze GUI | `pyla web` linka webkit2gtk/GTK anche senza GUI | follow-up: feature cargo `desktop`; nel frattempo il pacchetto server installa comunque `libwebkit2gtk-4.1-0` |
| Nessuna autenticazione multiutente | un solo token condiviso, nessun ruolo, history di apply senza autore | accettare per la 0.x; tenere il bind su loopback e usare il tunnel SSH |
| Due DB possibili sullo stesso host | il path dei dati dipende dall'utente che esegue il servizio | fissare `--data-dir` esplicitamente nell'unit; documentarlo |
| Sessioni SSE e proxy | alcuni proxy bufferizzano l'SSE | disabilitare il buffering sul location `/api/events` (`proxy_buffering off`) |
| Compatibilita' del helper | il web invoca l'helper installato: se e' piu' vecchio dell'app l'helper risponde "comando sconosciuto" (`src-tauri/src/helper.rs`) | reinstallare con `sudo packaging/install-helper.sh` a ogni aggiornamento |
| Porta fissa 8723 | puo' collidere con servizi esistenti sull'host | `--port`/`PYLA_WEB_PORT` |

---

## Action Items

1. [ ] `src-tauri/src/main.rs`: aggiungere clap con `Mode { Desktop, Web { host, port, data_dir, token } }`,
    default = desktop; sottocomando `pyla web`.
2. [ ] Estrazione del layer `commands::` (le 25 funzioni di `src-tauri/src/main.rs:390`) con firma
    `fn x(&AppState, args) -> Res<T>`; `generate_handler!` ridotto a wrapper.
3. [ ] `src-tauri/src/web.rs`: router axum con `POST /api/invoke`, `GET /api/events` (SSE),
    `GET /api/info`, asset di `ui/` via `include_dir!`; CSP e controllo `Host`/`Origin` + `X-Pyla-Token`
    su bind non-loopback.
4. [ ] `src-tauri/src/helper.rs`: risoluzione del canale privilegiato a 3 passi
    (`PYLA_HELPER_CMD` → euid 0 → `pkexec`), con messaggio d'errore esplicito sul caso pkexec/headless.
5. [ ] Sostituzione del canale `app.emit("cve-refreshed")` (`src-tauri/src/main.rs:282`) con un broadcast
    interno usato da Tauri **e** SSE.
6. [ ] Risoluzione del path dati in modalita' web: `--data-dir` → `XDG_DATA_HOME/space.pyla.app` →
    `~/.local/share/space.pyla.app` (coerente con `identifier: space.pyla.app`).
7. [ ] `ui/app.js`: adattatore di trasporto (Tauri vs `fetch` + `EventSource`) attorno a `call()`;
    verifica a mano delle 25 chiamate su entrambi i trasporti.
8. [ ] Test del catalogo comandi: asserire che l'elenco esposto da `generate_handler!` e quello del
    dispatch HTTP coincidono.
9. [ ] `packaging/pyla-web.service`: unit systemd con hardening e `PYLA_HELPER_CMD`
    (progettata in questo ADR, sezione 6; **il file non esiste ancora**).
10. [ ] `packaging/install-web-service.sh`: install/uninstall dell'unit, `daemon-reload`, `enable --now`,
    prompt del tunnel SSH (**file non esistente**).
11. [ ] Variante sudoers: file `packaging/pyla.sudoers` + opzione `--sudoers` in `install-web-service.sh`
    (User=pyla + `NOPASSWD` sulla sola `HELPER_PATH`), con creazione dell'utente di servizio.
12. [ ] `packaging/make-deb.sh`: variante `pyla-web` senza `Depends: libwebkit2gtk-4.1-0`, con
    `systemd` unit e postinst che installa/abilita il servizio.
13. [ ] Feature cargo `desktop` (default on) per build server-only senza Tauri/WebKitGTK.
14. [ ] README: sezione "Modalita' web" (avvio, token, tunnel SSH, reverse proxy TLS, vincolo pkexec).
15. [ ] Follow-up: socket systemd-activated AF_UNIX + `SO_PEERCRED` come canale privilegiato senza root
    nel web e senza sudoers (variante 3).

---

## Riferimenti

- `README.md` — *Architecture*, *Security model*, *Installation*
- `src-tauri/tauri.conf.json` — `identifier: space.pyla.app`, `frontendDist: ../ui`, CSP, `withGlobalTauri`
- `src-tauri/src/main.rs` — 25 comandi, `generate_handler!`, `app_data_dir()` + `pyla.db`, `cve-refreshed`
- `src-tauri/src/helper.rs` — `pkexec` + `HELPER_PATH`, gestione exit code 126/127
- `crates/pyla-core/src/lib.rs:19` — `HELPER_PATH = /usr/local/libexec/pyla/pyla-helper`
- `crates/pyla-helper/src/main.rs` — contratto JSON in/out, `is_root()`, backup in `/var/lib/pyla/backups`
- `packaging/space.pyla.app.policy` — action `space.pyla.app.helper`, `allow_active=auth_admin_keep`
- `packaging/install-helper.sh`, `packaging/make-deb.sh` — path di installazione e dipendenze
- `ui/app.js:3-5`, `ui/app.js:462` (`call()`) — punti d'innesto dell'adattatore
- Modello di riferimento esterno (tool interno non pubblicato): `main.rs` con sottocomandi e
  `web.rs` (axum, `include_dir!`, controllo `Host`/`Origin`)
