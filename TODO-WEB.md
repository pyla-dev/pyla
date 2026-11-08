# TODO — web/headless mode for PYLA (ADR-0001)

> Stato **misurato** il 2026-11-08 su `feat/web-mode` (HEAD `e6a93ff`).
> Ogni voce ha il file esatto da toccare e il criterio di "fatto".
> Riferimento di design: [`docs/adr/0001-modalita-web.md`](docs/adr/0001-modalita-web.md).

## Fatto e verificato

| Voce | Verifica |
|---|---|
| `docs/adr/0001-modalita-web.md` | ADR accettato: 4 opzioni valutate, canale privilegiato a 3 varianti, matrice di trade-off, 8 limiti noti, 15 action item |
| Dipendenze in `src-tauri/Cargo.toml` | `axum 0.8`, `include_dir 0.7`, `clap 4 (derive)`, `futures-util 0.3`, `tokio 1 (macros, rt-multi-thread, signal, net)`, `tokio-stream 0.1`; `Cargo.lock` aggiornato |
| `src-tauri/src/state.rs` | `AppState {db, db_path, mode}` + `web_data_dir()` (`--data-dir` > `PYLA_DATA_DIR` > `XDG_DATA_HOME` > `~/.local/share`, sottodir `space.pyla.app`) + 1 unit test |
| `src-tauri/src/events.rs` | `trait Emitter`, `Bus(Arc<dyn Emitter>)`, `TauriEmitter`, `NullEmitter` |
| Build del workspace | `cargo build --workspace` OK, `cargo clippy --workspace --all-targets` pulito, `cargo test --workspace` 24 passati / 0 falliti / 3 `--ignored` |

## ⚠️ Da sapere prima di continuare

`src-tauri/src/main.rs` dichiara solo `mod cve; mod db; mod helper;`.
**`state.rs` e `events.rs` non sono dichiarati**: non entrano nel grafo di compilazione,
quindi oggi sono **codice morto** — nessun warning, nessun test eseguito. Il crate `pyla`
e' un binario, non una libreria: un modulo orfano non da' errore.
Conseguenza pratica: il passo 4 (clap in `main.rs`) deve **collegare** i due moduli, e fino
a quel momento `cargo test -p pyla` non copre `state.rs` (il test `data_dir_esplicita_vince`
non viene eseguito).

**Verifica fatta il 2026-11-08** (collegamento temporaneo dei due moduli, poi ripristinato):
compilano. `cargo check -p pyla --all-targets` chiude con 5 warning `never constructed`
(`Bus`, `TauriEmitter`, `NullEmitter`, `AppState`, `web_data_dir`) e nessun errore;
`cargo test -p pyla` passa da 4 a **5 test** perche' `state::tests::data_dir_esplicita_vince`
entra nel grafo. Quindi la base e' **sana e integra**, non solo scritta: il lavoro restante e'
interfacciare, non riscrivere. NB: `cargo test --workspace` continuera' a riportare **24** finche'
i moduli restano orfani — quel numero NON dimostra che `state.rs` sia coperto.

### Realta' misurata della web mode (2026-11-08)

| Cosa | Reale |
|---|---|
| Design | ADR accettato, 431 righe, pubblicabile (il gate non segnala nulla) |
| Codice nel binario | **0 righe collegate**: `mod state;`/`mod events;` assenti da `main.rs` |
| `commands.rs` | **non esiste** — i 25 comandi sono ancora in `main.rs` |
| `web.rs` (router axum) | **non esiste** — 0 route HTTP |
| clap / `pyla web` | **assente** da `main.rs` (le dipendenze pero' si') |
| `helper.rs` | sempre `pkexec`: il canale headless a 3 passi **non e' implementato** |
| `packaging/pyla-web.service`, `install-web-service.sh` | **non esistono** |
| UI (adattatore di trasporto) | non iniziata |
| Dipendenze | `axum`, `include_dir`, `clap`, `futures-util`, `tokio-stream` dichiarate e risolte |

## Da fare, in ordine di dipendenza

1. [ ] `src-tauri/src/commands.rs` — estrarre i **25 comandi** da `main.rs:390`
       (`#[tauri::command]` + `State<AppState>`) in `pub fn x(st: &AppState, ...) -> Res<T>`.
       Fatto quando: in `main.rs` restano solo wrapper che delegano.
2. [ ] `src-tauri/src/web.rs` — router axum: `POST /api/invoke` (match sul nome comando),
       `GET /api/info`, `GET /api/events` (SSE da `tokio::sync::broadcast`), asset `ui/`
       via `include_dir!` + SPA fallback. `allowed()` su `Host`/`Origin` come in
       pattern `allowed()` del tool di riferimento + `X-Pyla-Token` se il bind non e' loopback.
3. [ ] `src-tauri/src/helper.rs` — risoluzione del canale privilegiato a 3 passi:
       `PYLA_HELPER_CMD` (senza pkexec) → `euid()==0` (helper diretto) → `pkexec`.
       Errore esplicito sul caso headless/pkexec.
4. [ ] `src-tauri/src/main.rs` — clap: `pyla` (default desktop), `pyla desktop`,
       `pyla web --host --port --data-dir --token`; env `PYLA_WEB_HOST`, `PYLA_WEB_PORT`,
       `PYLA_WEB_TOKEN`. **Declarations `mod commands; mod state; mod events; mod web;`**
       (chiude il warning di cui sopra) e refresh CVE che usa il `Bus` al posto di
       `app.emit` (`main.rs:282`).
5. [ ] `ui/app.js` — adattatore di trasporto: `window.__TAURI__` ? invoke Tauri :
       `fetch POST /api/invoke` + `EventSource /api/events` (righe 3 e 5; `call()` e' gia'
       il confine alla riga 462). `openUrl` (riga 1278, `plugin:opener|open_url`) degrada a
       `window.open` nel browser.
6. [ ] Test del catalogo comandi: i nomi di `generate_handler!` e quelli del `match` HTTP
       devono coincidere (la deriva altrimenti e' silenziosa).
7. [ ] Verifica end-to-end: `cargo build --release`, `cargo test --workspace`,
       `pyla web` in loopback + `curl` su `/api/info`, `/api/invoke` (`list_rulesets`) e
       `/api/events`; poi prove a mano delle 25 chiamate su **entrambi** i trasporti.
8. [ ] `packaging/pyla-web.service` + `packaging/install-web-service.sh`
       (progettati nell'ADR §6, i file non esistono).
9. [ ] Variante sudoers: `packaging/pyla.sudoers` + `--sudoers` in `install-web-service.sh`
       (`User=pyla` + `NOPASSWD` sulla sola `HELPER_PATH`), con utente di servizio.
10. [ ] `packaging/make-deb.sh`: variante `pyla-web` senza `Depends: libwebkit2gtk-4.1-0`,
        unit systemd nel postinst.
11. [ ] Feature cargo `desktop` (default on) per build server-only senza Tauri/WebKitGTK.
12. [ ] README: sezione "Web mode" (avvio, token, tunnel SSH
        `ssh -L 8723:127.0.0.1:8723 host`, reverse proxy TLS con `proxy_buffering off` su
        `/api/events`, perche' `pkexec` non funziona in headless) e link all'ADR.

## Vincoli da non dimenticare

- `pkexec` in headless fallisce (`pam_unix(polkit-1:auth): conversation failed`, osservato su
  su una workstation Ubuntu reale): la console web **non** puo' usarlo.
- Default di ascolto **loopback**: `pyla web` avviato a mano non espone nulla alla rete.
- Token obbligatorio (fail-closed: il server non parte) solo su bind non-loopback.
- Una sola UI: vietato duplicare o forkare `ui/`.
- Identita' fissa: `HELPER_PATH=/usr/local/libexec/pyla/pyla-helper`, policy
  `space.pyla.app.policy`, action `space.pyla.app.helper`, dati `space.pyla.app`.
- Il canale privilegiato non deve mai essere raggiungibile direttamente dal browser: `argv`
  costruito in Rust da argomenti validati in `pyla-core`.
