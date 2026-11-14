# Test della UI

Smoke test della UI di PYLA eseguiti con **jsdom** (nessun webview Tauri, nessuna
autenticazione polkit): i comandi Tauri sono sostituiti dai mock in `mock-data.mjs`.
Verificano la barra laterale a scomparsa (5 pagine + Firewall, Report incluso), il sottotitolo
contestuale della barra superiore, le traduzioni EN e i dialog di anteprima/applica.

```sh
cd tests
npm install          # una volta sola: jsdom
npm test             # IT + EN, exit code != 0 se un check fallisce
```

Copertura attuale: 110 check in italiano e 102 in inglese (`ui-smoke.mjs`,
`ui-smoke-en.mjs`). I check contengono asserzioni sul testo: se cambi un'etichetta
dell'interfaccia, aggiorna anche il test.

## Aprire la UI in un browser normale

`tests/mock-tauri.js` finge `window.__TAURI__` con dati d'esempio. Per una prova visiva
(screenshot, controllo layout a diverse larghezze):

```sh
cp tests/mock-tauri.js /tmp/preview/ && cp ui/index.html ui/app.js ui/style.css ui/icon.svg /tmp/preview/
sed -i 's#<script src="app.js">#<script src="mock-tauri.js"></script>\n  <script src="app.js">#' /tmp/preview/index.html
python3 -m http.server 8799 --directory /tmp/preview
# http://127.0.0.1:8799/index.html?view=cve&lang=en&collapsed=1
```

`mock-tauri.js` vive in `tests/` e non e' referenziato da `index.html`: `ui/` e' il bundle spedito nell'app: non viene caricato nell'app.
