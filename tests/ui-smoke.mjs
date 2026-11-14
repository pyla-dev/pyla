// Smoke test della UI di Pyla (barra laterale a scomparsa, viste a pagina) con jsdom.
// Uso: node /tmp/pyla-ui-smoke.mjs [radice-repo]
import fs from "node:fs";
import path from "node:path";
import { JSDOM, VirtualConsole } from "jsdom";

const ROOT = process.argv[2] || new URL("..", import.meta.url).pathname;
const html = fs.readFileSync(path.join(ROOT, "ui/index.html"), "utf8");
const appJs = fs.readFileSync(path.join(ROOT, "ui/app.js"), "utf8");
const cssText = fs.readFileSync(path.join(ROOT, "ui/style.css"), "utf8");

const calls = [];
import { data, APP_VERSION, watchState } from "./mock-data.mjs";

const vc = new VirtualConsole();
const errors = [];
vc.on("jsdomError", (e) => errors.push("jsdomError: " + e.message));
vc.on("error", (...a) => errors.push("console.error: " + a.join(" ")));

const dom = new JSDOM(html, { runScripts: "outside-only", url: "http://localhost/", pretendToBeVisual: true, virtualConsole: vc });
const { window } = dom;
let narrow = false;
// MediaQueryList finto ma con `matches` vivo, come quello reale del webview
window.matchMedia = (q) => ({ get matches() { return /max-width/.test(q) ? narrow : false; },
  media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });
window.localStorage.clear();
window.__TAURI__ = {
  core: { invoke: async (cmd, args) => { calls.push(cmd); if (!(cmd in data)) throw new Error("invoke non mockato: " + cmd); return typeof data[cmd] === "function" ? data[cmd](args) : data[cmd]; } },
  event: { listen: async () => () => {} },
};
window.navigator.clipboard = { writeText: async () => {} };

// jsdom non implementa <dialog>: polyfill minimo (open + close con evento "close")
window.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
window.HTMLDialogElement.prototype.show = window.HTMLDialogElement.prototype.showModal;
if (!window.HTMLDialogElement.prototype.close)
  window.HTMLDialogElement.prototype.close = function () {
    if (!this.open) return;
    this.open = false;
    this.dispatchEvent(new window.Event("close"));
  };

try { window.eval(appJs); } catch (e) { errors.push("eval: " + e.stack); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
await sleep(150);

const $ = (s) => window.document.querySelector(s);
const $$ = (s) => [...window.document.querySelectorAll(s)];
const txt = (s) => ($(s) ? $(s).textContent.replace(/\s+/g, " ").trim() : null);
const out = [];
const check = (label, cond, extra = "") => out.push(`${cond ? "PASS" : "FAIL"}  ${label}${extra ? " — " + extra : ""}`);

check("nav a 6 voci", $$("#main-nav .nav-item").length === 6, $$("#main-nav .nav-label").map((e) => e.textContent).join("|"));
check("brand+versione in barra", txt(".sidebar-brand")?.includes("PYLA") && txt("#app-version") === "v" + APP_VERSION, txt("#app-version"));
const btnLang = $("#btn-lang");
check("lingua spostata nell'header (non piu' in barra)",
  !!btnLang && !!btnLang.closest(".main-header") && !btnLang.closest(".sidebar"),
  btnLang ? (btnLang.closest(".main-header") ? "header OK" : "non nell'header") : "pulsante assente");
check("lingua ultima voce a destra dell'header",
  !!btnLang && btnLang.parentElement.lastElementChild === btnLang,
  btnLang ? btnLang.parentElement.className || btnLang.parentElement.tagName : "-");
check("lingua: etichetta e titolo",
  /^IT$/.test($("#btn-lang-label")?.textContent || "") && /Lingua|Language/.test(btnLang?.title || ""),
  `${$("#btn-lang-label")?.textContent} | ${btnLang?.title}`);
check("stato fw in fondo barra", txt("#fw-status")?.includes("UFW attivo"), txt("#fw-status"));
check("2 set in barra", $$("#rulesets li").length === 2);
check("barra aperta all'avvio", !$("#sidebar").classList.contains("collapsed"));
check("vista firewall", $("#view").className === "view" && $("#sets-rail").hidden === false);
check("header = set selezionato", txt("#view-title") === "Default" && txt("#view-sub")?.includes("regole"), `${txt("#view-title")} / ${txt("#view-sub")}`);
check("azioni header vuote", $("#view-actions").children.length === 0);
check("tabella regole", $$("#view table.rules tbody tr").length === 2);
check("nessun testo 'null'", !/(^| )null( |$)/.test(txt("#view") || ""), "");

$("#btn-rail").click();
check("barra collassata", $("#sidebar").classList.contains("collapsed"));
check("persistenza", window.localStorage.getItem("pyla.rail.collapsed") === "1");
$("#btn-rail").click();
check("barra riaperta", !$("#sidebar").classList.contains("collapsed") && window.localStorage.getItem("pyla.rail.collapsed") === "0");
window.document.dispatchEvent(new window.KeyboardEvent("keydown", { key: "b", ctrlKey: true, bubbles: true }));
check("Ctrl+B collassa", $("#sidebar").classList.contains("collapsed"));
window.document.dispatchEvent(new window.KeyboardEvent("keydown", { key: "b", ctrlKey: true, bubbles: true }));

$$("#main-nav .nav-item")[1].click(); await sleep(80);
check("vista Stato UFW", txt("#view-title") === "Stato UFW" && txt("#view")?.includes("wg0") && txt("#view")?.includes("51820") && txt("#view")?.includes("Regole utente presenti ora in UFW"), (txt("#view-title")||"") + " || " + (txt("#view")||"").slice(0,60));
check("sottotitolo Stato UFW", txt("#view-sub")?.includes("entrata deny") && txt("#view-sub")?.includes("1 regole utente"), txt("#view-sub"));
check("pulsante Aggiorna", $$("#view-actions button").some((b) => b.textContent === "Aggiorna"));
check("set nascosti fuori da Firewall", $("#sets-rail").hidden === true);

$$("#main-nav .nav-item")[2].click(); await sleep(80);
check("vista Ruleset completo", txt("#view-title") === "Ruleset completo" && txt("#view")?.includes("ufw-user-input") && txt("#view")?.includes("table ip filter"), (txt("#view")||"").slice(0,60));
check("catene vuote nascoste", !txt("#view")?.includes("blank"));
check("header tabelle", txt("#view-sub")?.includes("1 tabelle"), txt("#view-sub"));
check("verdetto colorato", !!$("#view .verdict.v-accept"), "");

$$("#main-nav .nav-item")[4].click(); await sleep(150);
check("vista CVE", txt("#view-title") === "CVE" && txt("#cve-body")?.includes("CVE-2026-98862"), (txt("#cve-body")||"").slice(0,80));
check("sottotitolo CVE", txt("#view-sub")?.includes("kernel 6.14.0-27") && txt("#view-sub")?.includes("415"), txt("#view-sub"));
check("badge seguite in nav", $$("#main-nav .nav-item")[4].textContent.includes(String(watchState().length)), $$("#main-nav .nav-item")[4].textContent.replace(/\s+/g," "));
check("nascondi corrette on", $("#cve-ctl input[type=checkbox]")?.checked === true);
check("corrette nascoste", !txt("#cve-body")?.includes("CVE-2026-98433"));
check("contatore nascoste", txt("#cve-sub")?.includes("1 corrette nascoste"), txt("#cve-sub"));
check("colonna mitigazione popolata", txt("#cve-body")?.includes("non in uso") && !!$("#cve-body button.small"), txt("#cve-body")?.match(/non in uso[^]*/)?.[0]?.slice(0,40));
$$(".cve-tab")[1].click(); await sleep(60);
check("tab Seguite", txt("#cve-body")?.includes("CVE-2026-98862"));
// cveCard (quindi descrizione e nota di mitigazione) esiste solo nel tab Seguite.
check("descrizione nello stesso riquadro della mitigazione",
  $$("#cve-body details.mit-note").length === 1 && !!$("#cve-body details.mit-note summary.mit-note-head"),
  String($$("#cve-body details.mit-note").length));
check("descrizione non in monospazio", $$("#cve-body details.mit-note pre").length === 0 &&
  !($("#cve-body details.mit-note .mit-text")?.className || "").includes("mono"),
  $$("#cve-body details.mit-note pre").map((x) => x.className).join(","));
check("descrizione conserva capolinea e indentazione",
  ($("#cve-body details.mit-note .mit-text")?.textContent || "").includes("\n    BUG: KASAN:") &&
  ($("#cve-body details.mit-note .mit-text")?.textContent || "").split("\n").length >= 5,
  JSON.stringify((($("#cve-body details.mit-note .mit-text") || {}))?.textContent?.split("\n")?.length));
check("descrizione chiusa di default", $("#cve-body details.mit-note")?.open === false,
  String($("#cve-body details.mit-note")?.open));
// La nota di mitigazione si vede nella scheda della CVE seguita (cveCard), non nella tabella.
check("nota mitigazione in box proprio", !!$("#cve-body .mit-note"), "nessun .mit-note");
check("pallini in lista", $$("#cve-body .mit-note .mit-facts li").length >= 4,
  String($$("#cve-body .mit-note .mit-facts li").length));
check("etichetta pallino in grassetto", $$("#cve-body .mit-note .mit-facts li b").some((b) => b.textContent === "Blocks:"),
  $$("#cve-body .mit-note .mit-facts li b").map((b) => b.textContent).join(","));
check("passo numerato", !!$("#cve-body .mit-note p.mit-step"), "nessun .mit-step");
check("comandi in pre multilineo", $$("#cve-body .mit-note pre.mit-cmd").length >= 1 &&
  ($("#cve-body .mit-note pre.mit-cmd")?.textContent || "").split("\n").length >= 5,
  JSON.stringify($$("#cve-body .mit-note pre.mit-cmd").map((p) => p.textContent.split("\n").length)));
check("nota non collassata in un paragrafo", !$$("#cve-body .mit-note p").some((p) => /Requires:.*Blocks:/s.test(p.textContent)),
  $$("#cve-body .mit-note p").map((p) => p.textContent.slice(0, 30)).join(" | "));

// --- ✕ nel tab "Seguite": la rimozione deve togliere la riga dallo schermo, non
//     solo mandare il toast. Erano rimaste le CVE smesse perche' la vista leggeva
//     i membri della cache (che accumulano) invece della watch list. ---
const cards = () => $$("#cve-body .cve-card");
check("due CVE seguite in vista", cards().length === 2, String(cards().length));
const cardBtn = (id, label) => cards().find((c) => c.textContent.includes(id))
  && [...cards().find((c) => c.textContent.includes(id)).querySelectorAll(".cve-head button")].find((b) => b.textContent === label);
check("pulsante x presente sulla card", !!cardBtn("CVE-2026-98435", "\u2715"), cardBtn("CVE-2026-98435", "\u2715") ? "ok" : "nessun ✕");
cardBtn("CVE-2026-98435", "\u2715").click(); await sleep(120);
check("dopo la x la CVE non e' piu' in vista", !txt("#cve-body")?.includes("CVE-2026-98435") && cards().length === 1,
  cards().length + " card, " + (txt("#cve-body") || "").includes("CVE-2026-98435"));
check("watch list aggiornata dal comando", watchState().join(",") === "CVE-2026-98862", watchState().join(","));
const tabCount = (i) => $$(".cve-tab")[i].querySelector(".pill")?.textContent.trim();
check("contatore tab Seguite scende a 1", tabCount(1) === "1", String(tabCount(1)));
check("toast dice rimossa", txt("#toast")?.includes("rimossa"), txt("#toast"));
// ri-seguirla dalla casella CVE-AAAA-NNNNN la fa ricomparire
const add = $("#cve-ctl input.cve-id-input"); add.value = "cve-2026-98435";
add.dispatchEvent(new window.Event("input", { bubbles: true })); await sleep(20);
$$("#cve-ctl button").find((b) => b.textContent === "Segui CVE").click(); await sleep(120);
check("ri-seguita: ricompare in vista", txt("#cve-body")?.includes("CVE-2026-98435") && cards().length === 2, String(cards().length));
check("input minuscolo accettato e normalizzato", watchState().includes("CVE-2026-98435") && !watchState().includes("cve-2026-98435"), watchState().join(","));
add.value = "CVE-99-1"; add.dispatchEvent(new window.Event("input", { bubbles: true })); await sleep(20);
$$("#cve-ctl button").find((b) => b.textContent === "Segui CVE").click(); await sleep(80);
check("id malformato rifiutato (niente card falsa)", !txt("#cve-body")?.includes("CVE-99-1") && cards().length === 2, cards().length + " card");

// ---- Report (porte in ascolto, come Gufw) ----
const repRows = () => $$("#report-body tbody tr");
$$("#main-nav .nav-item")[3].click(); await sleep(120);
check("vista Report", txt("#view-title") === "Report" && repRows().length === 3, `${txt("#view-title")} / ${repRows().length} righe`);
check("report: sottotitolo con conteggi", txt("#view-sub") === "3 in ascolto \u00b7 2 raggiungibili dalla rete \u00b7 solo i tuoi processi", txt("#view-sub"));
check("report: processo e pid", txt("#report-body")?.includes("sshd") && txt("#report-body")?.includes("pid 800"), "");
check("report: socket di altro utente senza nome (—) e con utente", repRows()[2].textContent.includes("\u2014") && repRows()[2].textContent.includes("avahi"), repRows()[2].textContent);
check("report: nota sui processi non risolti", txt("#view")?.includes("1 porta appartiene a un processo di un altro utente"), "");
check("report: porta locale attenuata", repRows()[1].classList.contains("dim") && repRows()[1].textContent.includes("solo locale") && repRows()[0].textContent.includes("tutte le interfacce"), repRows()[1].className);
check("report: data-label per il layout a schede", repRows()[0].children[4].getAttribute("data-label") === "Processo", repRows()[0].children[4].getAttribute("data-label"));
check("report: navbadge 3", $$("#main-nav .nav-item")[3].textContent.includes("3"), $$("#main-nav .nav-item")[3].textContent);
const repLocal = $("#view .nft-toolbar input[type=checkbox]");
repLocal.checked = true; repLocal.dispatchEvent(new window.Event("change", { bubbles: true })); await sleep(20);
check("report: nascondi solo locali", repRows().length === 2 && !txt("#report-body").includes("631"), String(repRows().length));
repLocal.checked = false; repLocal.dispatchEvent(new window.Event("change", { bubbles: true })); await sleep(20);
const repQ = $("#view .nft-toolbar input[type=search]");
repQ.value = "SSHD"; repQ.dispatchEvent(new window.Event("input", { bubbles: true })); await sleep(20);
check("report: filtro su processo (case insensitive)", repRows().length === 1 && repRows()[0].textContent.includes("22"), String(repRows().length));
repQ.value = "zzz"; repQ.dispatchEvent(new window.Event("input", { bubbles: true })); await sleep(20);
check("report: filtro senza risultati", txt("#report-body") === "Nessuna porta corrisponde al filtro.", txt("#report-body"));
repQ.value = ""; repQ.dispatchEvent(new window.Event("input", { bubbles: true })); await sleep(20);
const allBtn = $$("#view-actions button").find((b) => b.textContent === "Mostra tutti i processi");
check("report: pulsante Mostra tutti i processi", !!allBtn, $$("#view-actions button").map((b) => b.textContent).join("|"));
allBtn.click(); await sleep(120);
check("report: con root compare avahi-daemon", txt("#report-body")?.includes("avahi-daemon") && !txt("#view")?.includes("porte appartengono"), "");
check("report: dopo root niente pulsante e sottotitolo aggiornato",
  !$$("#view-actions button").some((b) => b.textContent === "Mostra tutti i processi") && txt("#view-sub")?.endsWith("processi di tutti gli utenti"), txt("#view-sub"));
repRows()[0].querySelector("td.ctl button").click(); await sleep(120);
const rf = $("#rule-form");
check("report: + Regola apre l'editor compilato nel set",
  $("#panel-rule").hidden === false && txt("#view-title") === "Default" && rf.elements.dport.value === "22" &&
  rf.elements.proto.value === "tcp" && rf.elements.action.value === "allow" && rf.elements.direction.value === "in" && rf.elements.comment.value === "sshd",
  `${$("#panel-rule").hidden} ${txt("#view-title")} ${rf.elements.dport.value}/${rf.elements.proto.value} ${rf.elements.comment.value}`);
$("#panel-rule [data-close]").click(); await sleep(40);
check("stili base delle pillole presenti", /^\.pill \{[^}]*border-radius/m.test(cssText) && /^\.pill\.warn \{/m.test(cssText), "");

$$("#main-nav .nav-item")[5].click(); await sleep(80);
check("vista Storico", txt("#view-title") === "Storico" && txt("#view")?.includes("applicate 2 regole") && txt("#view")?.includes("1 applicazioni registrate"), (txt("#view")||"").slice(0,60));
$$("#main-nav .nav-item")[0].click(); await sleep(60);
check("ritorno Firewall", txt("#view-title") === "Default" && $("#sets-rail").hidden === false);

narrow = true;
console.log("DEBUG pre-cassetto: collapsed=" + $("#sidebar").className + " narrowQuery=" + window.matchMedia("(max-width: 820px)").matches + " bodyKids=" + [...window.document.body.children].map(e=>e.className||e.tagName).join(","));
$("#btn-rail").click();
check("cassetto aperto (velo)", !!$(".drawer-backdrop") && !$("#sidebar").classList.contains("collapsed"), $("#sidebar").className + " | " + [...window.document.body.children].map(e=>e.className||e.tagName).join(","));
$("#btn-rail").click();
check("cassetto chiuso (fascia)", !!$(".drawer-edge") && $("#sidebar").classList.contains("collapsed"));
$(".drawer-edge").click();
check("bordo riapre", !!$(".drawer-backdrop"));
$$("#main-nav .nav-item")[1].click(); await sleep(60);
check("cassetto si richiude", $("#sidebar").classList.contains("collapsed") && !!$(".drawer-edge"));
check("vista persistita", window.localStorage.getItem("pyla.view") === "live", window.localStorage.getItem("pyla.view"));
check("pannelli al posto dei dialog", ["panel-rule","panel-set","panel-import","panel-info"].every((i) => !!window.document.getElementById(i)) &&
  window.document.querySelectorAll("dialog").length === 0,
  `dialog nel DOM: ${window.document.querySelectorAll("dialog").length}`);

// --- flussi che restano dialog: anteprima/applica, comandi ufw ---
data.preview = { status: data.local_status, plan: { in_sync: false, unsupported: [], removed: [], added: [
  { action: "allow", direction: "in", interface: "wg0", proto: "udp", src: "any", sport: null, dst: "any", dport: "51820", log: "off", comment: "wireguard" }],
  reordered: false, desired: [] }, commands: ["ufw allow 51820/udp"] };
data.apply = { ok: true, message: "applicate 1 regole", log: [{ ok: true, command: "ufw allow 51820/udp", output: "" }], backup: "/tmp/ufw.bak" };
data.ruleset_commands = ["ufw allow 51820/udp", "ufw deny 23/tcp"];

// ---------- import di un set da file JSONC ----------
// i pannelli hanno sostituito i dialog: si aprono/chiudono con l'attributo hidden
const panelOpen = (id) => { const el = window.document.getElementById(id); return !!el && !el.hidden; };
const key = (k) => window.document.dispatchEvent(new window.KeyboardEvent("keydown", { key: k, bubbles: true }));

const impBtn = window.document.getElementById("btn-import-file");
check("pulsante importa da file presente", !!impBtn && !!window.document.getElementById("panel-import"),
  impBtn ? "pulsante + dialog" : "manca il pulsante");
// file con commenti //, nome nel documento e UNA regola disabilitata: deve entrare
// spenta (non sparire), altrimenti l'utente non sa che il file la conteneva.
// set di prova: commenti da ignorare, UNA regola spenta unica (deve arrivare nel set
// come riga disabilitata) e un duplicato (deny tcp 22 dentro il deny "any" finale):
// l'import lo scarta, come fa UFW, e il mock lo riproduce.
const IMP_TEXT = [
  "{",
  "  // set di prova: i commenti vanno ignorati",
  '  "name": "Da file",',
  '  "description": "importato dal test",',
  '  "rules": [',
  '    { "action": "allow", "direction": "in", "proto": "tcp", "dport": "443" },',
  '    { "action": "deny", "direction": "in", "proto": "udp", "src": "192.0.2.5/32", "dport": "5353", "enabled": false },',
  '    { "action": "deny", "direction": "in", "proto": "any", "src": "any", "dst": "any" },',
  '    { "action": "deny", "direction": "in", "proto": "tcp", "dport": "22" }',
  "  ]",
  "}",
].join("\n");
impBtn.click(); await sleep(60);
check("pannello import aperto al posto del popup", panelOpen("panel-import") && window.document.getElementById("view").hidden);
// submit a vuoto: deve dire cosa fare, non chiamare il backend
const impForm = window.document.getElementById("import-form");
const before = calls.length;
impForm.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
await sleep(60);
check("textarea vuota rifiutata senza invocare il backend",
  !window.document.getElementById("import-error").hidden && calls.length === before,
  window.document.getElementById("import-error").textContent);
window.document.getElementById("import-text").value = IMP_TEXT;
impForm.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
await sleep(260);
check("import riuscito: dialog chiuso e toast con i conteggi",
  !panelOpen("panel-import") &&
  /Da file/.test(window.document.getElementById("toast").textContent) &&
  /\(3 regole, 1 disabilitate\)/.test(window.document.getElementById("toast").textContent),
  window.document.getElementById("toast").textContent);
check("set importato compare nella barra laterale",
  [...window.document.querySelectorAll("#rulesets li .name")].some((n) => n.textContent.includes("Da file")),
  [...window.document.querySelectorAll("#rulesets li .name")].map((n) => n.textContent).join("|"));
// il set appena importato deve essere quello selezionato (evidenziato) e la regola
// "enabled": false del file deve comparire come riga spenta, non sparita
const selNames = [...window.document.querySelectorAll("#rulesets li.selected .name")].map((n) => n.textContent).join("|");
check("il set importato risulta selezionato", selNames.includes("Da file"), `selezionato: ${selNames}`);
const offRows = [...window.document.querySelectorAll("#view tr")]
  .filter((el) => el.classList.contains("disabled") && el.textContent.includes("5353"));
check("la regola spenta del file e' una riga disabilitata del set, non sparita", offRows.length === 1,
  [...window.document.querySelectorAll("#view tr")].map((r) => r.textContent.replace(/\s+/g, " ").slice(0, 70)).join(" | "));
// JSON malformato: l'errore deve restare nel dialog, non chiudere nulla
window.document.getElementById("import-text").value = "{ rules: [ ,,, ]";
impBtn.click(); await sleep(60);
window.document.getElementById("import-text").value = "{ rules: [ ,,, ]";
window.document.getElementById("import-form").dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
await sleep(260);
check("JSON malformato: errore visibile nel pannello, che resta aperto",
  panelOpen("panel-import") &&
  !window.document.getElementById("import-error").hidden &&
  /malformato/.test(window.document.getElementById("import-error").textContent),
  window.document.getElementById("import-error").textContent);
window.document.querySelector("#panel-import [data-close]").click();
// riapre il pannello import per i controlli sul selettore di file
impBtn.click(); await sleep(60);
// "Incolla esempio" non c'e' piu': l'esempio reale e' il file examples/stealth.jsonc
// (nel pacchetto in /usr/share/doc/pyla/examples) e si carica dall'elenco dei JSONC.
check("niente checkbox ne pulsante 'Incolla esempio' nel pannello import",
  !window.document.getElementById("import-template") &&
  !/Incolla esempio/.test(window.document.getElementById("panel-import").textContent),
  window.document.getElementById("panel-import").textContent.trim().replace(/\s+/g, " ").slice(0, 70));
// Le etichette del selettore di file sono un pseudo-elemento nativo, non raggiungibile
// da applyLang(): l'unica via e' il CSS agganciato a html[lang]. Verifico che la regola
// per questa lingua esista davvero, altrimenti in EN resterebbe "Choose File" del
// toolkit o, peggio, "Scegli file" in una UI inglese.
check("etichetta selettore file definita nel CSS (Scegli file)",
  /::file-selector-button/.test(cssText) && cssText.includes('"Scegli file"'),
  (cssText.match(/[^\n]*::file-selector-button[^\n]*/g) || []).join(" | ").slice(0, 120));
// profili pubblici: github.com/pyla-dev/pyla-profiles, sempre visibili nel pannello di
// import (nessuna casella da spuntare). L'elenco si chiede a GitHub una volta per sessione.
check("profili pubblici: riquadro con titolo, nessuna casella",
  !window.document.getElementById("import-browse") &&
  !window.document.querySelector("#panel-import .import-files input[type=checkbox]") &&
  /Profili pubblici/.test(window.document.querySelector(".import-files-head")?.textContent || "") &&
  /github\.com\/pyla-dev\/pyla-profiles/.test(window.document.querySelector(".import-files-head")?.textContent || ""),
  window.document.querySelector(".import-files-head")?.textContent.trim());
check("niente piu' elenco dei file del computer",
  !/file JSONC del computer/.test(window.document.getElementById("panel-import").textContent) &&
  !calls.includes("list_import_files"), "");
const callsBefore = 0;
const impList = window.document.getElementById("import-list");
const rowIds = () => [...impList.querySelectorAll("tbody tr")].map((r) => r.dataset.id);
check("elenco profili popolato su richiesta", !impList.hidden &&
  calls.filter((c) => c === "list_profiles").length === callsBefore + 1 &&
  rowIds().join("|") === "home-server|stealth|workstation-laptop", rowIds().join("|"));
check("tabella profili nello stile CVE con intestazione Nome|Target|Rischio",
  !!impList.querySelector("table.rules.cve.profiles") &&
  [...impList.querySelectorAll("thead th")].map((t) => t.textContent).join("|") === "Nome|Target|Rischio",
  [...impList.querySelectorAll("thead th")].map((t) => t.textContent).join("|"));
check("riga profilo: nome, target e pill del rischio",
  impList.querySelector('tr[data-id="stealth"]')?.textContent.includes("Silent stealth") &&
  impList.querySelector('tr[data-id="stealth"]')?.textContent.includes("offer nothing") &&
  impList.querySelector('tr[data-id="stealth"] .pill.prio-high')?.textContent === "hard",
  impList.querySelector('tr[data-id="stealth"]')?.textContent.replace(/\s+/g, " ").slice(0, 80));
check("riquadro e altezza fissa con scroll verticale",
  window.document.querySelector(".import-files")?.contains(impList) &&
  /\.import-files\s*\{[^}]*border:\s*1px solid/.test(cssText) &&
  /\.profiles-scroll\s*\{[^}]*height:\s*\d+px;[^}]*overflow-y:\s*auto/.test(cssText),
  (cssText.match(/\.profiles-scroll\s*\{[^}]*\}/) || [""])[0].slice(0, 90));
check("profilo senza README: riga sceglibile per id",
  impList.querySelector('tr[data-id="workstation-laptop"]')?.textContent.includes("workstation-laptop"), "");
// scegliere un profilo lo scarica e lo porta nella textarea
impList.querySelector('tr[data-id="stealth"]').click(); await sleep(120);
check("scelta del profilo: contenuto caricato e riga evidenziata",
  window.document.getElementById("import-text").value.includes('"Da profilo"') &&
  impList.querySelector('tr[data-id="stealth"]').getAttribute("aria-selected") === "true",
  window.document.getElementById("import-text").value.slice(0, 40));
// freccia giu': passa al profilo successivo
impList.dispatchEvent(new window.KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true })); await sleep(120);
check("freccia giu' seleziona il profilo successivo",
  impList.querySelector('tr[data-id="workstation-laptop"]').getAttribute("aria-selected") === "true" &&
  impList.querySelector('tr[data-id="stealth"]').getAttribute("aria-selected") === "false", "");
// profilo senza "name": il nome di riserva e' l'id del profilo
impForm.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true })); await sleep(200);
check("set importato dal profilo, nome = id", !panelOpen("panel-import") &&
  txt("#toast")?.includes("workstation-laptop"), txt("#toast"));
impBtn.click(); await sleep(120);
check("riapertura: profili gia' in elenco, senza nuova richiesta e senza selezione",
  !window.document.getElementById("import-list").hidden &&
  calls.filter((c) => c === "list_profiles").length === 1 &&
  !window.document.querySelector('#import-list tr[aria-selected="true"]'),
  `list_profiles=${calls.filter((c) => c === "list_profiles").length}`);
window.document.querySelector("#panel-import [data-close]").click(); await sleep(30);


// ---------- pannelli: niente popup, e layout utilizzabile su telefono ----------
// "Annulla" del pannello import: prima del passaggio ai pannelli quel pulsante non era
// collegato a niente (closeOnButtons girava solo su dlg-rule/dlg-set), quindi il pannello
// non si chiudeva e l'utente restava bloccato. Ora e' collegato per tutti e quattro.
impBtn.click(); await sleep(60);
window.document.querySelector("#panel-import [data-close]").click(); await sleep(60);
check("Annulla del pannello import lo chiude e riporta la pagina",
  !panelOpen("panel-import") && !window.document.getElementById("view").hidden &&
  !window.document.body.classList.contains("panel-open"),
  `pannello=${panelOpen("panel-import")} vista_nascosta=${window.document.getElementById("view").hidden}`);
// Esc: la scorciatoia che la gente prova per prima; senza <dialog> niente la copre
impBtn.click(); await sleep(60); key("Escape"); await sleep(60);
check("Esc chiude il pannello import", !panelOpen("panel-import") && !window.document.getElementById("view").hidden);
// nessun modale: la barra laterale resta sempre cliccabile
impBtn.click(); await sleep(60);
check("nessun modale sopra il pannello: la barra resta cliccabile",
  panelOpen("panel-import") && window.document.querySelectorAll("dialog[open], .modal-backdrop").length === 0,
  `modali=${window.document.querySelectorAll("dialog[open], .modal-backdrop").length}`);
// le azioni della pagina sottostante non devono restare li' a comandare una vista nascosta
check("azioni della pagina nascoste mentre un pannello e' aperto",
  window.document.body.classList.contains("panel-open") &&
  /body\.panel-open \.header-actions\s*\{\s*display:\s*none/.test(cssText),
  (cssText.match(/body\.panel-open[^}]*}/) || ["nessuna regola CSS"])[0].slice(0, 60));
// cambiare pagina chiude il pannello aperto
window.document.querySelectorAll("#main-nav .nav-item")[1].click(); await sleep(90);
check("cambiare pagina chiude il pannello aperto", !panelOpen("panel-import") && !window.document.getElementById("view").hidden,
  `pannello=${panelOpen("panel-import")}`);
window.document.querySelectorAll("#main-nav .nav-item")[0].click(); await sleep(90);
// celle etichettate: il CSS mobile trasforma le righe in schede e legge data-label
const labeled = [...window.document.querySelectorAll("#view table.rules.plain td[data-label]")].map((c) => c.getAttribute("data-label"));
check("celle delle regole etichettate per la vista a schede",
  labeled.length >= 7 && labeled.includes("Azione") && labeled.includes("Destinazione"),
  [...new Set(labeled)].join("|"));
check("CSS telefono: form del regola a una colonna",
  /@media \(max-width: 820px\)[\s\S]*?\.grid \{ grid-template-columns: 1fr/.test(cssText),
  (cssText.match(/\.grid \{[^}]*\}/g) || ["nessuna"])[0].slice(0, 80));
check("CSS telefono: altezza reale della finestra (dvh)", /100dvh/.test(cssText));
check("CSS touch: campi a 16px (niente zoom) e tocchi da 40px",
  /@media \(pointer: coarse\)[\s\S]*?font-size: 16px/.test(cssText) &&
  /@media \(pointer: coarse\)[\s\S]*?min-height: 40px/.test(cssText));
check("pannello regola: i campi restano dentro il form (submit funziona)",
  (() => { const b = [...window.document.querySelectorAll("#view .toolbar button")].find((x) => x.textContent === "+ Regola"); if (b) b.click(); return true; })() &&
  (await sleep(60), panelOpen("panel-rule") &&
    !!window.document.querySelector("#rule-form select[name=action]") &&
    window.document.querySelector("#rule-form").closest("#panel-rule") !== null),
  `pannello_regola=${panelOpen("panel-rule")}`);
key("Escape"); await sleep(60);
check("Esc chiude il pannello regola", !panelOpen("panel-rule"));
// una conferma lasciata aperta non deve restare appesa: closePanel risolve la promessa
// a false, altrimenti deleteRule resta in await per sempre e non tocca UFW.
const delBtn = [...window.document.querySelectorAll("#view .toolbar button")].find((b) => b.textContent === "Elimina");
delBtn.click(); await sleep(80);
check("conferma di eliminazione aperta", panelOpen("panel-info") &&
  [...window.document.querySelectorAll("#info-actions button")].some((b) => b.textContent === "Conferma"),
  [...window.document.querySelectorAll("#info-actions button")].map((b) => b.textContent).join("|"));
const delCalls = calls.filter((c) => c === "delete_rule").length;
window.document.querySelectorAll("#main-nav .nav-item")[1].click(); await sleep(90);
check("cambiare pagina risolve la conferma senza eliminare",
  !panelOpen("panel-info") && calls.filter((c) => c === "delete_rule").length === delCalls,
  `delete_rule invocato ${calls.filter((c) => c === "delete_rule").length - delCalls} volte`);
window.document.querySelectorAll("#main-nav .nav-item")[0].click(); await sleep(90);
check("azioni pannello grandi su telefono (>=44px)",
  /\.panel \.actions button \{ flex: 1 1 40%; min-height: 44px; \}/.test(cssText));
check("sotto 820px la griglia passa a una colonna (main non collassa a 0)",
  /@media \(max-width: 820px\) \{[\s\S]{0,400}\.app \{ grid-template-columns: minmax\(0, 1fr\); \}/.test(cssText),
  (cssText.match(/\.app \{[^}]*\}/g) || ["nessuna"])[0].slice(0, 90));
check("container query sull'area utile, non sulla finestra",
  /\.main \{[^}]*container-type: inline-size/.test(cssText) && /@container \(max-width: 780px\)/.test(cssText));
check("touch e larghezza piccola nello stesso blocco CSS",
  /@media \(pointer: coarse\), \(max-width: 820px\)/.test(cssText));

narrow = false;
$$("#main-nav .nav-item")[0].click(); await sleep(60);
const tools = [...window.document.querySelectorAll("#view .toolbar button")];
check("toolbar set in vista Firewall", tools.some((b) => b.textContent === "Anteprima e applica") && tools.some((b) => b.textContent === "Comandi ufw"),
  tools.map((b) => b.textContent).join("|"));
tools.find((b) => b.textContent === "Comandi ufw").click(); await sleep(60);
check("pannello comandi ufw (non e' un popup)", panelOpen("panel-info") && txt("#info-body")?.includes("ufw allow 51820/udp"), txt("#info-body")?.slice(0,60));
$("#info-actions button:last-child").click();
check("pannello chiuso", !panelOpen("panel-info") && !window.document.getElementById("view").hidden);
[...window.document.querySelectorAll("#view .toolbar button")].find((b) => b.textContent === "Anteprima e applica").click();
await sleep(80);
check("pannello anteprima con diff", panelOpen("panel-info") && txt("#info-body")?.includes("Regole aggiunte (1)") && txt("#info-body")?.includes("ufw allow 51820/udp"), txt("#info-body")?.slice(0,80));
const applyBtn = [...$("#info-actions").children].find((b) => b.textContent === "Applica");
applyBtn.click(); await sleep(120);
check("pannello esito applicazione", panelOpen("panel-info") && txt("#info-body")?.includes("Applicato") && txt("#info-body")?.includes("ufw allow 51820/udp"), txt("#info-body")?.slice(0,80));
$("#info-actions button:last-child").click();
check("storico invalidated dopo apply", calls.filter((c) => c === "history").length === 1, "history invocato " + calls.filter((c) => c === "history").length + " volte");


// icone Google Material nei pulsanti del riquadro RULE SETS: devono esserci, non
// sovrapporsi al testo e restare entro il bottone. jsdom non fa layout (ogni
// getBoundingClientRect e' 0x0), quindi la geometria si verifica con Chrome headless;
// qui si controlla la struttura: svg inline, decorativa, accanto a uno span di testo.
const sideBtns = [...window.document.querySelectorAll(".sidebar-actions button")];
check("tre pulsanti nel riquadro set", sideBtns.length === 3 &&
  sideBtns.map((b) => b.textContent.trim()).join("|") === "Nuovo set|Importa da file|Importa da UFW",
  sideBtns.map((b) => b.textContent.trim()).join("|"));
for (const id of ["btn-new-set", "btn-import-file", "btn-import"]) {
  const b = window.document.getElementById(id);
  const svg = b && b.querySelector("svg.btn-ico");
  const span = b && b.querySelector("span");
  check(`struttura icona in #${id}`,
    !!svg && !!span && svg.getAttribute("aria-hidden") === "true" && !!svg.getAttribute("viewBox") &&
    [...svg.children].some((el) => (el.getAttribute("d") || "").length > 20) &&
    b.textContent.trim().length > 3,
    svg ? `svg con ${svg.children.length} path, testo "${b.textContent.trim()}"` : "svg mancante");
}

// icone: SVG ufficiali Material Symbols (griglia 960, viewBox "0 -960 960 960"),
// non disegni fatti a mano che le imitano
check("icone Material Symbols ufficiali nei tre pulsanti",
  ["btn-new-set", "btn-import-file", "btn-import"].every((id) =>
    window.document.querySelector(`#${id} svg.btn-ico`)?.getAttribute("viewBox") === "0 -960 960 960"),
  ["btn-new-set", "btn-import-file", "btn-import"].map((id) =>
    window.document.querySelector(`#${id} svg.btn-ico`)?.getAttribute("viewBox")).join(" | "));
// jsdom non applica la cascata: che l'attributo hidden vinca su `.rail-sub { display: flex }`
// (RULE SETS visibile fuori da Firewall) si garantisce con la regola globale nel CSS
check("[hidden] vince su ogni display del CSS",
  /\[hidden\]\s*\{\s*display:\s*none\s*!important;?\s*\}/.test(cssText), "");

console.log(out.join("\n"));
console.log("\ninvoke:", [...new Set(calls)].sort().join(", "));
console.log("errori pagina:", errors.length ? "\n  " + errors.join("\n  ") : "nessuno");
const fails = out.filter((l) => l.startsWith("FAIL"));
console.log(`${out.length - fails.length}/${out.length} check superati`);
process.exit(fails.length || errors.length ? 1 : 0);
