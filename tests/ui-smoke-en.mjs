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
window.localStorage.setItem("pyla.lang", "en");
window.localStorage.setItem("pyla.lang", "en");
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

check("[EN] nav a 6 voci", $$("#main-nav .nav-item").length === 6, $$("#main-nav .nav-label").map((e) => e.textContent).join("|"));
check("brand+versione in barra", txt(".sidebar-brand")?.includes("PYLA") && txt("#app-version") === "v" + APP_VERSION, txt("#app-version"));
const btnLang = $("#btn-lang");
check("lingua spostata nell'header (non piu' in barra)",
  !!btnLang && !!btnLang.closest(".main-header") && !btnLang.closest(".sidebar"),
  btnLang ? (btnLang.closest(".main-header") ? "header OK" : "non nell'header") : "pulsante assente");
check("lingua ultima voce a destra dell'header",
  !!btnLang && btnLang.parentElement.lastElementChild === btnLang,
  btnLang ? btnLang.parentElement.className || btnLang.parentElement.tagName : "-");
check("lingua: etichetta e titolo",
  /^EN$/.test($("#btn-lang-label")?.textContent || "") && /Lingua|Language/.test(btnLang?.title || ""),
  `${$("#btn-lang-label")?.textContent} | ${btnLang?.title}`);
check("[EN] stato fw in fondo barra", txt("#fw-status")?.includes("UFW active"), txt("#fw-status"));
check("2 set in barra", $$("#rulesets li").length === 2);
check("barra aperta all'avvio", !$("#sidebar").classList.contains("collapsed"));
check("vista firewall", $("#view").className === "view" && $("#sets-rail").hidden === false);
check("[EN] header = set selezionato", txt("#view-title") === "Default" && txt("#view-sub")?.includes("rules enabled"), `${txt("#view-title")} / ${txt("#view-sub")}`);
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
check("[EN] vista Stato UFW", txt("#view-title") === "UFW status" && txt("#view")?.includes("wg0") && txt("#view")?.includes("51820") && txt("#view")?.includes("User rules currently in UFW"), (txt("#view-title")||"") + " || " + (txt("#view")||"").slice(0,60));
check("[EN] sottotitolo Stato UFW", txt("#view-sub")?.includes("in deny") && txt("#view-sub")?.includes("1 user rules"), txt("#view-sub"));
check("[EN] pulsante Refresh", $$("#view-actions button").some((b) => b.textContent === "Refresh"));
check("set nascosti fuori da Firewall", $("#sets-rail").hidden === true);

$$("#main-nav .nav-item")[2].click(); await sleep(80);
check("[EN] vista Ruleset completo", txt("#view-title") === "Full ruleset" && txt("#view")?.includes("ufw-user-input") && txt("#view")?.includes("table ip filter"), (txt("#view")||"").slice(0,60));
check("[EN] catene vuote nascoste", !txt("#view")?.includes("blank"));
check("[EN] header tabelle", txt("#view-sub")?.includes("1 tables · 2 chains"), txt("#view-sub"));
check("[EN] verdetto colorato", !!$("#view .verdict.v-accept"), "");

$$("#main-nav .nav-item")[4].click(); await sleep(150);
check("[EN] vista CVE", txt("#view-title") === "CVE" && txt("#cve-body")?.includes("CVE-2026-98862"), (txt("#cve-body")||"").slice(0,80));
check("[EN] sottotitolo CVE", txt("#view-sub")?.includes("kernel 6.14.0-27") && txt("#view-sub")?.includes("415 from ubuntu.com"), txt("#view-sub"));
check("badge seguite in nav", $$("#main-nav .nav-item")[4].textContent.includes(String(watchState().length)), $$("#main-nav .nav-item")[4].textContent.replace(/\s+/g," "));
check("[EN] hide resolved on", $("#cve-ctl input[type=checkbox]")?.checked === true);
check("corrette nascoste", !txt("#cve-body")?.includes("CVE-2026-98433"));
check("[EN] contatore nascoste", txt("#cve-sub")?.includes("1 resolved hidden"), txt("#cve-sub"));
check("[EN] colonna mitigazione popolata", txt("#cve-body")?.includes("not in use") && !!$("#cve-body button.small"), txt("#cve-body")?.match(/non in uso[^]*/)?.[0]?.slice(0,40));
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
// La nota di mitigazione e' testo dell'advisory: in EN la struttura resta e i
// comandi dentro <pre> non vanno tradotti (PRE e' in I18N_SKIP).
check("[EN] nota mitigazione formattata", !!$("#cve-body .mit-note") &&
  $$("#cve-body .mit-note .mit-facts li b").length >= 4,
  String($$("#cve-body .mit-note .mit-facts li b").length));
const mitCmds = $$("#cve-body .mit-note pre.mit-cmd").map((p) => p.textContent).join("\n");
check("[EN] comandi non tradotti", mitCmds.includes("sudo nft -c -f /etc/cve-2026-98432.nft") &&
  mitCmds.includes("printf"), mitCmds.slice(0, 70));
// ✕ nel tab "Followed": deve togliere la riga, e il toast deve essere tradotto.
const cards = () => $$("#cve-body .cve-card");
check("[EN] due CVE seguite in vista", cards().length === 2, String(cards().length));
const cardBtn = (id, label) => cards().find((c) => c.textContent.includes(id))
  && [...cards().find((c) => c.textContent.includes(id)).querySelectorAll(".cve-head button")].find((b) => b.textContent === label);
cardBtn("CVE-2026-98435", "\u2715").click(); await sleep(120);
check("[EN] dopo la x la CVE non e' piu' in vista", !txt("#cve-body")?.includes("CVE-2026-98435") && cards().length === 1, String(cards().length));
check("[EN] toast tradotto", txt("#toast")?.includes("CVE-2026-98435 removed"), txt("#toast"));
check("[EN] contatore tab Followed scende a 1", $$(".cve-tab")[1].querySelector(".pill")?.textContent.trim() === "1", $$(".cve-tab")[1].querySelector(".pill")?.textContent);
check("[EN] etichette advisory non ritradotte", txt("#cve-body")?.includes("Blocks:") && txt("#cve-body")?.includes("Requires:"), (txt("#cve-body") || "").slice(0, 60));

// ---- Report (listening ports, like Gufw) ----
const repRows = () => $$("#report-body tbody tr");
$$("#main-nav .nav-item")[3].click(); await sleep(120);
check("[EN] vista Report", txt("#view-title") === "Report" && repRows().length === 3, `${txt("#view-title")} / ${repRows().length}`);
check("[EN] report sottotitolo", txt("#view-sub") === "3 listening \u00b7 2 reachable from the network \u00b7 your processes only", txt("#view-sub"));
check("[EN] report testate", txt("#report-body thead")?.includes("Process") && txt("#report-body thead")?.includes("Listening on") && txt("#report-body thead")?.includes("User"), txt("#report-body thead"));
check("[EN] report pulsanti", txt("#report-body")?.includes("+ Rule") && $$("#view-actions button").some((b) => b.textContent === "Show all processes"), $$("#view-actions button").map((b) => b.textContent).join("|"));
check("[EN] report pillole scope", txt("#report-body")?.includes("local only") && txt("#report-body")?.includes("all interfaces") && !/tutte|solo locale/.test(txt("#report-body")), "");
check("[EN] report nota non risolti", txt("#view")?.includes("1 port belongs to another user's process") && txt("#view")?.includes("Use + Rule to create an allow rule") && txt("#view")?.includes("the names appear with Show all processes"), "");
check("[EN] report data-label tradotto", repRows()[0].children[4].getAttribute("data-label") === "Process", repRows()[0].children[4].getAttribute("data-label"));
check("[EN] report filtro placeholder", $("#view .nft-toolbar input[type=search]")?.placeholder === "Filter (e.g. 22, udp, sshd, root)", $("#view .nft-toolbar input[type=search]")?.placeholder);

$$("#main-nav .nav-item")[5].click(); await sleep(80);
check("[EN] vista Storico", txt("#view-title") === "History" && txt("#view")?.includes("1 applies recorded") && txt("#view")?.includes("applied 2 rules"), (txt("#view")||"").slice(0,160));
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
check("panels instead of dialogs", ["panel-rule","panel-set","panel-import","panel-info"].every((i) => !!window.document.getElementById(i)) &&
  window.document.querySelectorAll("dialog").length === 0,
  `dialogs in DOM: ${window.document.querySelectorAll("dialog").length}`);

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
check("import-from-file button present", !!impBtn && !!window.document.getElementById("panel-import"),
  impBtn ? "pulsante + dialog" : "manca il pulsante");
// comments must be ignored; one UNIQUE disabled rule (must land in the set as a
// disabled row) plus a duplicate (deny tcp 22 inside the final deny "any"): the
// import drops it, like UFW does, and the mock reproduces that.
const IMP_TEXT = [
  "{",
  "  // test set: comments must be ignored",
  '  "name": "Da file",',
  '  "description": "imported by the test",',
  '  "rules": [',
  '    { "action": "allow", "direction": "in", "proto": "tcp", "dport": "443" },',
  '    { "action": "deny", "direction": "in", "proto": "udp", "src": "192.0.2.5/32", "dport": "5353", "enabled": false },',
  '    { "action": "deny", "direction": "in", "proto": "any", "src": "any", "dst": "any" },',
  '    { "action": "deny", "direction": "in", "proto": "tcp", "dport": "22" }',
  "  ]",
  "}",
].join("\n");
impBtn.click(); await sleep(60);
check("import panel open instead of a popup", panelOpen("panel-import") && window.document.getElementById("view").hidden);
const impForm = window.document.getElementById("import-form");
const beforeImp = calls.length;
impForm.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
await sleep(60);
check("empty textarea rejected without invoking backend",
  !window.document.getElementById("import-error").hidden && calls.length === beforeImp,
  window.document.getElementById("import-error").textContent);
window.document.getElementById("import-text").value = IMP_TEXT;
impForm.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
await sleep(260);
check("import succeeded: dialog closed and toast with counts",
  !panelOpen("panel-import") &&
  /Da file/.test(window.document.getElementById("toast").textContent) &&
  /\(3 rules, 1 disabled\)/.test(window.document.getElementById("toast").textContent),
  window.document.getElementById("toast").textContent);
check("imported set appears in the sidebar",
  [...window.document.querySelectorAll("#rulesets li .name")].some((n) => n.textContent.includes("Da file")),
  [...window.document.querySelectorAll("#rulesets li .name")].map((n) => n.textContent).join("|"));
// il set appena importato deve essere quello selezionato (evidenziato) e la regola
// "enabled": false del file deve comparire come riga spenta, non sparita
const selNames = [...window.document.querySelectorAll("#rulesets li.selected .name")].map((n) => n.textContent).join("|");
check("the imported set is the selected one", selNames.includes("Da file"), `selezionato: ${selNames}`);
const offRows = [...window.document.querySelectorAll("#view tr")]
  .filter((el) => el.classList.contains("disabled") && el.textContent.includes("5353"));
check("the disabled rule from the file is a disabled row of the set, not gone", offRows.length === 1,
  [...window.document.querySelectorAll("#view tr")].map((r) => r.textContent.replace(/\s+/g, " ").slice(0, 70)).join(" | "));
// JSON malformato: l'errore deve restare nel dialog, non chiudere nulla
window.document.getElementById("import-text").value = "{ rules: [ ,,, ]";
impBtn.click(); await sleep(60);
window.document.getElementById("import-text").value = "{ rules: [ ,,, ]";
window.document.getElementById("import-form").dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
await sleep(260);
check("bad JSON: error shown in the panel, which stays open",
  panelOpen("panel-import") &&
  !window.document.getElementById("import-error").hidden &&
  /malformato/.test(window.document.getElementById("import-error").textContent),
  window.document.getElementById("import-error").textContent);
window.document.querySelector("#panel-import [data-close]").click();
// reopens the import panel for the file-picker checks
impBtn.click(); await sleep(60);
// "Incolla esempio" is gone: the real example is examples/stealth.jsonc (shipped in
// /usr/share/doc/pyla/examples) and it loads from the JSONC file list.
check("no 'Incolla esempio' checkbox or button in the import panel",
  !window.document.getElementById("import-template") &&
  !/Incolla esempio/.test(window.document.getElementById("panel-import").textContent),
  window.document.getElementById("panel-import").textContent.trim().replace(/\s+/g, " ").slice(0, 70));
// Le etichette del selettore di file sono un pseudo-elemento nativo, non raggiungibile
// da applyLang(): l'unica via e' il CSS agganciato a html[lang]. Verifico che la regola
// per questa lingua esista davvero, altrimenti in EN resterebbe "Choose File" del
// toolkit o, peggio, "Scegli file" in una UI inglese.
check("[EN] etichetta selettore file definita nel CSS (Choose File)",
  /::file-selector-button/.test(cssText) && cssText.includes('"Choose File"'),
  (cssText.match(/[^\n]*::file-selector-button[^\n]*/g) || []).join(" | ").slice(0, 120));
// profili pubblici: github.com/pyla-dev/pyla-profiles, sempre visibili nel pannello di
// import (nessuna casella da spuntare). L'elenco si chiede a GitHub una volta per sessione.
check("profili pubblici: riquadro con titolo, nessuna casella",
  !window.document.getElementById("import-browse") &&
  !window.document.querySelector("#panel-import .import-files input[type=checkbox]") &&
  /Public profiles/.test(window.document.querySelector(".import-files-head")?.textContent || "") &&
  /github\.com\/pyla-dev\/pyla-profiles/.test(window.document.querySelector(".import-files-head")?.textContent || ""),
  window.document.querySelector(".import-files-head")?.textContent.trim());
check("niente piu' elenco dei file del computer",
  !/JSONC files on this computer/.test(window.document.getElementById("panel-import").textContent) &&
  !calls.includes("list_import_files"), "");
const callsBefore = 0;
const impList = window.document.getElementById("import-list");
const rowIds = () => [...impList.querySelectorAll("tbody tr")].map((r) => r.dataset.id);
check("elenco profili popolato su richiesta", !impList.hidden &&
  calls.filter((c) => c === "list_profiles").length === callsBefore + 1 &&
  rowIds().join("|") === "home-server|stealth|workstation-laptop", rowIds().join("|"));
check("tabella profili nello stile CVE con intestazione Name|Target|Risk",
  !!impList.querySelector("table.rules.cve.profiles") &&
  [...impList.querySelectorAll("thead th")].map((t) => t.textContent).join("|") === "Name|Target|Risk",
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


// ---------- panels: no popups, and a layout usable on a phone ----------
// The import panel's Cancel button used to be wired to nothing (closeOnButtons only ran
// on dlg-rule/dlg-set), so the panel never closed. Now all four are wired the same way.
impBtn.click(); await sleep(60);
window.document.querySelector("#panel-import [data-close]").click(); await sleep(60);
check("Cancel on the import panel closes it and restores the page",
  !panelOpen("panel-import") && !window.document.getElementById("view").hidden &&
  !window.document.body.classList.contains("panel-open"),
  `panel=${panelOpen("panel-import")} view_hidden=${window.document.getElementById("view").hidden}`);
// Esc: the shortcut people try first; without <dialog> nothing native covers it
impBtn.click(); await sleep(60); key("Escape"); await sleep(60);
check("Esc closes the import panel", !panelOpen("panel-import") && !window.document.getElementById("view").hidden);
// no modal at all: the sidebar stays clickable
impBtn.click(); await sleep(60);
check("no modal over the panel: the rail stays clickable",
  panelOpen("panel-import") && window.document.querySelectorAll("dialog[open], .modal-backdrop").length === 0,
  `modals=${window.document.querySelectorAll("dialog[open], .modal-backdrop").length}`);
// the page actions underneath must not stay visible driving a hidden view
check("page actions hidden while a panel is open",
  window.document.body.classList.contains("panel-open") &&
  /body\.panel-open \.header-actions\s*\{\s*display:\s*none/.test(cssText),
  (cssText.match(/body\.panel-open[^}]*}/) || ["no such CSS rule"])[0].slice(0, 60));
// switching page closes the open panel
window.document.querySelectorAll("#main-nav .nav-item")[1].click(); await sleep(90);
check("switching page closes the open panel", !panelOpen("panel-import") && !window.document.getElementById("view").hidden,
  `panel=${panelOpen("panel-import")}`);
window.document.querySelectorAll("#main-nav .nav-item")[0].click(); await sleep(90);
// labelled cells: the mobile CSS turns rows into cards reading data-label
const labeled = [...window.document.querySelectorAll("#view table.rules.plain td[data-label]")].map((c) => c.getAttribute("data-label"));
check("rule cells labelled for the card layout",
  labeled.length >= 7 && labeled.includes("Azione") && labeled.includes("Destinazione"),
  [...new Set(labeled)].join("|"));
check("phone CSS: rule form in one column",
  /@media \(max-width: 820px\)[\s\S]*?\.grid \{ grid-template-columns: 1fr/.test(cssText),
  (cssText.match(/\.grid \{[^}]*\}/g) || ["none"])[0].slice(0, 80));
check("phone CSS: real viewport height (dvh)", /100dvh/.test(cssText));
check("touch CSS: 16px inputs (no auto zoom) and 40px targets",
  /@media \(pointer: coarse\)[\s\S]*?font-size: 16px/.test(cssText) &&
  /@media \(pointer: coarse\)[\s\S]*?min-height: 40px/.test(cssText));
check("rule panel: fields stay inside the form (submit works)",
  (() => { const b = [...window.document.querySelectorAll("#view .toolbar button")].find((x) => x.textContent === "+ Rule"); if (b) b.click(); return true; })() &&
  (await sleep(60), panelOpen("panel-rule") &&
    !!window.document.querySelector("#rule-form select[name=action]") &&
    window.document.querySelector("#rule-form").closest("#panel-rule") !== null),
  `rule_panel=${panelOpen("panel-rule")}`);
key("Escape"); await sleep(60);
check("Esc closes the rule panel", !panelOpen("panel-rule"));
// una conferma lasciata aperta non deve restare appesa: closePanel risolve la promessa
// a false, altrimenti deleteSet resta in await per sempre e non tocca UFW.
const delBtn = [...window.document.querySelectorAll("#view .toolbar button")].find((b) => b.textContent === "Delete");
delBtn.click(); await sleep(80);
check("delete confirmation open", panelOpen("panel-info") &&
  [...window.document.querySelectorAll("#info-actions button")].some((b) => b.textContent === "Confirm"),
  [...window.document.querySelectorAll("#info-actions button")].map((b) => b.textContent).join("|"));
const delCalls = calls.filter((c) => c === "delete_rule").length;
window.document.querySelectorAll("#main-nav .nav-item")[1].click(); await sleep(90);
check("switching page resolves the confirmation without deleting",
  !panelOpen("panel-info") && calls.filter((c) => c === "delete_rule").length === delCalls,
  `delete_rule called ${calls.filter((c) => c === "delete_rule").length - delCalls} extra times`);
window.document.querySelectorAll("#main-nav .nav-item")[0].click(); await sleep(90);
check("panel actions are phone-sized (>=44px)",
  /\.panel \.actions button \{ flex: 1 1 40%; min-height: 44px; \}/.test(cssText));
check("sotto 820px la griglia passa a una colonna (main non collassa a 0)",
  /@media \(max-width: 820px\) \{[\s\S]{0,400}\.app \{ grid-template-columns: minmax\(0, 1fr\); \}/.test(cssText),
  (cssText.match(/\.app \{[^}]*\}/g) || ["nessuna"])[0].slice(0, 90));
check("container query sull'area utile, non sulla finestra",
  /\.main \{[^}]*container-type: inline-size/.test(cssText) && /@container \(max-width: 780px\)/.test(cssText));
check("touch and narrow width share one CSS block",
  /@media \(pointer: coarse\), \(max-width: 820px\)/.test(cssText));

narrow = false;
$$("#main-nav .nav-item")[0].click(); await sleep(60);
const tools = [...window.document.querySelectorAll("#view .toolbar button")];
check("[EN] toolbar set", tools.some((b) => b.textContent === "Preview and apply") && tools.some((b) => b.textContent === "ufw commands"),
  tools.map((b) => b.textContent).join("|"));
tools.find((b) => b.textContent === "ufw commands").click(); await sleep(60);
check("[EN] ufw commands panel (not a popup)", panelOpen("panel-info") && txt("#info-body")?.includes("ufw allow 51820/udp"), txt("#info-body")?.slice(0,60));
$("#info-actions button:last-child").click();
check("panel closed", !panelOpen("panel-info") && !window.document.getElementById("view").hidden);
[...window.document.querySelectorAll("#view .toolbar button")].find((b) => b.textContent === "Preview and apply").click();
await sleep(80);
check("preview panel with diff", panelOpen("panel-info") && txt("#info-body")?.includes("Rules added (1)") && txt("#info-body")?.includes("ufw allow 51820/udp"), txt("#info-body")?.slice(0,80));
const applyBtn = [...$("#info-actions").children].find((b) => b.textContent === "Apply");
applyBtn.click(); await sleep(120);
check("apply result panel", panelOpen("panel-info") && txt("#info-body")?.includes("Applied") && txt("#info-body")?.includes("ufw allow 51820/udp"), txt("#info-body")?.slice(0,80));
$("#info-actions button:last-child").click();
check("storico invalidated dopo apply", calls.filter((c) => c === "history").length === 1, "history invocato " + calls.filter((c) => c === "history").length + " volte");

if (window.tr) {
  console.log("tr diretto:", JSON.stringify(window.tr("applicate 2 regole")));
  console.log("tr header:", JSON.stringify(window.tr("1 applicazioni registrate")));
}
console.log("PATTERNS count:", window.PATTERNS ? window.PATTERNS.length : "n/d");

// icone Google Material nei pulsanti del riquadro RULE SETS: devono esserci, non
// sovrapporsi al testo e restare entro il bottone. jsdom non fa layout (ogni
// getBoundingClientRect e' 0x0), quindi la geometria si verifica con Chrome headless;
// qui si controlla la struttura: svg inline, decorativa, accanto a uno span di testo.
const sideBtns = [...window.document.querySelectorAll(".sidebar-actions button")];
check("tre pulsanti nel riquadro set", sideBtns.length === 3 &&
  sideBtns.map((b) => b.textContent.trim()).join("|") === "New set|Import from file|Import from UFW",
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
