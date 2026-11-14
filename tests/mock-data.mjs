// Mock dei comandi Tauri per gli smoke test della UI di PYLA.
// Mock dei comandi Tauri per gli smoke test della UI di Pyla (condiviso tra le run IT/EN).
import { readFileSync } from "node:fs";
const sys = { kernel: "6.14.0-27", release: "resolute", package: "linux", version: "6.14.0-27" };
const MIT_NOTE = "\nIPv4 TCP packet filtering:\n - Requires: nftables and root access through sudo.\n - Assumes: IPv4 options are not needed. For boot persistence,\n   /etc/nftables.conf manages the firewall, without UFW or firewalld.\n - Blocks: incoming IPv4 TCP packets that contain IP options.\n - Limit: reduces the risk but does not fully prevent exploitation.\n To apply the rule:\n  1. Create the rule file:\n     printf '%s\\n' 'table inet cve_2026_98432 {\n       chain input {\n         type filter hook input priority -310; policy accept;\n         ip protocol tcp ip hdrlength > 5 counter drop\n       }\n     }' | sudo tee /etc/cve-2026-98432.nft >/dev/null\n  2. Check and apply the rule:\n     sudo nft -c -f /etc/cve-2026-98432.nft &&\n     sudo nft -f /etc/cve-2026-98432.nft";

const MIT_DESC = "In the Linux kernel, the following vulnerability has been resolved:\naudit: fix exe mark UAF in kill_rules()\ntree is pruned. It drops entry->rule.exe before removing the rule from the\nRCU-visible filter lists.\n    BUG: KASAN: slab-use-after-free in audit_mark_compare+0x8d/0xa0";

// Versione reale del workspace: i mock non la indovinano a mano. Se restasse un valore
// fisso, il check sul numero mostrato nella UI passerebbe anche dopo un bump (gia'
// successo con 0.2.4) o fallirebbe per colpa del mock, non dell'app.
const APP_VERSION = (() => {
  // import.meta.url + fs sincrona: il file e' un modulo ESM usato dai test sotto Node.
  const here = new URL("..", import.meta.url);
  const conf = JSON.parse(readFileSync(new URL("src-tauri/tauri.conf.json", here), "utf8"));
  if (!conf.version) throw new Error("versione mancante in src-tauri/tauri.conf.json");
  return conf.version;
})();

// CVE seguibili nel mock: la seconda SENZA descrizione ne nota di mitigazione, cosi'
// i check sul box della mitigazione (che contano un solo .mit-note) restano validi.
const WATCH_POOL = {
  "CVE-2026-98862": { id: "CVE-2026-98862", title: "t", url: "u", published: "2026-11-01", verdict: "vulnerable", priority: "high", cvss3: 7.8, status: "vulnerable", fix_version: "6.14.0-28", description: MIT_DESC, mitigation: MIT_NOTE, mitigation_id: "mptcp-off", mitigation_note: "n", error: null },
  "CVE-2026-98435": { id: "CVE-2026-98435", title: "atm: fix leak", url: "u", published: "2026-10-03", verdict: "fixed", priority: "low", cvss3: 3, status: "released", fix_version: "6.14.0-20", description: "", mitigation: null, mitigation_id: null, mitigation_note: null, error: null },
};
let WATCH_IDS = ["CVE-2026-98862", "CVE-2026-98435"];
export const watchState = () => WATCH_IDS.slice();

// Set importati da file: restano visibili in list_rulesets e get_ruleset, altrimenti
// il flusso "importa da file -> seleziona il set creato" non e' provabile nei mock
// (e il bug "la riga non compare" resterebbe invisibile ai test).
const IMPORTED = new Map();
let NEXT_ID = 100;
const BASE_RULESETS = [
  { id: 1, name: "Default", description: "", rules: 3, enabled: 2, active: true },
  { id: 2, name: "Lab", description: "d", rules: 1, enabled: 1, active: false },
];
const BASE_DETAIL = [{ id: 1, name: "Default", description: "", active: true, rules: 2, enabled: 2, rules_list: [], rules: [
    { id: 11, enabled: true, action: "allow", direction: "in", interface: "wg0", proto: "udp", src: "10.0.0.0/8", sport: null, dst: "any", dport: "51820", log: "off", comment: "wireguard" },
    { id: 12, enabled: false, action: "deny", direction: "in", interface: null, proto: "tcp", src: "any", sport: null, dst: "any", dport: "23", log: "log", comment: "telnet off" },
  ] }];

const data = {
  app_info: { version: APP_VERSION, db_path: "/x/pyla.db", helper_path: "/y/pyla-helper", helper_installed: true },
  local_status: { enabled: true, defaults: { incoming: "deny", outgoing: "allow", routed: "deny" }, loglevel: "low", rules: [] },
  list_rulesets: () => [
    ...BASE_RULESETS,
    ...[...IMPORTED.values()].map((r) => ({ id: r.id, name: r.name, description: r.description, rules: r.rules.length, enabled: r.rules.filter((x) => x.enabled).length, active: false })),
  ],
  get_ruleset: ({ id }) => {
    const found = [...BASE_DETAIL, ...IMPORTED.values()].find((r) => r.id === id);
    if (!found) throw new Error(`set ${id} non trovato`);
    return found;
  },
  history: [{ ts: "2026-11-09 10:00", ruleset_name: "Default", ok: true, message: "applicate 2 regole", report: { ok: true, message: "m", log: [] } }],
  live_status: { enabled: true, defaults: { incoming: "deny", outgoing: "allow", routed: "deny" }, loglevel: "low",
    rules: [{ raw: "allow on wg0 to any port 51820", spec: { action: "allow", direction: "in", interface: "wg0", proto: "udp", src: "any", sport: null, dst: "any", dport: "51820", log: "off", comment: "" } }] },
  full_ruleset: { text: "table ip filter { ... }", tables: [{ family: "ip", name: "filter", other: [], note: null, chains: [
    { name: "ufw-user-input", owner: "ufw", hook: "input", policy: "accept", rules: [
      { text: "udp dport 51820 counter packets 12 bytes 1200 accept", packets: 12, bytes: 1200 },
      { text: "tcp dport 23 counter packets 0 bytes 0 drop", packets: 0, bytes: 0 },
    ] },
    { name: "blank", owner: "kernel", hook: null, policy: null, rules: [] },
  ] }] },
  mitigation_states: { checks: [{ id: "mptcp-off", label: "Disattiva MPTCP", state: "non-in-uso", configured: false, actionable: true, impact: "i", facts: ["a = b"] }],
    listeners: [{ addr: "0.0.0.0", port: "8723", family: 4, scope: "tutte" }] },
  // Watch list DI STATO: riproduce il flusso reale (setting cve_watch -> cve_watched
  // legge quella lista), per poter verificare che la ✕ tolga davvero la riga.
  cve_watched: () => ({ items: WATCH_IDS.map((i) => WATCH_POOL[i]).filter(Boolean), system: sys }),
  cve_kernel: { system: sys, total: 415, updated_at: 1762000000, items: [
    { id: "CVE-2026-98862", title: "MPTCP flaw", url: "u", published: "2026-11-01", verdict: "vulnerable", priority: "high", cvss3: 7.8, status: "vulnerable", fix_version: "6.14.0-28", description: MIT_DESC, mitigation: MIT_NOTE, mitigation_id: "mptcp-off", mitigation_note: "n", error: null },
    { id: "CVE-2026-98433", title: "fixed one", url: "u", published: "2026-10-02", verdict: "fixed", priority: "low", cvss3: 3, status: "fixed", fix_version: null, description: MIT_DESC, mitigation: null, mitigation_id: null, mitigation_note: null, error: null },
  ] },
  // report porte in ascolto: senza root il socket di avahi resta senza processo,
  // con privileged (helper) compare anche lui
  listening_report: ({ privileged } = {}) => ({
    privileged: !!privileged,
    unresolved: privileged ? 0 : 1,
    sockets: [
      { proto: "tcp", family: 4, addr: "0.0.0.0", port: 22, scope: "tutte", uid: 0, user: "root", inode: 1, pid: 800, process: "sshd", cmdline: "sshd: /usr/sbin/sshd -D" },
      { proto: "tcp", family: 4, addr: "127.0.0.1", port: 631, scope: "locale", uid: 0, user: "root", inode: 2, pid: 42, process: "cupsd", cmdline: "/usr/sbin/cupsd -l" },
      { proto: "udp", family: 4, addr: "0.0.0.0", port: 5353, scope: "tutte", uid: 104, user: "avahi", inode: 3,
        pid: privileged ? 610 : null, process: privileged ? "avahi-daemon" : null, cmdline: null },
    ],
  }),
  exposure_check: [{ addr: "0.0.0.0", port: "8723", family: 4, verdict: "bloccata", detail: "regola ufw" }],
  // come cve_watch_set in main.rs: trim + maiuscole, formato CVE-AAAA-NNNNN,
  // poi "togli e rimetti in testa" e restituzione della lista intera
  cve_watch_set: ({ id, watch }) => {
    const canon = String(id || "").trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,8}$/.test(canon)) throw new Error(`identificativo non valido: ${JSON.stringify(id)} (formato CVE-AAAA-NNNNN)`);
    WATCH_IDS = WATCH_IDS.filter((x) => x !== canon);
    if (watch) WATCH_IDS = [canon, ...WATCH_IDS];
    return WATCH_IDS.slice();
  },
  // list_profiles / read_profile: specchio di profiles.rs. Il backend legge l'albero di
  // github.com/pyla-dev/pyla-profiles e scarica profiles/<id>/profile.jsonc; la UI passa
  // solo l'id, mai un URL. Un id non valido viene rifiutato come nel backend.
  list_profiles: () => [
    { id: "home-server", size: 3540, name: "Home server", risk: "hard",
      target: "a small Ubuntu server at home that must expose exactly SSH and HTTPS" },
    { id: "stealth", size: 6999, name: "Silent stealth", risk: "hard",
      target: "machines that should offer nothing and confirm nothing" },
    // README non leggibile: campi vuoti, la riga resta sceglibile per id
    { id: "workstation-laptop", size: 2756, name: "", target: "", risk: "" },
  ],
  read_profile: ({ id }) => {
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id || "")) throw new Error(`profilo non valido: ${id}`);
    if (id === "workstation-laptop") return String.raw`{
  // profilo senza "name": il nome di riserva e' l'id
  "rules": [ { "action": "allow", "direction": "in", "proto": "tcp", "dport": "22" } ]
}`;
    return String.raw`{
  // profilo dal repository (stessa forma di examples/stealth.jsonc)
  "name": "Da profilo",
  "rules": [
    { "action": "deny", "direction": "in", "proto": "any", "comment": "silenziosa" },
    { "action": "allow", "direction": "in", "proto": "tcp", "dport": "443", "enabled": false, "comment": "spenta dal file" }
  ]
}`;
  },
  // import_file: specchio minimale di pyla_core::import per gli smoke test. Le regole
  // con "enabled": false restano nel set ma spente (non spariscono), come nel DB reale.
  import_file: ({ text, fallbackName }) => {
    const stripped = String(text).replace(/\/\/[^\n]*/g, "");
    let doc;
    try { doc = JSON.parse(stripped); } catch { throw new Error("file non valido: JSON malformato"); }
    if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error("file non valido: serve un oggetto JSONC");
    if (!Array.isArray(doc.rules)) throw new Error('campo "rules": deve essere una lista di regole');
    const name = typeof doc.name === "string" && doc.name.trim() ? doc.name.trim() : String(fallbackName || "Set importato");
    let id;
    IMPORTED.set((id = NEXT_ID++), {
      id, name, description: typeof doc.description === "string" ? doc.description : "", active: false,
      rules: doc.rules.map((r, i) => ({ id: id * 100 + i + 1, position: i + 1, enabled: r.enabled !== false, ...r })),
    });
    // lo stato per-regola va normalizzato come fa RuleSpec nel backend (dst "any"
    // viene riempito), cosi' la UI del set importato renderizza senza buchi
    const norm = (r) => ({ direction: r.direction || "in", action: r.action, proto: r.proto ?? "any",
      interface: r.interface ?? null, src: r.src ?? "any", sport: r.sport ?? null,
      dst: r.dst ?? "any", dport: r.dport ?? null, log: r.log ?? "off", comment: r.comment ?? "",
      family: r.family ?? "both" });
    const off = (r) => r.enabled === false || doc.enabled === false;
    // duplicati come pyla_core::import: identita' strutturale senza commento, la
    // seconda copia si scarta perche' in UFW la prima regola vince gia'. Le regole
    // spente non entrano nel conto dei duplicati (non sono nell'insieme attivo).
    // profilo canonizzato come RuleSpec nel backend: proto "any" copre ogni porta, quindi
    // una regola senza porte e senza dst scritto contiene quella con la porta (il caso di
    // `ufw deny 22/tcp` dentro un deny su proto any). Il commento non conta.
    const profile = (r) => {
      const proto = String(r.proto ?? "any").toLowerCase();
      const portless = (p) => p == null || p === "" || p === "any";
      return JSON.stringify([String(r.action).toLowerCase(), (r.direction || "in").toLowerCase(),
        r.interface ?? null, proto, (r.src ?? "any") || "any", r.sport ?? null,
        (r.dst ?? "any") || "any", portless(r.dport) ? null : r.dport, portless(r.proto) && r.proto == null]);
    };
    const seen = new Set();
    const kept = [];
    let dupes = 0;
    doc.rules.forEach((r) => {
      if (!off(r)) {
        const k = profile(r);
        if (seen.has(k)) { dupes++; return; }
        seen.add(k);
      }
      kept.push(r);
    });
    const rules = kept.map((r, i) => ({ id: id * 100 + i + 1, position: i + 1, enabled: !off(r), ...norm(r) }));
    IMPORTED.get(id).rules = rules;
    const on = rules.filter((r) => r.enabled).length;
    return { id, name, rules: on, disabled: rules.length - on, duplicates: dupes };
  },
  set_rule_enabled: null, move_rule: null,
};

export { data, sys, APP_VERSION };
