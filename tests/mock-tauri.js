// Mock di window.__TAURI__ per aprire la UI di PYLA in un browser normale
// ( screenshot / prova layout ). Non fa parte dell'app: solo preview.
const q = new URLSearchParams(location.search);
const sys = { kernel: "6.14.0-27-generic", release: "resolute", package: "linux", version: "6.14.0-27-generic" };
const R = (r) => new Promise((res) => setTimeout(() => res(r), 120));
const rules = [
  { id: 11, enabled: true, action: "allow", direction: "in", interface: "wg0", proto: "udp", src: "10.0.0.0/8", sport: null, dst: "any", dport: "51820", log: "off", comment: "wireguard" },
  { id: 12, enabled: true, action: "deny", direction: "in", interface: null, proto: "tcp", src: "any", sport: null, dst: "any", dport: "23", log: "log", comment: "telnet spento" },
  { id: 13, enabled: false, action: "reject", direction: "in", interface: "br0", proto: "tcp", src: "192.0.2.0/24", sport: null, dst: "any", dport: "6000:6007", log: "off", comment: "libvirt vnc" },
];
const MIT_NOTE = "\nIPv4 TCP packet filtering:\n - Requires: nftables and root access through sudo.\n - Assumes: IPv4 options are not needed. For boot persistence,\n   /etc/nftables.conf manages the firewall, without UFW or firewalld.\n - Blocks: incoming IPv4 TCP packets that contain IP options.\n - Limit: reduces the risk but does not fully prevent exploitation.\n To apply the rule:\n  1. Create the rule file:\n     printf '%s\\n' 'table inet cve_2026_98432 {\n       chain input {\n         type filter hook input priority -310; policy accept;\n         ip protocol tcp ip hdrlength > 5 counter drop\n       }\n     }' | sudo tee /etc/cve-2026_98432.nft >/dev/null\n  2. Check and apply the rule:\n     sudo nft -c -f /etc/cve-2026_98432.nft &&\n     sudo nft -f /etc/cve-2026_98432.nft";
const MIT_DESC = "In the Linux kernel, the following vulnerability has been resolved:\naudit: fix exe mark UAF in kill_rules()\nkill_rules() removes mixed AUDIT_DIR and AUDIT_EXE rules when an audit\ntree is pruned. It drops entry->rule.exe before removing the rule from the\nRCU-visible filter lists.\nAfter a rule has been installed with AUDIT_ADD_RULE, which requires\nCAP_AUDIT_CONTROL, removing the watched directory can race with another\ntask that is still evaluating the rule.\n    BUG: KASAN: slab-use-after-free in audit_mark_compare+0x8d/0xa0";
const cve = (id, verdict, prio, cvss, fix, title, mit) => ({ id, verdict, priority: prio, cvss3: cvss, status: verdict === "fixed" ? "released" : "needs-triage", fix_version: fix, title, published: "2026-11-02", url: "https://ubuntu.com/security/" + id, description: MIT_DESC, mitigation: mit ? MIT_NOTE : null, mitigation_id: mit ? "mptcp-off" : null, mitigation_note: mit ? "Nota di mitigazione." : null, error: null });
// Nella preview da browser non c'e' filesystem: la versione arriva da ?v=NN.NN.N (lo
// script di preview la passa), altrimenti si segna che e' finta invece di mostrare un
// numero che potrebbe essere vecchio.
const APP_VERSION = q.get("v") || "0.0.0-preview";

// CVE seguibili nella preview: la watch list e' a stato, come il DB dell'app reale.
const WATCH_POOL = {};
let WATCH_IDS = [];

// le due seguite di partenza sono le stesse due righe dell'elenco ubuntu.com
WATCH_POOL["CVE-2026-98862"] = cve("CVE-2026-98862", "vulnerable", "high", 7.8, "6.14.0-28", "MPTCP: uso dopo free in multipath", true);
WATCH_POOL["CVE-2026-98435"] = cve("CVE-2026-98435", "not-affected", "negligible", 1.0, null, "atm: fix leak", false);
WATCH_IDS = ["CVE-2026-98862", "CVE-2026-98435"];

// set importati via import_file restano visibili nelle liste: senza questo il flusso
// "importa da file -> seleziona il set creato" nei mock non mostrerebbe nulla.
const IMPORTED = new Map();
let NEXT_ID = 100;
const BASE_RULESETS = [
  { id: 1, name: "Laptop", description: "set quotidiano del portatile", rules: 3, enabled: 2, active: true, updated_at: "2026-11-09 09:12" },
  { id: 2, name: "Lab KVM", description: "lab libvirt con bridge", rules: 6, enabled: 5, active: false, updated_at: "2026-11-08 18:04" },
  { id: 3, name: "Vuoto", description: "", rules: 0, enabled: 0, active: false, updated_at: "2026-11-01 08:00" },
];
const BASE_RULESETS_DETAIL = [{ id: 1, name: "Laptop", description: "set quotidiano del portatile", active: true, rules }];

const data = {
  app_info: { version: APP_VERSION, db_path: "~/.local/share/space.pyla.app/pyla.db", helper_path: "/usr/local/libexec/pyla/pyla-helper", helper_installed: true },
  local_status: { enabled: true, defaults: { incoming: "deny", outgoing: "allow", routed: "deny" }, loglevel: "low", rules },
  // liste a stato come il DB reale: i set importati da file devono comparire, e
  // get_ruleset deve rispondere anche a loro (dopo l'import la UI seleziona il set)
  list_rulesets: () => [
    ...BASE_RULESETS,
    ...[...IMPORTED.values()].map((r) => ({ id: r.id, name: r.name, description: r.description, rules: r.rules.length, enabled: r.rules.filter((x) => x.enabled).length, active: false, updated_at: r.updated_at })),
  ],
  get_ruleset: ({ id }) => {
    const found = [...BASE_RULESETS_DETAIL, ...IMPORTED.values()].find((r) => r.id === id);
    if (!found) throw new Error(`set ${id} non trovato`);
    return found;
  },
  history: [
    { ts: "2026-11-09 09:12", ruleset_name: "Laptop", ok: true, message: "applicate 3 regole", report: { ok: true, message: "applicate 3 regole", log: [{ ok: true, command: "ufw allow 51820/udp", output: "" }], backup: "/tmp/ufw-2026-11-09.bak" } },
    { ts: "2026-11-08 18:04", ruleset_name: "Lab KVM", ok: false, message: "errore: regole non allineate", report: { ok: false, message: "dopo l'applicazione le regole in UFW non coincidono", log: [{ ok: false, command: "ufw deny 23/tcp", output: "ERROR: invalid position" }] } },
  ],
  live_status: { enabled: true, defaults: { incoming: "deny", outgoing: "allow", routed: "deny" }, loglevel: "low", rules: [
    { raw: "allow in on wg0 to any port 51820", spec: rules[0] }, { raw: "deny in to any port 23", spec: rules[1] },
    { raw: "route deny from 198.51.100.0/24", spec: null },
  ] },
  full_ruleset: { text: "# nft list ruleset\ntable ip filter {\n}\n", tables: [
    { family: "ip", name: "filter", note: null, other: [], chains: [
      { name: "ufw-user-input", owner: "ufw", hook: "input", policy: "accept", rules: [
        { text: "iifname \"wg0\" udp dport 51820 counter packets 1824 bytes 214356 accept", packets: 1824, bytes: 214356 },
        { text: "tcp dport 23 counter packets 41 bytes 2460 drop", packets: 41, bytes: 2460 },
        { text: "ip saddr 192.0.2.0/24 tcp dport 6000:6007 counter packets 0 bytes 0 reject", packets: 0, bytes: 0 },
      ] },
      { name: "ufw-user-output", owner: "ufw", hook: "output", policy: "accept", rules: [{ text: "ct state related,established counter packets 9123 bytes 1200441 accept", packets: 9123, bytes: 1200441 }] },
      { name: "docker-output", owner: "docker", hook: null, policy: null, rules: [] },
    ] },
    { family: "ip6", name: "filter", note: null, other: ["chain ufw6-user-input { policy accept; }"], chains: [
      { name: "ufw6-user-input", owner: "ufw", hook: "input", policy: "drop", rules: [{ text: "meta l4proto ipv6-icmp icmpv6 type nd-neighbor-solicitation counter packets 12 bytes 984 accept", packets: 12, bytes: 984 }] },
    ] },
  ] },
  mitigation_states: { checks: [
    { id: "mptcp-off", label: "Disattiva MPTCP", state: "esposta", configured: false, actionable: true, impact: "Riduce il rischio, non lo elimina.", facts: ["net.mptcp.enabled = 1", "modulo tcp_multipath: caricato"] },
    { id: "sctp-block", label: "Blocca il modulo sctp", state: "mitigata", configured: true, actionable: true, impact: "Il protocollo SCTP non è più disponibile." , facts: ["modulo sctp: non caricato (si carica da solo alla prima richiesta)", "caricamento bloccato: sì"] },
  ], listeners: [
    { addr: "0.0.0.0", port: "8723", family: 4, scope: "tutte" },
    { addr: "127.0.0.53", port: "53", family: 4, scope: "locale" },
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
  exposure_check: [
    { addr: "0.0.0.0", port: "8723", family: 4, verdict: "bloccata", detail: "nessuna regola corrisponde; policy drop di ip filter ufw-user-input", per_family: [{ family: 4, verdict: "bloccata" }, { family: 6, verdict: "aperta" }] },
  ],
  cve_watched: () => ({ system: sys, items: WATCH_IDS.map((i) => WATCH_POOL[i]).filter(Boolean) }),
  cve_kernel: { system: sys, total: 415, updated_at: 1762686000, items: [
    cve("CVE-2026-98862", "vulnerable", "high", 7.8, "6.14.0-28", "MPTCP: uso dopo free in multipath", true),
    cve("CVE-2026-98863", "update", "medium", 6.5, "6.14.0-28", "io_uring: out of bounds in IORING_OP_...", false),
    cve("CVE-2026-98434", "fixed", "low", 3.3, null, "tipc: null pointer dereference", false),
    cve("CVE-2026-98435", "not-affected", "negligible", 1.0, null, "atm: fix leak", false),
  ] },
  // come cve_watch_set in main.rs: trim + maiuscole, formato CVE-AAAA-NNNNN,
  // poi "togli e rimetti in testa" e restituzione della lista intera
  cve_watch_set: ({ id, watch }) => {
    const canon = String(id || "").trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,8}$/.test(canon)) throw new Error(`identificativo non valido: ${JSON.stringify(id)} (formato CVE-AAAA-NNNNN)`);
    WATCH_IDS = WATCH_IDS.filter((x) => x !== canon);
    if (watch) WATCH_IDS = [canon, ...WATCH_IDS];
    return WATCH_IDS.slice();
  },
  // set creati a mano restano visibili e selezionabili, come nel DB reale
  create_ruleset: ({ name }) => {
    const id = NEXT_ID++;
    IMPORTED.set(id, { id, name, description: "", active: false, updated_at: "2026-11-11 12:00", rules: [] });
    return id;
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
  // import_file: parser minimale FEDELE al backend (pyla_core::import) per i smoke
  // test. Tiene lo stato: il set importato compare in list_rulesets e get_ruleset,
  // come succede davvero dopo l'insert in DB.
  import_file: ({ text, fallbackName }) => {
    const stripped = String(text).replace(/\/\/[^\n]*/g, "");
    let doc;
    try { doc = JSON.parse(stripped); } catch (e) { throw new Error("file non valido: JSON malformato"); }
    if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error("file non valido: serve un oggetto JSONC");
    if (!Array.isArray(doc.rules)) throw new Error('campo "rules": deve essere una lista di regole');
    const name = (typeof doc.name === "string" && doc.name.trim()) ? doc.name.trim() : String(fallbackName || "Set importato");
    const off = (r) => r.enabled === false || doc.enabled === false;
    // duplicati come pyla_core::import: stessa identita' strutturale senza commento,
    // la seconda copia si scarta (in UFW la prima regola vince gia')
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
    doc.rules.forEach((r) => {
      if (!off(r)) {
        const k = profile(r);
        if (seen.has(k)) return;
        seen.add(k);
      }
      kept.push(r);
    });
    // lo stato per-regola si normalizza come RuleSpec nel backend (dst "any" riempito)
    const norm = (r) => ({ direction: r.direction || "in", action: r.action, proto: r.proto ?? "any",
      interface: r.interface ?? null, src: r.src ?? "any", sport: r.sport ?? null,
      dst: r.dst ?? "any", dport: r.dport ?? null, log: r.log ?? "off", comment: r.comment ?? "",
      family: r.family ?? "both" });
    let id;
    const rules = kept.map((r, i) => ({ id: (id = id ?? NEXT_ID++) * 100 + i + 1, position: i + 1, enabled: !off(r), ...norm(r) }));
    IMPORTED.set(id, { id, name, description: typeof doc.description === "string" ? doc.description : "",
      active: false, updated_at: "2026-11-11 12:00", rules });
    const enabled = rules.filter((r) => r.enabled).length;
    return { id, name, rules: enabled, disabled: rules.length - enabled };
  },
  set_rule_enabled: null, move_rule: null,
  preview: { status: null, plan: { in_sync: false, unsupported: [], removed: [], added: [rules[2]], reordered: false, desired: rules }, commands: ["ufw allow in on wg0 to any port 51820 proto udp", "ufw deny in any to any 23/tcp log"] },
  apply: { ok: true, message: "applicate 3 regole", log: [{ ok: true, command: "ufw --force reset", output: "" }, { ok: true, command: "ufw allow in on wg0 to any port 51820 proto udp", output: "Rules updated" }], backup: "/tmp/ufw-2026-11-09.bak" },
  ruleset_commands: ["ufw allow in on wg0 to any port 51820 proto udp", "ufw deny in any to any 23/tcp log", "ufw reject in on br0 from 192.0.2.0/24 to any 6000:6007/tcp"],
};
const calls = [];
window.__TAURI__ = {
  core: { invoke: async (cmd, args) => { calls.push(cmd); if (!(cmd in data)) throw new Error("mock mancante: " + cmd); return R(typeof data[cmd] === "function" ? data[cmd](args) : data[cmd]); } },
  event: { listen: async () => () => {} },
};
window.__calls = calls;
// parametri di anteprima: ?view=cve&lang=en&collapsed=1
if (q.get("lang") === "en") localStorage.setItem("pyla.lang", "en");
if (q.get("collapsed") === "1") localStorage.setItem("pyla.rail.collapsed", "1");
if (q.get("view")) localStorage.setItem("pyla.view", q.get("view"));
