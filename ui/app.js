"use strict";

const invoke = window.__TAURI__.core.invoke;
// "cve-refreshed": il backend aggiorna la cache in background e avvisa quando ha finito.
const listenEvent = (window.__TAURI__?.event?.listen) || (() => Promise.resolve(() => {}));

const state = {
  info: null,
  status: null,
  rulesets: [],
  selected: null, // Ruleset completo
};

// ---------- utilità ----------

const $ = (sel) => document.querySelector(sel);

// ---------- lingue (IT di default, EN opzionale) ----------
// I testi IT sono scritti nel codice; il dizionario li traduce sul DOM quando la
// lingua è EN (esatto + pattern per le frasi con valori dinamici). Il toggle ricarica.

const LANG = localStorage.getItem("pyla.lang") === "en" ? "en" : "it";
const EXACT = {};
const PATTERNS = [
  [/^entrata (.+) · uscita (.+) · inoltro (.+)$/, "in $1 · out $2 · fwd $3"],
  [/^(\d+)\/(\d+) regole abilitate$/, "$1/$2 rules enabled"],
  [/^Applica «(.+)»$/, 'Apply "$1"'],
  [/^Regole tolte da UFW \((\d+)\)$/, "Rules removed from UFW ($1)"],
  [/^Regole aggiunte \((\d+)\)$/, "Rules added ($1)"],
  [/^Comandi che verranno eseguiti \((\d+)\)$/, "Commands to be run ($1)"],
  [/^(\d+) regole$/, "$1 rules"],
  [/· ([\d.,]+) pacchetti$/, "· $1 packets"],
  [/^(\d+) catene$/, "$1 chains"],
  [/^(\d+) di (\d+)$/, "$1 of $2"],
  [/^Kernel (.+): CVE aperte high\/critical su (.+)$/, "Kernel $1: open high/critical CVEs on $2"],
  [/^nessuno stato Ubuntu per (.+) su (.+)$/, "No Ubuntu status for $1 on $2"],
  [/^(.+) su (.+): (.+) \(installata (.+)\)$/, "$1 on $2: $3 (installed $4)"],
  [/→ corretta in (.+)/, "→ fixed in $1"],
  [/^Ordina per (.+)$/, "Sort by $1"],
  [/^Eliminare il set «(.+)»\?$/, 'Delete ruleset "$1"?'],
  [/^Comandi ufw di «(.+)»$/, 'ufw commands of "$1"'],
  [/^Annullare «(.+)»\?$/, 'Undo "$1"?'],
  [/^(CVE-\d{4}-\d+(\/.*)?) seguita$/, "$1 followed"],
  [/^(CVE-\d{4}-\d+(\/.*)?) rimossa$/, "$1 removed"],
  [/Rimuovile con ufw o Gufw prima di applicare:/, "Remove them with ufw or Gufw before applying:"],
  [/^Il set non ha regole abilitate: in UFW resteranno solo le policy di default/, "The set has no enabled rules: UFW will keep only the default policies"],
  [/ \(entrata: (.+)\)\.$/, " (incoming: $1)."],
  [/^Copia delle regole precedenti: (.+)$/, "Previous rules backup: $1"],
  [/ La mitigazione resta attiva dopo il riavvio finché non la annulli\. Serve l'autenticazione\.$/, " The mitigation stays active after reboot until you undo it. Authentication required."],
  [/^Helper non installato \((.*)\): puoi preparare i set, ma per leggere o applicare le regole esegui una volta (.+) dalla cartella del progetto\.$/,
    "Helper not installed ($1): you can prepare sets, but to read or apply rules run once $2 from the project folder."],
  [/ \(copia\)$/, " (copy)"],
  [/^Porte TCP in ascolto fuori dal loopback \((\d+)\):$/, "TCP ports listening outside loopback ($1):"],
  [/^(.*) — condizioni non valutate: (.+)$/, "$1 — conditions not evaluated: $2"],
  [/^in ascolto solo su loopback: non raggiungibile dalla rete$/, "listening on loopback only: not reachable from the network"],
  [/^nessuna regola corrisponde; policy drop di (.+)$/, "no rule matches; drop policy of $1"],
  [/^nessuna catena con hook input nel ruleset$/, "no chain with input hook in the ruleset"],
  [/^nessuna regola intercetta il traffico e tutte le catene input hanno policy accept$/, "no rule intercepts the traffic; all input chains have accept policy"],
];

Object.assign(EXACT, {
  // ---- exposure check (pillole verdetto e pulsante) ----
  "Verifica col firewall": "Check against firewall",
  "Verifica…": "Checking…",
  "aperta": "open",
  "condizionata": "conditional",
  "bloccata": "blocked",
  "ignota": "unknown",
  "locale": "local",
  "tutte": "all addresses",
  "indirizzo": "specific address",
});

Object.assign(EXACT, {
  // ---- index.html (cornice, form regola/set) ----
  "Stato UFW": "UFW status",
  "Legge le regole presenti ora in UFW (chiede l'autenticazione)": "Reads the rules currently in UFW (asks for authentication)",
  "Ruleset completo": "Full ruleset",
  "Tutte le tabelle e catene del kernel (UFW, Docker, libvirt…), in sola lettura": "All kernel tables and chains (UFW, Docker, libvirt…), read-only",
  "Vulnerabilità del kernel Ubuntu in uso (Ubuntu Security API)": "Ubuntu kernel vulnerabilities (Ubuntu Security API)",
  "Storico": "History",
  "Lingua / Language": "Language / Lingua",
  "Set di regole": "Rule sets",
  "Nuovo set": "New set",
  "Importa da UFW": "Import from UFW",
  "Crea un set con le regole presenti ora in UFW": "Create a set from the rules currently in UFW",
  "Seleziona un set o creane uno nuovo.": "Select a set or create a new one.",
  "Per partire dalle regole attuali usa": "To start from the current rules use",
  "Regola": "Rule",
  "Azione": "Action",
  "allow — consenti": "allow — permit",
  "deny — scarta": "deny — drop",
  "reject — rifiuta": "reject — reject",
  "limit — consenti con limite": "limit — rate-limited",
  "Direzione": "Direction",
  "in — entrata": "in — inbound",
  "out — uscita": "out — outbound",
  "Interfaccia": "Interface",
  "tutte": "all",
  "Protocollo": "Protocol",
  "tutti": "any",
  "Sorgente": "Source",
  "Porta sorgente": "Source port",
  "Destinazione": "Destination",
  "Porta destinazione": "Destination port",
  "nessuno": "none",
  "nuove connessioni": "new connections",
  "tutti i pacchetti": "all packets",
  "Abilitata": "Enabled",
  "Commento": "Comment",
  "Annulla": "Cancel",
  "Salva": "Save",
  "Nome": "Name",
  "Descrizione": "Description",
});

Object.assign(EXACT, {
  // ---- barra superiore / stato ----
  "stato sconosciuto": "unknown status",
  "UFW attivo": "UFW active",
  "UFW disattivato": "UFW inactive",
  "Disattiva firewall": "Turn firewall off",
  "Attiva firewall": "Turn firewall on",
  // ---- sidebar / dettaglio set ----
  "applicato": "applied",
  "+ Regola": "+ Rule",
  "Rinomina": "Rename",
  "Duplica": "Duplicate",
  "Comandi ufw": "ufw commands",
  "Elimina": "Delete",
  "Anteprima e applica": "Preview and apply",
  "Dir.": "Dir.",
  "Proto": "Proto",
  "Nessuna regola. Con un set vuoto UFW applica solo le policy di default.": "No rules. With an empty set UFW applies only the default policies.",
  "Disabilita": "Disable",
  "Abilita": "Enable",
  "Su": "Up",
  "Giù": "Down",
  "Modifica": "Edit",
  "L'ordine conta: UFW applica la prima regola che corrisponde.": "Order matters: UFW applies the first matching rule.",
  "Le regole disabilitate restano nel set ma non vengono scritte in UFW.": "Disabled rules stay in the set but are not written to UFW.",
  "Le modifiche diventano effettive solo con «Anteprima e applica».": "Changes take effect only with \"Preview and apply\".",
  "Eliminare la regola?": "Delete this rule?",
  "Modifica regola": "Edit rule",
  "Nuova regola": "New rule",
  "Nuovo set di regole": "New rule set",
  "Rinomina set": "Rename set",
  "Duplica set": "Duplicate set",
  "È il set applicato: le regole in UFW restano come sono, ma Pyla non lo considererà più attivo.": "This is the applied set: UFW rules stay as they are, but Pyla will no longer consider it active.",
  "Le regole in UFW non vengono toccate.": "UFW rules are left untouched.",
  "Autenticazione…": "Authenticating…",
  "Regole importate da UFW": "Rules imported from UFW",
  // ---- dialog generici / applica ----
  "Conferma": "Confirm",
  "Chiudi": "Close",
  "Lettura UFW…": "Reading UFW…",
  "In UFW ci sono regole che Pyla non sa gestire (route o per applicazione).": "UFW contains rules Pyla cannot manage (route or application rules).",
  "UFW contiene già esattamente queste regole, nello stesso ordine. Niente da fare.": "UFW already contains exactly these rules, in the same order. Nothing to do.",
  "Le regole sono le stesse ma cambia l'ordine.": "Same rules, different order.",
  "UFW riscrive tutte le regole utente nell'ordine del set. Le connessioni già aperte non cadono.": "UFW rewrites all user rules in set order. Already-open connections are not dropped.",
  "Prima di modificare viene salvata una copia delle regole; se qualcosa va storto viene ripristinata.": "A backup of the rules is saved before applying; if something fails, it is restored.",
  "Applica": "Apply",
  "Applicato": "Applied",
  "Applicazione non riuscita": "Apply failed",
  "Applicazione…": "Applying…",
  "Esito dei comandi": "Command results",
  // ---- stato reale / storico ----
  "Regole presenti ora in UFW": "Rules currently in UFW",
  "Stato": "Status",
  "attivo": "active",
  "disattivato": "inactive",
  "Policy": "Policy",
  "Nessuna regola utente.": "No user rules.",
  "non gestita": "not managed",
  "Sono solo le regole utente di UFW. Le regole di before.rules, Docker e libvirt non compaiono qui.": "These are only UFW user rules. before.rules, Docker and libvirt rules are not shown here.",
  "(nessuna regola)": "(no rules)",
  "Copiato": "Copied",
  "Copia": "Copy",
  "Storico applicazioni": "Apply history",
  "Nessuna applicazione registrata.": "No apply recorded.",
  "Quando": "When",
  "Set": "Set",
  "Esito": "Result",
  "Messaggio": "Message",
  "errore": "error",
  "dettagli": "details",
  "Disattivare il firewall?": "Turn the firewall off?",
  "Tutte le regole e le policy di UFW smettono di essere applicate: ogni porta in ascolto diventa raggiungibile dalla rete.": "All UFW rules and policies stop being applied: every listening port becomes reachable from the network.",
  "Disattiva": "Turn off",
  "Firewall attivato": "Firewall enabled",
  "Firewall disattivato": "Firewall disabled",
  // ---- ruleset completo (nft) ----
  "Ruleset completo del kernel": "Full kernel ruleset",
  "Sola lettura: tutto ciò che il firewall applica, incluse le regole di before.rules, Docker e libvirt.": "Read-only: everything the firewall applies, including before.rules, Docker and libvirt rules.",
  "I contatori partono dall'ultimo caricamento delle regole. Le righe grigie non hanno mai trovato pacchetti.": "Counters start from the last rules load. Grey rows have never matched packets.",
  "Filtra (es. 192.0.2.6, dport 22, docker)": "Filter (e.g. 192.0.2.6, dport 22, docker)",
  "tutte le catene": "all chains",
  "solo ufw": "ufw only",
  "solo docker": "docker only",
  "solo libvirt": "libvirt only",
  "solo kernel": "kernel only",
  "nascondi catene vuote": "hide empty chains",
  "Aggiorna": "Refresh",
  "Copia testo": "Copy text",
  "Pacchetti": "Packets",
  "Catena vuota.": "Empty chain.",
  "Nessuna corrispondenza.": "No matches.",
  // ---- CVE ----
  "Vulnerabilità Ubuntu": "Ubuntu vulnerabilities",
  "Seguite": "Followed",
  "Nessuna CVE seguita.": "No CVEs followed.",
  "Carica altre 20": "Load 20 more",
  "Segui CVE": "Follow CVE",
  "Segui": "Follow",
  "seguita": "followed",
  "Filtra elenco (es. tcp, mptcp, sctp)": "Filter list (e.g. tcp, mptcp, sctp)",
  "Caricamento…": "Loading…",
  "Caricamento da ubuntu.com…": "Loading from ubuntu.com…",
  "Priorità": "Priority",
  "priorità": "priority",
  "Correzione": "Fix",
  "correzione": "fix",
  "Titolo": "Title",
  "titolo": "title",
  "Mitigazione": "Mitigation",
  "mitigazione": "mitigation",
  "stato": "status",
  "mitigata": "mitigated",
  "mitigata al riavvio": "mitigated on reboot",
  "esposta": "exposed",
  "in uso": "in use",
  "non in uso": "not in use",
  "Mitiga": "Mitigate",
  "Annulla mitigazione": "Undo mitigation",
  "Verifica:": "Check:",
  "Effetto:": "Effect:",
  "vulnerabile": "vulnerable",
  "corretta: aggiorna": "fixed: update",
  "corretta": "fixed",
  "non affetto": "not affected",
  "stato ignoto": "unknown status",
  "Mitigazione Ubuntu:": "Ubuntu mitigation:",
  "Descrizione completa": "Full description",
  "Non seguire più": "Unfollow",
  "Il sottosistema torna disponibile. Serve l'autenticazione.": "The subsystem becomes available again. Authentication required.",
});

Object.assign(EXACT, {
  // ---- messaggi del backend (helper / mitigazioni) ----
  "Disattiva MPTCP": "Disable MPTCP",
  "Disattiva io_uring": "Disable io_uring",
  "Blocca il modulo sctp": "Block sctp module",
  "Blocca il modulo tipc": "Block tipc module",
  "Blocca il modulo rds": "Block rds module",
  "Blocca il modulo atm": "Block atm module",
  "Blocca il modulo l2tp": "Block l2tp module",
  "Blocca il modulo can": "Block can module",
  "Blocca il server SMB del kernel (ksmbd)": "Block kernel SMB server (ksmbd)",
  "Blocca il server NFS (nfsd)": "Block NFS server (nfsd)",
  "Blocca il Bluetooth": "Block Bluetooth",
  "Uso di KVM": "KVM usage",
  "Le applicazioni che chiedono Multipath TCP usano TCP normale. Su un portatile non si nota.": "Apps requesting Multipath TCP use plain TCP. Unnoticeable on a laptop.",
  "I programmi che usano io_uring (alcuni database, QEMU, runtime async) falliscono o ripiegano su un'altra interfaccia. I processi già avviati non cambiano.": "Programs using io_uring (some databases, QEMU, async runtimes) fail or fall back to another interface. Already-running processes are unchanged.",
  "Il protocollo SCTP non è più disponibile (usato solo da telefonia/WebRTC lato server).": "The SCTP protocol is no longer available (only used by server-side telephony/WebRTC).",
  "Il protocollo TIPC (cluster) non è più disponibile.": "The TIPC protocol (cluster) is no longer available.",
  "Il protocollo RDS (Oracle/InfiniBand) non è più disponibile.": "The RDS protocol (Oracle/InfiniBand) is no longer available.",
  "Il supporto ATM (vecchi modem DSL) non è più disponibile.": "ATM support (old DSL modems) is no longer available.",
  "Le VPN L2TP/IPsec smettono di funzionare (WireGuard non è toccato).": "L2TP/IPsec VPNs stop working (WireGuard is untouched).",
  "Il bus CAN (automotive/industriale) non è più disponibile.": "The CAN bus (automotive/industrial) is no longer available.",
  "Il server SMB nel kernel non è più disponibile. Samba e l'accesso a share SMB non sono toccati.": "The in-kernel SMB server is no longer available. Samba and SMB client access are untouched.",
  "Questa macchina non può più esportare cartelle via NFS. Montare share NFS altrui funziona ancora.": "This machine can no longer export folders via NFS. Mounting others' NFS shares still works.",
  "IL BLUETOOTH SMETTE DI FUNZIONARE (cuffie, mouse, tastiere). Se il modulo è in uso l'effetto completo arriva al riavvio.": "BLUETOOTH STOPS WORKING (headphones, mice, keyboards). If the module is in use, full effect comes at reboot.",
  "Sfruttabile solo da codice che gira dentro una VM KVM avviata da questa macchina.": "Exploitable only by code running inside a KVM VM started on this machine.",
  "UFW è già allineato al set: nessuna modifica": "UFW already matches the set: no changes",
  "dopo l'applicazione le regole in UFW non coincidono con il set": "after applying, UFW rules do not match the set",
});

// Le frasi del helper con id/etichette dinamiche.
PATTERNS.push(
  [/^applicate (\d+) regole$/, "applied $1 rules"],
  [/^(.*): ripristinate le regole precedenti$/, "$1: previous rules restored"],
  [/ripristino fallito \((.*)\), backup in (.*)$/, "restore failed ($1), backup at $2"],
  [/: effettiva al prossimo riavvio$/, ": effective on next reboot"],
  [/: attiva$/, ": active"],
  [/: rimossa$/, ": removed"],
  // fatti delle mitigazioni (mitigation.rs) e cache CVE
  [/^(\S+) = non presente$/, "$1 = not present"],
  [/^modulo (\S+): caricato$/, "module $1: loaded"],
  [/^modulo (\S+): non caricato \(si carica da solo alla prima richiesta\)$/, "module $1: not loaded (loads automatically on first use)"],
  [/^caricamento bloccato: sì$/, "loading blocked: yes"],
  [/^caricamento bloccato: no$/, "loading blocked: no"],
  [/^VM KVM\/libvirt avviate: (\d+)$/, "running KVM/libvirt VMs: $1"],
  [/^· dati ubuntu\.com del (.+)$/, "· ubuntu.com data from $1"],
  [/^entrata (.+), uscita (.+), inoltro (.+)$/, "in $1, out $2, fwd $3"],
  // ---- errori e messaggi del backend (db, helper, validazione, piano, esposizione) ----
  [/^risposta di ubuntu\.com non valida: /, "invalid response from ubuntu.com: "],
  [/^nome già usato \((.*)\)$/, "name already used ($1)"],
  [/^il database è di una versione più recente di Pyla \(schema (\d+)\)$/, "the database is from a newer Pyla version (schema $1)"],
  [/^set (\d+) non trovato$/, "set $1 not found"],
  [/^regola (\d+) non trovata$/, "rule $1 not found"],
  [/^helper non installato in (\S+): esegui /, "helper not installed in $1: run "],
  [/^avvio di pkexec: /, "starting pkexec: "],
  [/^invio all'helper: /, "sending to helper: "],
  [/^attesa dell'helper: /, "waiting for helper: "],
  [/^risposta non valida dall'helper \(uscita (.*?)\):/, "invalid response from helper (exit $1):"],
  [/^risposta dell'helper: /, "helper response: "],
  [/^l'helper installato in (\S+) è più vecchio dell'app e non conosce (`[^`]*`): ricompila \((`[^`]*`)\) e reinstalla con /,
    "the helper installed in $1 is older than the app and does not know $2: rebuild ($3) and reinstall with "],
  [/^lettura configurazione UFW: /, "reading UFW configuration: "],
  [/^lettura stato UFW: /, "reading UFW status: "],
  [/^lettura stdin: /, "reading stdin: "],
  [/^operazione interrotta: /, "operation aborted: "],
  [/^Importato da UFW \((\d+) regole non gestite escluse\)$/, "Imported from UFW ($1 unmanaged rules skipped)"],
  [/^identificativo non valido: (.*) \(formato CVE-AAAA-NNNNN\)$/, "invalid identifier: $1 (format CVE-YYYY-NNNNN)"],
  [/^mitigazione sconosciuta: /, "unknown mitigation: "],
  [/^comando sconosciuto: (.*) \(/, "unknown command: $1 ("],
  [/^richiesta non valida: /, "invalid request: "],
  [/^troppe regole \(massimo (\d+)\)$/, "too many rules (max $1)"],
  [/^backup di (\S+): /, "backup of $1: "],
  [/^ripristino di (\S+): /, "restore of $1: "],
  [/^avvio di (\S+): /, "starting $1: "],
  [/^in UFW ci sono regole che Pyla non gestisce, rimuovile prima con ufw o Gufw: /,
    "UFW has rules Pyla does not manage, remove them first with ufw or Gufw: "],
  [/^un comando ufw non è riuscito/, "a ufw command failed"],
  [/^dopo l'applicazione le regole in UFW non coincidono con il set/, "after applying, UFW rules do not match the set"],
  [/^ufw reload dopo il ripristino non riuscito/, "ufw reload after restore failed"],
  [/^(\S+) è solo una verifica$/, "$1 is a check only"],
  [/^modulo (\S+) in uso, non scaricato \((.*)\): bloccato dal prossimo riavvio$/, "module $1 in use, not unloaded ($2): blocked from next reboot"],
  [/^interfaccia non valida: /, "invalid interface: "],
  [/^indirizzo non valido: /, "invalid address: "],
  [/^porte non valide: /, "invalid ports: "],
  [/^commento non valido: più di (\d+) caratteri$/, "invalid comment: more than $1 characters"],
  [/^commento non valido: caratteri di controllo$/, "invalid comment: control characters"],
  [/^le regole (\d+) e (\d+) sono uguali \(UFW salterebbe la seconda\)$/, "rules $1 and $2 are identical (UFW would skip the second)"],
  [/^nessuna regola corrisponde; policy drop di (\S+)$/, "no rule matches; drop policy of $1"],
  [/ — condizioni non valutate: /, " — conditions not evaluated: "],
);

Object.assign(EXACT, {
  "percorso database non impostato": "database path not set",
  "release Ubuntu non determinabile": "cannot determine Ubuntu release",
  "nessun dato da ubuntu.com": "no data from ubuntu.com",
  "il nome del set è obbligatorio": "the set name is required",
  "autenticazione annullata": "authentication cancelled",
  "autenticazione negata o helper non autorizzato da polkit": "authentication denied or helper not authorized by polkit",
  "database bloccato": "database locked",
  "Importato da UFW": "Imported from UFW",
  "pyla-helper va avviato come root (tramite pkexec)": "pyla-helper must run as root (via pkexec)",
  "mitigazione scritta ma non applicata subito: vedi dettagli": "mitigation written but not applied immediately: see details",
  "sorgente e destinazione devono essere entrambe IPv4 o entrambe IPv6": "source and destination must both be IPv4 or both IPv6",
  "con più porte o un intervallo va scelto il protocollo tcp o udp": "with multiple ports or a range, choose protocol tcp or udp",
  "lo stato reale non contiene le regole (serve root)": "the live status does not include the rules (root required)",
  "in ascolto solo su loopback: non raggiungibile dalla rete": "listening on loopback only: not reachable from the network",
  "nessuna catena con hook input nel ruleset": "no chain with an input hook in the ruleset",
  "nessuna regola intercetta il traffico e tutte le catene input hanno policy accept":
    "no rule catches the traffic and all input chains have policy accept",
  "Riduce il rischio, non lo elimina: l'errore è nel TCP IPv4 e l'exploit dimostrato passa da un listener MPTCP. Conta anche chi può raggiungere le porte TCP IPv4 in ascolto (vedi sotto e regole UFW). La correzione vera è il kernel aggiornato.":
    "Reduces the risk, does not remove it: the bug is in IPv4 TCP and the demonstrated exploit goes through an MPTCP listener. Who can reach the listening IPv4 TCP ports also matters (see below and UFW rules). The real fix is the updated kernel.",
});

Object.assign(EXACT, {
  "Caricamento dalla cache locale…": "Loading from local cache…",
  "Cache CVE vuota: primo scaricamento da ubuntu.com in corso, la lista si popolerà a breve.":
    "CVE cache empty: first download from ubuntu.com in progress, the list will fill in shortly.",
});

/** Traduce una stringa IT in EN (identità per l'italiano o per testi non in dizionario). */
function tr(s) {
  if (LANG !== "en" || !s) return s;
  const t = s.trim();
  if (!t) return s;
  let out = EXACT[t];
  if (out === undefined) {
    out = t;
    for (const [re, rep] of PATTERNS) out = out.replace(re, rep);
    // "<etichetta IT>: <resto>" (es. "Blocca il modulo sctp: effettiva al prossimo riavvio")
    const i = out.indexOf(": ");
    if (i > 0 && EXACT[out.slice(0, i)] !== undefined) out = EXACT[out.slice(0, i)] + out.slice(i);
    if (out === t) return s;
  }
  return s.replace(t, out);
}

const I18N_SKIP = new Set(["SCRIPT", "STYLE"]);

/** Sostituisce nei nodi di testo e negli attributi titolo/placeholder del sottoalbero. */
function applyLang(root) {
  if (LANG !== "en") return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = walker.nextNode())) {
    const p = n.parentElement;
    if (!p || I18N_SKIP.has(p.tagName)) continue;
    const v = tr(n.nodeValue);
    if (v !== n.nodeValue) n.nodeValue = v;
  }
  if (root.nodeType !== Node.ELEMENT_NODE) return;
  const els = [root, ...root.querySelectorAll("[title], [placeholder], [aria-label]")];
  for (const el of els) {
    for (const a of ["title", "placeholder", "aria-label"]) {
      const v = el.getAttribute(a);
      if (!v) continue;
      const t = tr(v);
      if (t !== v) el.setAttribute(a, t);
    }
  }
}

document.documentElement.lang = LANG;

// Ogni nodo aggiunto al DOM (render, dialog, toast) passa dalla traduzione.
new MutationObserver((muts) => {
  if (LANG !== "en") return;
  for (const m of muts) {
    for (const node of m.addedNodes) {
      if (node.nodeType === Node.TEXT_NODE) {
        const v = tr(node.nodeValue);
        if (v !== node.nodeValue) node.nodeValue = v;
      } else if (node.nodeType === Node.ELEMENT_NODE) {
        applyLang(node);
      }
    }
  }
}).observe(document.body, { childList: true, subtree: true });

function toggleLang() {
  localStorage.setItem("pyla.lang", LANG === "it" ? "en" : "it");
  location.reload();
}

$("#btn-lang").addEventListener("click", toggleLang);
$("#btn-lang-label").textContent = LANG.toUpperCase();
applyLang(document.body);

/** Crea un elemento: h("td", {class: "x", onclick: fn}, "testo", altroNodo) */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

let toastTimer;
function toast(msg, bad = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = bad ? "toast bad" : "toast";
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), bad ? 7000 : 3500);
}

async function call(cmd, args) {
  try {
    return await invoke(cmd, args);
  } catch (e) {
    toast(String(e), true);
    throw e;
  }
}

/** Esegue fn disabilitando il bottone, che mostra `busyText` nel frattempo. */
async function busy(button, busyText, fn) {
  const old = button.textContent;
  button.disabled = true;
  button.textContent = busyText;
  try {
    return await fn();
  } finally {
    button.disabled = false;
    button.textContent = old;
  }
}

function closeOnButtons(dlg) {
  dlg.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => dlg.close()));
}

function ep(addr, port) {
  return port ? `${addr} : ${port}` : addr;
}

function ruleCells(s) {
  return [
    h("td", {}, h("span", { class: `act-${s.action}` }, s.action), s.log !== "off" ? " ✎" : ""),
    h("td", {}, s.direction),
    h("td", {}, s.interface || "—"),
    h("td", {}, s.proto === "any" ? "tutti" : s.proto),
    h("td", { class: "mono" }, ep(s.src, s.sport)),
    h("td", { class: "mono" }, ep(s.dst, s.dport)),
    h("td", { class: "comment", title: s.comment || "" }, s.comment || ""),
  ];
}

function ruleText(s) {
  let t = `${s.action} ${s.direction}`;
  if (s.interface) t += ` on ${s.interface}`;
  if (s.proto !== "any") t += ` ${s.proto}`;
  t += ` da ${ep(s.src, s.sport)} a ${ep(s.dst, s.dport)}`;
  if (s.comment) t += `  # ${s.comment}`;
  return t;
}

// ---------- intestazione: stato firewall ----------

function renderStatus() {
  const st = state.status;
  const box = $("#fw-status");
  box.replaceChildren();
  if (!st) {
    box.append(h("span", { class: "pill muted" }, "stato sconosciuto"));
    return;
  }
  box.append(
    h("span", { class: `pill ${st.enabled ? "ok" : "bad"}` }, st.enabled ? "UFW attivo" : "UFW disattivato"),
    h("span", {}, `entrata ${st.defaults.incoming} · uscita ${st.defaults.outgoing} · inoltro ${st.defaults.routed}`)
  );
  const btn = $("#btn-toggle-fw");
  btn.textContent = st.enabled ? "Disattiva firewall" : "Attiva firewall";
  btn.className = st.enabled ? "danger" : "primary";
}

async function loadStatus() {
  try {
    state.status = await invoke("local_status");
  } catch (e) {
    state.status = null;
    toast(String(e), true);
  }
  renderStatus();
}

// ---------- sidebar ----------

function renderRulesets() {
  const ul = $("#rulesets");
  ul.replaceChildren(
    ...state.rulesets.map((r) =>
      h(
        "li",
        {
          class: state.selected && state.selected.id === r.id ? "selected" : "",
          onclick: () => selectRuleset(r.id),
        },
        h("div", { class: "name" }, r.name, r.active ? h("span", { class: "pill ok" }, "applicato") : null),
        h("div", { class: "meta" }, `${r.enabled}/${r.rules} regole abilitate`)
      )
    )
  );
}

async function loadRulesets() {
  state.rulesets = await call("list_rulesets");
  renderRulesets();
}

async function selectRuleset(id) {
  state.selected = await call("get_ruleset", { id });
  renderRulesets();
  renderDetail();
}

async function refreshSelected() {
  await loadRulesets();
  if (state.selected) await selectRuleset(state.selected.id);
}

// ---------- dettaglio set ----------

function renderDetail() {
  const rs = state.selected;
  const box = $("#detail");
  if (!rs) {
    box.replaceChildren(
      h("div", { class: "empty" }, "Seleziona un set o creane uno nuovo.", h("br"),
        "Per partire dalle regole attuali usa ", h("b", {}, "Importa da UFW"), ".")
    );
    return;
  }

  const head = h(
    "div",
    { class: "detail-head" },
    h(
      "div",
      { class: "title" },
      h("h1", {}, rs.name, rs.active ? h("span", { class: "pill ok" }, "applicato") : null),
      rs.description ? h("p", {}, rs.description) : null
    ),
    h(
      "div",
      { class: "toolbar" },
      h("button", { onclick: () => editRule(null) }, "+ Regola"),
      h("button", { class: "ghost", onclick: editSet }, "Rinomina"),
      h("button", { class: "ghost", onclick: duplicateSet }, "Duplica"),
      h("button", { class: "ghost", onclick: showCommands }, "Comandi ufw"),
      h("button", { class: "ghost danger", onclick: deleteSet }, "Elimina"),
      h("button", { class: "primary", onclick: (ev) => previewApply(ev.currentTarget) }, "Anteprima e applica")
    )
  );

  let body;
  if (rs.rules.length === 0) {
    body = h("div", { class: "empty" }, "Nessuna regola. Con un set vuoto UFW applica solo le policy di default.");
  } else {
    body = h(
      "table",
      { class: "rules" },
      h(
        "thead",
        {},
        h("tr", {},
          h("th", {}, ""), h("th", {}, "#"), h("th", {}, "Azione"), h("th", {}, "Dir."),
          h("th", {}, "Interfaccia"), h("th", {}, "Proto"), h("th", {}, "Sorgente"),
          h("th", {}, "Destinazione"), h("th", {}, "Commento"), h("th", {}, ""))
      ),
      h(
        "tbody",
        {},
        rs.rules.map((r, i) =>
          h(
            "tr",
            { class: r.enabled ? "" : "disabled", ondblclick: () => editRule(r) },
            h(
              "td",
              { class: "ctl" },
              h(
                "label",
                { class: "switch", title: r.enabled ? "Disabilita" : "Abilita" },
                h("input", {
                  type: "checkbox",
                  checked: r.enabled,
                  onchange: async (ev) => {
                    await call("set_rule_enabled", { id: r.id, enabled: ev.target.checked });
                    await refreshSelected();
                  },
                }),
                h("span")
              )
            ),
            h("td", { class: "num" }, i + 1),
            ...ruleCells(r),
            h(
              "td",
              { class: "ctl" },
              h("button", { class: "icon", title: "Su", disabled: i === 0, onclick: () => move(r, -1) }, "↑"),
              h("button", { class: "icon", title: "Giù", disabled: i === rs.rules.length - 1, onclick: () => move(r, 1) }, "↓"),
              h("button", { class: "icon", title: "Modifica", onclick: () => editRule(r) }, "✎"),
              h("button", { class: "icon", title: "Elimina", onclick: () => deleteRule(r) }, "✕")
            )
          )
        )
      )
    );
  }

  box.replaceChildren(
    head,
    body,
    h("p", { class: "hint" },
      "L'ordine conta: UFW applica la prima regola che corrisponde. ",
      "Le regole disabilitate restano nel set ma non vengono scritte in UFW. ",
      "Le modifiche diventano effettive solo con «Anteprima e applica».")
  );
}

async function move(rule, delta) {
  await call("move_rule", { id: rule.id, delta });
  await refreshSelected();
}

async function deleteRule(rule) {
  const ok = await confirmDialog("Eliminare la regola?", ruleText(rule));
  if (!ok) return;
  await call("delete_rule", { id: rule.id });
  await refreshSelected();
}

// ---------- editor regola ----------

let editingRule = null;

function editRule(rule) {
  editingRule = rule;
  const f = $("#rule-form");
  const s = rule || {
    enabled: true, action: "allow", direction: "in", interface: "", proto: "tcp",
    src: "any", sport: "", dst: "any", dport: "", log: "off", comment: "",
  };
  $("#rule-title").textContent = rule ? "Modifica regola" : "Nuova regola";
  for (const k of ["action", "direction", "interface", "proto", "src", "sport", "dst", "dport", "log", "comment"]) {
    f.elements[k].value = s[k] ?? "";
  }
  f.elements.enabled.checked = rule ? rule.enabled : true;
  $("#rule-error").hidden = true;
  $("#dlg-rule").showModal();
  f.elements.src.focus();
}

$("#rule-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const v = (k) => f.elements[k].value.trim();
  const opt = (k) => v(k) || null;
  const rule = {
    id: editingRule ? editingRule.id : null,
    enabled: f.elements.enabled.checked,
    action: v("action"),
    direction: v("direction"),
    interface: opt("interface"),
    log: v("log"),
    proto: v("proto"),
    src: v("src") || "any",
    sport: opt("sport"),
    dst: v("dst") || "any",
    dport: opt("dport"),
    comment: opt("comment"),
  };
  try {
    await invoke("save_rule", { rulesetId: state.selected.id, rule });
  } catch (e) {
    const err = $("#rule-error");
    err.textContent = String(e);
    err.hidden = false;
    return;
  }
  $("#dlg-rule").close();
  await refreshSelected();
});

// ---------- set: crea / rinomina / duplica / elimina ----------

/** Apre il dialog nome/descrizione; `save(name, description)` può lanciare un errore. */
function setDialog(title, name, description, save) {
  const f = $("#set-form");
  $("#set-title").textContent = title;
  f.elements.name.value = name;
  f.elements.description.value = description;
  $("#set-error").hidden = true;
  f.onsubmit = async (ev) => {
    ev.preventDefault();
    try {
      await save(f.elements.name.value, f.elements.description.value);
      $("#dlg-set").close();
    } catch (e) {
      $("#set-error").textContent = String(e);
      $("#set-error").hidden = false;
    }
  };
  $("#dlg-set").showModal();
  f.elements.name.focus();
}

function newSet() {
  setDialog("Nuovo set di regole", "", "", async (name, description) => {
    const id = await invoke("create_ruleset", { name, description, copyFrom: null });
    await loadRulesets();
    await selectRuleset(id);
  });
}

function editSet() {
  const rs = state.selected;
  setDialog("Rinomina set", rs.name, rs.description, async (name, description) => {
    await invoke("update_ruleset", { id: rs.id, name, description });
    await refreshSelected();
  });
}

function duplicateSet() {
  const rs = state.selected;
  setDialog("Duplica set", `${rs.name} (copia)`, rs.description, async (name, description) => {
    const id = await invoke("create_ruleset", { name, description, copyFrom: rs.id });
    await loadRulesets();
    await selectRuleset(id);
  });
}

async function deleteSet() {
  const rs = state.selected;
  const extra = rs.active
    ? "È il set applicato: le regole in UFW restano come sono, ma Pyla non lo considererà più attivo."
    : "Le regole in UFW non vengono toccate.";
  if (!(await confirmDialog(`Eliminare il set «${rs.name}»?`, extra))) return;
  await call("delete_ruleset", { id: rs.id });
  state.selected = null;
  await loadRulesets();
  renderDetail();
}

async function importLive(button) {
  const name = `UFW ${new Date().toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" })}`;
  await busy(button, "Autenticazione…", async () => {
    const id = await call("import_live", { name });
    await loadRulesets();
    await selectRuleset(id);
    toast("Regole importate da UFW");
  });
}

// ---------- dialog generico ----------

function infoDialog(content, buttons) {
  $("#info-body").replaceChildren(...[content].flat());
  $("#info-actions").replaceChildren(...buttons);
  const dlg = $("#dlg-info");
  if (!dlg.open) dlg.showModal();
}

function confirmDialog(title, text, okLabel = "Conferma", okClass = "primary") {
  return new Promise((resolve) => {
    const dlg = $("#dlg-info");
    const done = (v) => {
      dlg.removeEventListener("close", onClose);
      dlg.close();
      resolve(v);
    };
    const onClose = () => resolve(false);
    dlg.addEventListener("close", onClose, { once: true });
    infoDialog(
      [h("h3", {}, title), text ? h("p", {}, text) : null],
      [
        h("button", { class: "ghost", onclick: () => done(false) }, "Annulla"),
        h("button", { class: okClass, onclick: () => done(true) }, okLabel),
      ]
    );
  });
}

const closeButton = () => h("button", { onclick: () => $("#dlg-info").close() }, "Chiudi");

// ---------- anteprima e applicazione ----------

async function previewApply(button) {
  const rs = state.selected;
  const pv = await busy(button, "Lettura UFW…", () => call("preview", { rulesetId: rs.id }));
  state.status = { ...pv.status, rules: null };
  renderStatus();
  const p = pv.plan;

  const parts = [h("h3", {}, `Applica «${rs.name}»`)];
  if (p.unsupported.length) {
    parts.push(
      h("p", { class: "error" },
        "In UFW ci sono regole che Pyla non sa gestire (route o per applicazione). ",
        "Rimuovile con ufw o Gufw prima di applicare:\n" + p.unsupported.join("\n"))
    );
    infoDialog(parts, [closeButton()]);
    return;
  }
  if (p.in_sync) {
    parts.push(h("p", {}, "UFW contiene già esattamente queste regole, nello stesso ordine. Niente da fare."));
    infoDialog(parts, [closeButton()]);
    if (!rs.active) {
      // allineato ma non segnato come attivo: lo segna applicando (no-op lato UFW)
      await call("apply", { rulesetId: rs.id });
      await refreshSelected();
    }
    return;
  }

  if (p.removed.length) {
    parts.push(h("div", { class: "section" }, `Regole tolte da UFW (${p.removed.length})`),
      h("ul", { class: "diff" }, p.removed.map((s) => h("li", { class: "del mono" }, "− " + ruleText(s)))));
  }
  if (p.added.length) {
    parts.push(h("div", { class: "section" }, `Regole aggiunte (${p.added.length})`),
      h("ul", { class: "diff" }, p.added.map((s) => h("li", { class: "add mono" }, "+ " + ruleText(s)))));
  }
  if (p.reordered) parts.push(h("p", {}, "Le regole sono le stesse ma cambia l'ordine."));
  if (p.desired.length === 0) {
    parts.push(h("p", { class: "error" },
      "Il set non ha regole abilitate: in UFW resteranno solo le policy di default " +
      `(entrata: ${pv.status.defaults.incoming}).`));
  }
  parts.push(
    h("div", { class: "section" }, `Comandi che verranno eseguiti (${pv.commands.length})`),
    h("pre", { class: "cmds mono" }, pv.commands.join("\n")),
    h("p", { class: "hint" },
      "UFW riscrive tutte le regole utente nell'ordine del set. Le connessioni già aperte non cadono. ",
      "Prima di modificare viene salvata una copia delle regole; se qualcosa va storto viene ripristinata.")
  );

  infoDialog(parts, [
    h("button", { class: "ghost", onclick: () => $("#dlg-info").close() }, "Annulla"),
    h("button", { class: "primary", onclick: (ev) => doApply(ev.currentTarget, rs) }, "Applica"),
  ]);
}

async function doApply(button, rs) {
  let report;
  try {
    report = await busy(button, "Applicazione…", () => call("apply", { rulesetId: rs.id }));
  } catch {
    return;
  }
  showReport(report);
  await loadStatus();
  await refreshSelected();
}

function showReport(report) {
  const parts = [
    h("h3", {}, report.ok ? "Applicato" : "Applicazione non riuscita"),
    h("p", { class: report.ok ? "" : "error" }, report.message),
  ];
  if (report.log && report.log.length) {
    parts.push(
      h("div", { class: "section" }, "Esito dei comandi"),
      h("pre", { class: "cmds mono" },
        report.log.map((l) => h("div", { class: l.ok ? "ok" : "bad" }, `${l.ok ? "✓" : "✗"} ${l.command}`,
          l.ok ? null : h("div", {}, l.output))))
    );
  }
  if (report.backup) parts.push(h("p", { class: "hint" }, `Copia delle regole precedenti: ${report.backup}`));
  infoDialog(parts, [closeButton()]);
}

// ---------- stato reale, comandi, storico ----------

async function showLive(button) {
  const st = await busy(button, "Autenticazione…", () => call("live_status"));
  state.status = { ...st, rules: null };
  renderStatus();
  const rules = st.rules || [];
  const parts = [
    h("h3", {}, "Regole presenti ora in UFW"),
    h("dl", { class: "kv" },
      h("dt", {}, "Stato"), h("dd", {}, st.enabled ? "attivo" : "disattivato"),
      h("dt", {}, "Policy"), h("dd", {}, `entrata ${st.defaults.incoming}, uscita ${st.defaults.outgoing}, inoltro ${st.defaults.routed}`),
      h("dt", {}, "Log"), h("dd", {}, st.loglevel || "—")),
  ];
  if (!rules.length) {
    parts.push(h("p", {}, "Nessuna regola utente."));
  } else {
    parts.push(
      h("table", { class: "rules" },
        h("thead", {}, h("tr", {}, h("th", {}, "#"), h("th", {}, "Azione"), h("th", {}, "Dir."), h("th", {}, "Interfaccia"),
          h("th", {}, "Proto"), h("th", {}, "Sorgente"), h("th", {}, "Destinazione"), h("th", {}, "Commento"))),
        h("tbody", {},
          rules.map((r, i) =>
            r.spec
              ? h("tr", {}, h("td", { class: "num" }, i + 1), ...ruleCells(r.spec))
              : h("tr", {}, h("td", { class: "num" }, i + 1),
                  h("td", { colspan: 7, class: "mono" }, h("span", { class: "pill warn" }, "non gestita"), " ", r.raw))
          )))
    );
  }
  parts.push(h("p", { class: "hint" },
    "Sono solo le regole utente di UFW. Le regole di before.rules, Docker e libvirt non compaiono qui."));
  infoDialog(parts, [closeButton()]);
}

async function showCommands() {
  const cmds = await call("ruleset_commands", { id: state.selected.id });
  const text = cmds.join("\n");
  infoDialog(
    [
      h("h3", {}, `Comandi ufw di «${state.selected.name}»`),
      h("pre", { class: "cmds mono" }, text || "(nessuna regola)"),
    ],
    [
      h("button", {
        class: "ghost",
        onclick: async () => {
          await navigator.clipboard.writeText(text);
          toast("Copiato");
        },
      }, "Copia"),
      closeButton(),
    ]
  );
}

async function showHistory() {
  const rows = await call("history", { limit: 50 });
  const parts = [h("h3", {}, "Storico applicazioni")];
  if (!rows.length) parts.push(h("p", {}, "Nessuna applicazione registrata."));
  else
    parts.push(
      h("table", { class: "rules" },
        h("thead", {}, h("tr", {}, h("th", {}, "Quando"), h("th", {}, "Set"), h("th", {}, "Esito"), h("th", {}, "Messaggio"), h("th", {}, ""))),
        h("tbody", {},
          rows.map((r) =>
            h("tr", {},
              h("td", { class: "mono" }, r.ts),
              h("td", {}, r.ruleset_name),
              h("td", {}, h("span", { class: `pill ${r.ok ? "ok" : "bad"}` }, r.ok ? "ok" : "errore")),
              h("td", {}, r.message),
              h("td", { class: "ctl" }, h("button", { class: "icon", onclick: () => showReport(r.report) }, "dettagli"))
            ))))
    );
  infoDialog(parts, [closeButton()]);
}

async function toggleFirewall(button) {
  const on = !(state.status && state.status.enabled);
  if (!on) {
    const ok = await confirmDialog(
      "Disattivare il firewall?",
      "Tutte le regole e le policy di UFW smettono di essere applicate: ogni porta in ascolto diventa raggiungibile dalla rete.",
      "Disattiva",
      "danger"
    );
    if (!ok) return;
  }
  const st = await busy(button, "Autenticazione…", () => call("set_firewall", { enabled: on }));
  state.status = { ...st, rules: null };
  renderStatus();
  toast(on ? "Firewall attivato" : "Firewall disattivato");
}

// ---------- ruleset completo (nft, sola lettura) ----------

const nftView = { data: null, filter: "", hideEmpty: true, owner: "" };

function fmtBytes(n) {
  if (n === null || n === undefined) return "";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function fmtCount(n) {
  return n === null || n === undefined ? "" : n.toLocaleString("it-IT");
}

const chainId = (t, c) => `nft-${t.family}-${t.name}-${c}`.replace(/[^A-Za-z0-9_-]/g, "_");

/** Testo della regola con il verdetto colorato e jump/goto cliccabili. */
function nftRuleText(table, r) {
  const out = [];
  const words = r.text.split(" ");
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if ((w === "jump" || w === "goto") && words[i + 1]) {
      const target = words[i + 1];
      out.push(w + " ", h("a", { href: "#", class: "jump", onclick: (ev) => { ev.preventDefault(); openChain(chainId(table, target)); } }, target));
      i++;
    } else if (["accept", "drop", "reject", "return"].includes(w)) {
      out.push(h("span", { class: `verdict v-${w}` }, w));
    } else {
      out.push(w);
    }
    if (i < words.length - 1) out.push(" ");
  }
  return out;
}

function openChain(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.open = true;
  el.closest("details.nft-table")?.setAttribute("open", "");
  el.scrollIntoView({ behavior: "smooth", block: "start" });
  el.classList.add("flash");
  setTimeout(() => el.classList.remove("flash"), 1200);
}

function renderNftBody() {
  const box = $("#nft-body");
  if (!box) return;
  const q = nftView.filter.toLowerCase();
  const tables = [];
  for (const t of nftView.data.tables) {
    const chains = [];
    for (const c of t.chains) {
      if (nftView.owner && (c.owner || "kernel") !== nftView.owner) continue;
      const nameHit = !q || c.name.toLowerCase().includes(q);
      const rules = nameHit ? c.rules : c.rules.filter((r) => r.text.toLowerCase().includes(q));
      if (q && !nameHit && rules.length === 0) continue;
      if (nftView.hideEmpty && c.rules.length === 0 && !c.hook) continue;
      const hits = c.rules.reduce((a, r) => a + (r.packets || 0), 0);
      chains.push(
        h("details", { class: "nft-chain", id: chainId(t, c.name), open: !!(q || c.hook) },
          h("summary", {},
            h("span", { class: "mono chain-name" }, c.name),
            c.owner ? h("span", { class: `pill owner-${c.owner}` }, c.owner) : null,
            c.hook ? h("span", { class: "pill muted mono" }, c.hook) : null,
            c.policy ? h("span", { class: `pill ${c.policy === "drop" ? "bad" : "ok"}` }, `policy ${c.policy}`) : null,
            h("span", { class: "chain-meta" }, `${c.rules.length} regole`, hits ? ` · ${fmtCount(hits)} pacchetti` : "")
          ),
          rules.length
            ? h("table", { class: "rules nft" },
                h("thead", {}, h("tr", {}, h("th", {}, "Regola"), h("th", { class: "n" }, "Pacchetti"), h("th", { class: "n" }, "Byte"))),
                h("tbody", {}, rules.map((r) =>
                  h("tr", { class: r.packets ? "" : "zero" },
                    h("td", { class: "mono" }, nftRuleText(t, r)),
                    h("td", { class: "n mono" }, fmtCount(r.packets)),
                    h("td", { class: "n mono" }, fmtBytes(r.bytes))))))
            : h("p", { class: "hint" }, "Catena vuota.")
        )
      );
    }
    const others = q ? t.other.filter((o) => o.toLowerCase().includes(q)) : t.other;
    if (!chains.length && !others.length) continue;
    tables.push(
      h("details", { class: "nft-table", open: true },
        h("summary", {}, h("b", { class: "mono" }, `table ${t.family} ${t.name}`),
          h("span", { class: "chain-meta" }, `${t.chains.length} catene`)),
        t.note ? h("p", { class: "hint" }, t.note) : null,
        chains,
        others.map((o) => h("pre", { class: "cmds mono" }, o))
      )
    );
  }
  box.replaceChildren(...(tables.length ? tables : [h("p", { class: "hint" }, "Nessuna corrispondenza.")]));
}

async function showRuleset(button) {
  nftView.data = await busy(button, "Autenticazione…", () => call("full_ruleset"));
  const owners = ["", "ufw", "docker", "libvirt", "kernel"];
  infoDialog(
    [
      h("h3", {}, "Ruleset completo del kernel"),
      h("p", { class: "hint" },
        "Sola lettura: tutto ciò che il firewall applica, incluse le regole di before.rules, Docker e libvirt. ",
        "I contatori partono dall'ultimo caricamento delle regole. Le righe grigie non hanno mai trovato pacchetti."),
      h("div", { class: "nft-toolbar" },
        h("input", {
          type: "search", placeholder: "Filtra (es. 192.0.2.6, dport 22, docker)",
          value: nftView.filter,
          oninput: (ev) => { nftView.filter = ev.target.value; renderNftBody(); },
        }),
        h("select", { onchange: (ev) => { nftView.owner = ev.target.value; renderNftBody(); } },
          owners.map((o) => h("option", { value: o, selected: o === nftView.owner }, o ? `solo ${o}` : "tutte le catene"))),
        h("label", { class: "inline" },
          h("input", { type: "checkbox", checked: nftView.hideEmpty, onchange: (ev) => { nftView.hideEmpty = ev.target.checked; renderNftBody(); } }),
          " nascondi catene vuote")
      ),
      h("div", { id: "nft-body", class: "nft-body" }),
    ],
    [
      h("button", { class: "ghost", onclick: (ev) => showRuleset(ev.currentTarget) }, "Aggiorna"),
      h("button", { class: "ghost", onclick: async () => { await navigator.clipboard.writeText(nftView.data.text); toast("Copiato"); } }, "Copia testo"),
      closeButton(),
    ]
  );
  renderNftBody();
}

// ---------- CVE (Ubuntu Security API) ----------

const cveView = { watch: null, page: null, items: [], filter: "", loading: false, mit: null, sort: null, tab: "ubuntu" };

const MIT_STATE = {
  mitigata: ["ok", "mitigata"],
  "al-riavvio": ["warn", "mitigata al riavvio"],
  esposta: ["bad", "esposta"],
  "in-uso": ["warn", "in uso"],
  "non-in-uso": ["ok", "non in uso"],
};

function mitCheck(c) {
  return c.mitigation_id && cveView.mit ? cveView.mit.checks.find((k) => k.id === c.mitigation_id) : null;
}

function mitPill(k) {
  const [cls, label] = MIT_STATE[k.state] || ["muted", k.state];
  return h("span", { class: `pill ${cls}` }, label);
}

function mitButton(k, small = false) {
  if (!k.actionable) return null;
  const on = !k.configured;
  return h("button", {
    class: `${on ? "primary" : "ghost"}${small ? " small" : ""}`,
    title: k.label,
    onclick: (ev) => mitigateAsk(k, on, ev.currentTarget),
  }, on ? "Mitiga" : "Annulla mitigazione");
}

const EXPO = {
  aperta: ["bad", "aperta"],
  condizionata: ["warn", "condizionata"],
  bloccata: ["ok", "bloccata"],
  locale: ["muted", "locale"],
  ignota: ["muted", "ignota"],
};

function expoPill(v) {
  const [cls, label] = EXPO[v] || EXPO.ignota;
  return h("span", { class: `pill ${cls}` }, label);
}

async function exposureRun(button) {
  if (cveView.expoLoading) return;
  cveView.expoLoading = true;
  if (button) button.disabled = true;
  try {
    cveView.expo = await call("exposure_check");
    cveView.expoError = null;
  } catch (e) {
    cveView.expo = null;
    cveView.expoError = String(e);
  }
  cveView.expoLoading = false;
  await showCve($("#btn-cve"), true);
}

function mitBox(c) {
  const k = mitCheck(c);
  if (!k) return null;
  const listeners = k.id === "mptcp-off" && cveView.mit ? cveView.mit.listeners : null;
  const remote = listeners ? listeners.filter((l) => l.scope !== "locale") : null;
  return h("div", { class: "mit-box" },
    h("div", { class: "cve-head" }, h("b", {}, "Verifica: ", k.label), mitPill(k), h("span", { class: "spacer" }),
      listeners && remote.length
        ? h("button", {
            class: "ghost small",
            disabled: cveView.expoLoading || null,
            onclick: (ev) => exposureRun(ev.currentTarget),
          }, cveView.expoLoading ? "Verifica…" : "Verifica col firewall")
        : null,
      mitButton(k)),
    c.mitigation_note ? h("p", { class: "hint" }, c.mitigation_note) : null,
    h("ul", { class: "facts" },
      k.facts.map((f) => h("li", { class: "mono" }, f)),
      listeners ? h("li", {}, `Porte TCP in ascolto fuori dal loopback (${remote.length}):`,
        remote.length ? h("ul", { class: "expo" }, remote.map((l) => {
          const e = cveView.expo
            ? cveView.expo.find((x) => x.addr === l.addr && x.port === l.port && x.family === l.family)
            : null;
          const split = e && Array.isArray(e.per_family) && e.per_family.length
            ? h("span", { class: "mono muted" }, e.per_family.map((f) => `v${f.family}=${f.verdict}`).join("  "))
            : null;
          return h("li", {}, h("span", { class: "mono" }, `${l.addr}:${l.port}`), " ",
            e ? h("span", {}, expoPill(e.verdict), split ? " " : null, split, " ", h("span", { class: "hint" }, e.detail))
              : h("span", { class: "muted" }, l.scope));
        })) : null) : null),
    cveView.expoError ? h("p", { class: "error" }, cveView.expoError) : null,
    h("p", { class: "hint" }, h("b", {}, "Effetto: "), k.impact)
  );
}

async function cveLoadMit() {
  cveView.mit = await call("mitigation_states");
}

async function mitigateAsk(k, on, button) {
  const ok = await confirmDialog(
    on ? `${k.label}?` : `Annullare «${k.label}»?`,
    on ? `${k.impact} La mitigazione resta attiva dopo il riavvio finché non la annulli. Serve l'autenticazione.`
       : "Il sottosistema torna disponibile. Serve l'autenticazione.",
    on ? "Mitiga" : "Annulla mitigazione", on ? "primary" : "danger");
  if (!ok) return showCve($("#btn-cve"), true);
  let r;
  try {
    r = await call("mitigate", { id: k.id, on });
    cveView.expo = null; // il ruleset è cambiato: i verdetti precedenti non valgono più
  } finally {
    await showCve($("#btn-cve"), true);
  }
  toast(r.message, !r.ok);
}

const VERDICT = {
  vulnerable: ["bad", "vulnerabile"],
  update: ["warn", "corretta: aggiorna"],
  fixed: ["ok", "corretta"],
  "not-affected": ["ok", "non affetto"],
  unknown: ["muted", "stato ignoto"],
};

const openUrl = (url) => invoke("plugin:opener|open_url", { url }).catch((e) => toast(String(e), true));

function verdictPill(c) {
  const [cls, label] = VERDICT[c.verdict] || VERDICT.unknown;
  return h("span", { class: `pill ${cls}` }, label);
}

function statusText(c, sys) {
  if (!c.status) return `nessuno stato Ubuntu per ${sys.package} su ${sys.release}`;
  const fix = c.fix_version ? ` → corretta in ${c.fix_version}` : "";
  return `${sys.package} su ${sys.release}: ${c.status}${fix} (installata ${sys.version || "?"})`;
}

function cveLink(c) {
  return h("a", { href: "#", class: "mono", onclick: (ev) => { ev.preventDefault(); openUrl(c.url); } }, c.id);
}

function cveCard(c, sys) {
  if (c.error) return h("div", { class: "cve-card" }, h("p", { class: "error" }, c.error));
  return h("div", { class: `cve-card v-${c.verdict}` },
    h("div", { class: "cve-head" },
      h("b", {}, cveLink(c)),
      verdictPill(c),
      h("span", { class: `pill prio-${c.priority}` }, c.priority || "—"),
      c.cvss3 != null ? h("span", { class: "pill muted" }, `CVSS ${c.cvss3}`) : null,
      h("span", { class: "chain-meta" }, c.published),
      h("span", { class: "spacer" }),
      h("button", { class: "ghost small", title: "Non seguire più", onclick: () => cveWatch(c.id, false) }, "✕")
    ),
    h("p", { class: "cve-title" }, c.title),
    h("p", { class: "hint" }, statusText(c, sys)),
    c.mitigation ? h("p", {}, h("b", {}, "Mitigazione Ubuntu: "), c.mitigation) : null,
    c.verdict === "vulnerable" || c.verdict === "update" ? mitBox(c) : null,
    h("details", {}, h("summary", {}, "Descrizione completa"), h("pre", { class: "cmds" }, c.description))
  );
}

// Ordinamento colonna elenco CVE: clic sull'intestazione alterna su/giù (default: ordine API)
const PRIO_RANK = { critical: 0, high: 1, medium: 2, low: 3, negligible: 4 };
const CVE_VERDICT_RANK = { vulnerable: 0, update: 1, unknown: 2, "not-affected": 3, fixed: 4 };
const MIT_RANK = { esposta: 0, "in-uso": 1, "al-riavvio": 2, mitigata: 3, "non-in-uso": 4 };

function cveCompare(a, b, key) {
  switch (key) {
    case "id": return a.id.localeCompare(b.id);
    case "prio":
      return (PRIO_RANK[a.priority] ?? 9) - (PRIO_RANK[b.priority] ?? 9) || (b.cvss3 ?? 0) - (a.cvss3 ?? 0);
    case "stato":
      return (CVE_VERDICT_RANK[a.verdict] ?? 9) - (CVE_VERDICT_RANK[b.verdict] ?? 9);
    case "fix":
      return (a.fix_version || "").localeCompare(b.fix_version || "", undefined, { numeric: true });
    case "title":
      return (a.title || "").localeCompare(b.title || "", undefined, { sensitivity: "base" });
    case "mit":
      return (MIT_RANK[mitCheck(a)?.state] ?? 9) - (MIT_RANK[mitCheck(b)?.state] ?? 9);
    default: return 0;
  }
}

function cveSort(rows) {
  const s = cveView.sort;
  if (!s) return rows;
  const m = s.dir === "asc" ? 1 : -1;
  return rows.slice().sort((a, b) => {
    if (s.key === "fix" && (!a.fix_version || !b.fix_version))
      return (b.fix_version ? 1 : 0) - (a.fix_version ? 1 : 0) || a.id.localeCompare(b.id);
    return cveCompare(a, b, s.key) * m || a.id.localeCompare(b.id);
  });
}

function thCve(key, label) {
  const s = cveView.sort;
  const on = s && s.key === key;
  return h("th", {
    class: "sortable",
    title: `Ordina per ${label.toLowerCase()}`,
    onclick: () => { cveView.sort = { key, dir: on && s.dir === "asc" ? "desc" : "asc" }; renderCveBody(); },
  }, label + (on ? (s.dir === "asc" ? " ▲" : " ▼") : ""));
}

function cveTabSet(tab) {
  cveView.tab = tab;
  renderCveBody();
}

/** Titre e controlli fissi, tab bar con contatore; la lista scrolla dentro #cve-body. */
function renderCveBody() {
  const box = $("#cve-body");
  if (!box) return;
  const w = cveView.watch;
  $("#cve-tabs").replaceChildren(
    h("button", { class: `cve-tab${cveView.tab === "ubuntu" ? " active" : ""}`, onclick: () => cveTabSet("ubuntu") },
      "Vulnerabilità Ubuntu"),
    h("button", { class: `cve-tab${cveView.tab === "seguite" ? " active" : ""}`, onclick: () => cveTabSet("seguite") },
      "Seguite", w ? h("span", { class: "pill muted" }, String(w.items.length)) : null)
  );
  const ctl = $("#cve-ctl");
  if (cveView.tab === "ubuntu") {
    ctl.replaceChildren(h("input", {
      type: "search", class: "cve-filter", placeholder: "Filtra elenco (es. tcp, mptcp, sctp)",
      value: cveView.filter,
      oninput: (ev) => { cveView.filter = ev.target.value; renderCveList(); },
    }));
  } else {
    const addInput = h("input", {
      type: "search", class: "cve-id-input", placeholder: "CVE-AAAA-NNNNN", autocomplete: "off",
      onkeydown: (ev) => { if (ev.key === "Enter" && addInput.value.trim()) cveWatch(addInput.value, true); },
    });
    ctl.replaceChildren(addInput,
      h("button", { class: "ghost", onclick: () => addInput.value.trim() && cveWatch(addInput.value, true) }, "Segui CVE"));
  }
  renderCveList();
}

/** Solo il contenuto scrollabile (e il riepilogo fisso sopra la lista). */
function renderCveList() {
  const box = $("#cve-body");
  if (!box) return;
  const sub = $("#cve-sub");
  const w = cveView.watch;
  if (cveView.tab === "seguite") {
    sub.replaceChildren();
    if (!w) {
      box.replaceChildren(h("p", { class: "hint" }, "Caricamento…"));
      return;
    }
    box.replaceChildren(...(w.items.length
      ? w.items.map((c) => cveCard(c, w.system))
      : [h("p", { class: "hint" }, "Nessuna CVE seguita.")]));
    return;
  }
  if (!cveView.page) {
    sub.replaceChildren();
    box.replaceChildren(h("p", { class: "hint" }, "Caricamento dalla cache locale…"));
    return;
  }
  const sys = cveView.page.system;
  sub.replaceChildren(
    h("h4", {}, `Kernel ${sys.kernel}: CVE aperte high/critical su ${sys.release} `,
      h("span", { class: "chain-meta" }, `${cveView.items.length} di ${cveView.page.total}`,
        cveView.page.updated_at
          ? h("span", { class: "chain-meta" }, ` · dati ubuntu.com del ${new Date(cveView.page.updated_at * 1000).toLocaleString()}`)
          : null))
  );
  const q = cveView.filter.toLowerCase();
  const rows = cveSort(cveView.items.filter((c) => !q || `${c.id} ${c.title} ${c.description}`.toLowerCase().includes(q)));
  const watched = new Set((w?.items || []).map((c) => c.id));
  box.replaceChildren(
    h("table", { class: "rules cve" },
      h("thead", {}, h("tr", {}, thCve("id", "CVE"), thCve("prio", "Priorità"), thCve("stato", "Stato"),
        thCve("fix", "Correzione"), thCve("title", "Titolo"), thCve("mit", "Mitigazione"), h("th", {}, ""))),
      h("tbody", {}, rows.map((c) =>
        h("tr", {},
          h("td", { class: "nowrap" }, cveLink(c), h("div", { class: "chain-meta" }, c.published)),
          h("td", { class: "nowrap" }, h("span", { class: `pill prio-${c.priority}` }, c.priority), c.cvss3 != null ? ` ${c.cvss3}` : ""),
          h("td", {}, verdictPill(c), " ", h("span", { class: "chain-meta" }, c.status)),
          h("td", { class: "mono nowrap" }, c.fix_version || "—"),
          h("td", {}, c.title),
          h("td", { class: "nowrap" }, (() => {
            const k = mitCheck(c);
            return k ? [mitPill(k), " ", mitButton(k, true)] : h("span", { class: "chain-meta" }, "—");
          })()),
          h("td", {}, watched.has(c.id) ? h("span", { class: "chain-meta" }, "seguita")
            : h("button", { class: "ghost small", onclick: () => cveWatch(c.id, true) }, "Segui")))))),
    cveView.items.length === 0
      ? h("p", { class: "hint" }, "Cache CVE vuota: primo scaricamento da ubuntu.com in corso, la lista si popolerà a breve.")
      : null
  );
}

async function cveLoadWatch() {
  cveView.watch = await call("cve_watched");
  renderCveBody();
}

// Cache locale: la lista arriva subito; ubuntu.com viene interrogato in background
// dall'app e un evento "cve-refreshed" aggiorna tutto quando i dati nuovi arrivano.
async function cveLoadList() {
  cveView.page = await call("cve_kernel", { limit: 2000 });
  cveView.items = cveView.page.items;
  renderCveBody();
}

listenEvent("cve-refreshed", () => {
  if (!$("#cve-body")) return; // dialog chiuso
  cveLoadWatch().catch(() => {});
  cveLoadList().catch(() => {});
});

async function cveWatch(id, watch) {
  await call("cve_watch_set", { id, watch });
  toast(watch ? `${id} seguita` : `${id} rimossa`);
  await cveLoadWatch();
}

/** Struttura della scheda CVE (dialog generico): titolo, tab e controlli fissi; solo #cve-body scrolla. */
function cveShell() {
  infoDialog(
    [
      h("h3", {}, "Vulnerabilità Ubuntu"),
      h("div", { class: "cve-tabs", id: "cve-tabs" }),
      h("div", { id: "cve-sub" }),
      h("div", { class: "nft-toolbar cve-toolbar", id: "cve-ctl" }),
      h("div", { id: "cve-body", class: "cve-body" }, h("p", { class: "hint" }, "Caricamento dalla cache locale…")),
    ],
    [
      h("button", { class: "ghost", onclick: (ev) => showCve(ev.currentTarget) }, "Aggiorna"),
      closeButton(),
    ]
  );
  renderCveBody();
}

async function showCve(button, keepList = false) {
  if (keepList && cveView.page) {
    // dopo una mitigazione: rileggi stato locale e CVE seguite, l'elenco già caricato resta
    cveShell();
    await cveLoadMit().catch(() => {});
    renderCveBody();
    await cveLoadWatch().catch(() => {});
    return;
  }
  cveView.items = [];
  cveView.page = null;
  cveShell();
  await cveLoadMit().catch(() => {});
  await Promise.allSettled([cveLoadWatch(), cveLoadList()]);
}

// ---------- avvio ----------

async function init() {
  closeOnButtons($("#dlg-rule"));
  closeOnButtons($("#dlg-set"));
  $("#btn-new-set").addEventListener("click", newSet);
  $("#btn-import").addEventListener("click", (ev) => importLive(ev.currentTarget));
  $("#btn-live").addEventListener("click", (ev) => showLive(ev.currentTarget));
  $("#btn-history").addEventListener("click", showHistory);
  $("#btn-cve").addEventListener("click", (ev) => showCve(ev.currentTarget));
  $("#btn-nft").addEventListener("click", (ev) => showRuleset(ev.currentTarget));
  $("#btn-toggle-fw").addEventListener("click", (ev) => toggleFirewall(ev.currentTarget));

  state.info = await call("app_info");
  if (!state.info.helper_installed) {
    const w = $("#helper-warning");
    w.textContent =
      `Helper non installato (${state.info.helper_path}): puoi preparare i set, ma per leggere o applicare le regole ` +
      "esegui una volta  sudo packaging/install-helper.sh  dalla cartella del progetto.";
    w.hidden = false;
  }
  await loadStatus();
  await loadRulesets();
  const active = state.rulesets.find((r) => r.active) || state.rulesets[0];
  if (active) await selectRuleset(active.id);
}

init();
