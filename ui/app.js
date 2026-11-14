"use strict";

const invoke = window.__TAURI__.core.invoke;
// "cve-refreshed": il backend aggiorna la cache in background e avvisa quando ha finito.
const listenEvent = (window.__TAURI__?.event?.listen) || (() => Promise.resolve(() => {}));

const state = {
  info: null,
  status: null,
  rulesets: [],
  selected: null, // Ruleset completo
  view: "firewall", // pagina attiva nella barra sinistra
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
  [/^(\d+) disabilitate$/, "$1 disabled"],
  [/^(\d+) duplicate scartate$/, "$1 duplicates dropped"],
  [/· ([\d.,]+) pacchetti$/, "· $1 packets"],
  [/^(\d+) catene$/, "$1 chains"],
  [/^(\d+) di (\d+)$/, "$1 of $2"],
  [/^Kernel (.+): CVE aperte high\/critical su (.+)$/, "Kernel $1: open high/critical CVEs on $2"],
  [/^· (\d+) corrette nascoste$/, "· $1 resolved hidden"],
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
  // ---- report (porte in ascolto) ----
  [/^(\d+) in ascolto · (\d+) raggiungibili dalla rete · (.+)$/,
    (_, n, net, who) => `${n} listening · ${net} reachable from the network · ${EXACT[who] ?? who}`],
  [/^(\d+) porte appartengono a processi di altri utenti \(servizi di sistema\):$/, "$1 ports belong to other users' processes (system services):"],
  [/^Porte TCP in ascolto fuori dal loopback \((\d+)\):$/, "TCP ports listening outside loopback ($1):"],
  [/^(.*) — condizioni non valutate: (.+)$/, "$1 — conditions not evaluated: $2"],
  [/^in ascolto solo su loopback: non raggiungibile dalla rete$/, "listening on loopback only: not reachable from the network"],
  [/^nessuna regola corrisponde; policy drop di (.+)$/, "no rule matches; drop policy of $1"],
  [/^nessuna catena con hook input nel ruleset$/, "no chain with input hook in the ruleset"],
  [/^nessuna regola intercetta il traffico e tutte le catene input hanno policy accept$/, "no rule intercepts the traffic; all input chains have accept policy"],
];

Object.assign(EXACT, {
  // ---- report (porte in ascolto, come la scheda Report di Gufw) ----
  "Report": "Report",
  "Porte TCP e UDP in ascolto e processi che le aprono": "Listening TCP and UDP ports and the processes that open them",
  "processi di tutti gli utenti": "processes of all users",
  "solo i tuoi processi": "your processes only",
  "Rilegge le porte in ascolto": "Re-reads the listening ports",
  "Mostra tutti i processi": "Show all processes",
  "Legge i processi di tutti gli utenti come root (chiede l'autenticazione)": "Reads the processes of all users as root (asks for authentication)",
  "Lettura delle porte in ascolto\u2026": "Reading the listening ports\u2026",
  "Servizi che accettano connessioni TCP o datagrammi UDP su questa macchina.": "Services accepting TCP connections or UDP datagrams on this machine.",
  "Quelli in ascolto solo su loopback (locale) non sono raggiungibili dalla rete.": "Those listening on loopback only (local) are not reachable from the network.",
  "Con": "Use",
  "crei una regola allow per la porta nel set selezionato.": "to create an allow rule for the port in the selected set.",
  "1 porta appartiene a un processo di un altro utente (servizio di sistema):": "1 port belongs to another user's process (a system service):",
  "Filtra (es. 22, udp, sshd, root)": "Filter (e.g. 22, udp, sshd, root)",
  "nascondi quelle solo locali": "hide local-only ports",
  "il nome compare con Mostra tutti i processi, che li legge come root.": "the names appear with Show all processes, which reads them as root.",
  "Nessuna porta corrisponde al filtro.": "No port matches the filter.",
  "Nessuna porta in ascolto.": "No listening ports.",
  "solo locale": "local only",
  "tutte le interfacce": "all interfaces",
  "un indirizzo": "one address",
  "Porta": "Port",
  "Indirizzo": "Address",
  "Ascolto": "Listening on",
  "Processo": "Process",
  "Utente": "User",
  "+ Regola": "+ Rule",
  "Crea una regola allow per questa porta nel set selezionato": "Create an allow rule for this port in the selected set",
  "Crea prima un set di regole nella pagina Firewall.": "Create a rule set in the Firewall page first.",
});

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
  // ---- barra sinistra / barra superiore (stile Orbit) ----
  "Mostra o nascondi la barra laterale (Ctrl+B)": "Show or hide the sidebar (Ctrl+B)",
  "Apri la barra laterale": "Open the sidebar",
  "Viste": "Views",
  "Stato e azioni globali": "Status and global actions",
  "Set di regole": "Rule sets",
  "Firewall": "Firewall",
  "Set di regole e applicazione a UFW": "Rule sets and how they map to UFW",
  "Applicazioni passate con esito e dettagli": "Past applies with result and details",
  "Seleziona un set o creane uno nuovo.": "Select a set or create a new one.",
  "regole abilitate": "rules enabled",
  "\u00b7 applicato": "\u00b7 applied",
  "tabelle": "tables",
  "catene": "chains",
  "CVE in cache locale": "CVEs in local cache",
  "kernel": "kernel",
  "di ubuntu.com": "from ubuntu.com",
  "regole utente": "user rules",
  "Regole utente presenti ora in UFW": "User rules currently in UFW",
  "attivo": "active",
  "disattivato": "inactive",
  "Riprova": "Try again",
  "Lettura delle regole attuali di UFW\u2026": "Reading the current UFW rules\u2026",
  "Lettura del ruleset del kernel\u2026": "Reading the kernel ruleset\u2026",
  "Pu\u00f2 chiedere l'autenticazione.": "It may ask for authentication.",
  "Rilegge UFW (può chiedere l'autenticazione)": "Re-reads UFW (may ask for authentication)",
  "Rilegge il ruleset del kernel (può chiedere l'autenticazione)": "Re-reads the kernel ruleset (may ask for authentication)",
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
  "Importa da file": "Import from file",
  "Crea un set dalle regole di un file JSONC": "Create a set from the rules in a JSONC file",
  // dialog import. applyLang() traduce i text node, quindi il paragrafo con <code>
  // va spezzato nei due testi attorno al tag; le chiavi sono in IT -> EN (la lingua
  // di partenza dell'HTML) e valgono anche al contrario per il reload in IT.
  "Importa un set da file": "Import a set from a file",
  "File JSONC con le regole del set. Le righe che iniziano con": "JSONC file with the rules of the set. Lines starting with",
  '{ "name": "il mio set", "rules": [ { "action": "allow", "direction": "in", "proto": "tcp", "dport": "443" } ] }':
    '{ "name": "my set", "rules": [ { "action": "allow", "direction": "in", "proto": "tcp", "dport": "443" } ] }',
  // etichetta nativa del selettore di file: WebKit/GTK la disegna in italiano quando
  // la pagina e' IT e la lascia in inglese quando il documento passa a EN, perche' non
  // e' un text node. La sovrascriviamo noi, cosi' il dialog resta coerente.
  "Scegli file": "Choose File",
  "nessun file selezionato": "no file selected",
  "sono commenti e vengono ignorate; i nomi dei campi sono in inglese perché il formato è quello condiviso con l'infrastruttura.": "are comments and are ignored; field names are in English because that is the format shared with the infrastructure.",
  "Set importato": "Imported set",
  "Incolla il contenuto del file o scegli un file.": "Paste the file contents, or pick a file.",
  "File troppo grande (oltre 2 MB).": "File too large (over 2 MB).",
  "Profili pubblici": "Public profiles",
  "Profili disponibili": "Available profiles",
  "Lettura dei profili da GitHub…": "Reading the profiles from GitHub…",
  "Nessun profilo nel repository.": "No profiles in the repository.",
  "Rischio": "Risk",
  // etichette "<testo>: <errore>": la chiave e' il testo SENZA ": " (vedi tr())
  "Elenco dei profili non disponibile": "Profile list not available",
  "Profilo non scaricabile": "Could not download the profile",
  "Lettura del file fallita": "Could not read the file",
  "regole": "rules",
  "disabilitate": "disabled",
  // toast esito import: la forma con segnaposti NON e' una chiave usata (il guscio
  // lo traduce il ramo regex di tr()), quindi qui restano solo i frammenti.
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
  "È il set applicato: le regole in UFW restano come sono, ma PYLA non lo considererà più attivo.": "This is the applied set: UFW rules stay as they are, but PYLA will no longer consider it active.",
  "Le regole in UFW non vengono toccate.": "UFW rules are left untouched.",
  "Autenticazione…": "Authenticating…",
  "Regole importate da UFW": "Rules imported from UFW",
  // ---- dialog generici / applica ----
  "Conferma": "Confirm",
  "Chiudi": "Close",
  "Lettura UFW…": "Reading UFW…",
  "In UFW ci sono regole che PYLA non sa gestire (route o per applicazione).": "UFW contains rules PYLA cannot manage (route or application rules).",
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
  "Copia il testo della mitigazione": "Copy the mitigation text",
  "Copia il testo della descrizione": "Copy the description text",
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
  "nascondi corrette": "hide resolved",
  "Mostrale": "Show them",
  "Nessuna CVE vulnerabile o da aggiornare in elenco:": "No vulnerable or to-update CVE in the list:",
  "corrette sono nascoste dal filtro.": "resolved ones are hidden by the filter.",
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
  // sottotitolo della barra superiore (dinamico, cambia con la pagina attiva)
  [/^(\d+)\/(\d+) regole abilitate · applicato$/, "$1/$2 rules enabled · applied"],
  [/^(attivo|disattivato) · entrata (.+), uscita (.+), inoltro (.+) · (\d+) regole utente$/,
    "$1 · in $2, out $3, fwd $4 · $5 user rules"],
  [/^(\d+) tabelle · (\d+) catene$/, "$1 tables · $2 chains"],
  [/^(\d+) applicazioni registrate$/, "$1 applies recorded"],
  [/^kernel (.+) · (\d+) CVE in cache locale su (\d+) di ubuntu\.com$/,
    "kernel $1 · $2 CVEs in local cache of $3 from ubuntu.com"],
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
  [/^il database è di una versione più recente di PYLA \(schema (\d+)\)$/, "the database is from a newer PYLA version (schema $1)"],
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
  [/^in UFW ci sono regole che PYLA non gestisce, rimuovile prima con ufw o Gufw: /,
    "UFW has rules PYLA does not manage, remove them first with ufw or Gufw: "],
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
  // import da file JSONC (pyla_core::import); il prefisso "regola N: " lo toglie tr()
  [/^JSON non valido: (.*) \(riga (\d+)\)$/, "invalid JSON: $1 (line $2)"],
  [/^format_version (\d+) non supportato: PYLA (\S+) legge al massimo la versione (\d+); aggiorna PYLA prima di importare questo profilo$/,
    "format_version $1 not supported: PYLA $2 reads at most version $3; update PYLA before importing this profile"],
  [/^troppe regole: (\d+) \(massimo (\d+)\)$/, "too many rules: $1 (max $2)"],
  [/^duplicato di una regola precedente: /, "duplicate of an earlier rule: "],
  [/ — i campi accettati a livello di file sono: (.+) \(i campi delle regole stanno dentro "rules"\)$/,
    ' — fields accepted at file level are: $1 (rule fields go inside "rules")'],
  [/^azione non valida (.+) \(allow, deny, reject, limit\)$/, "invalid action $1 (allow, deny, reject, limit)"],
  [/^direzione non valida (.+) \(in, out\)$/, "invalid direction $1 (in, out)"],
  [/^protocollo non valido (.+) \(tcp, udp, any\)$/, "invalid protocol $1 (tcp, udp, any)"],
  [/^log non valido (.+) \(off, log, log-all\)$/, "invalid log $1 (off, log, log-all)"],
  [/ \(massimo 15 porte\)$/, " (max 15 ports)"],
  [/^non e' un file: /, "not a file: "],
  // riepilogo di una regola (ruleText e RuleSpec::summary): "... da <src> a <dst>"
  [/\bda (any|[0-9a-f.:/]+(?: ?: ?[\d,:]+)?) a (any|[0-9a-f.:/]+)/i, "from $1 to $2"],
  // sottotitolo di "Stato UFW": "attivo · entrata deny, uscita allow, ..."
  [/^attivo · /, "active · "],
  [/^disattivato · /, "inactive · "],
);

Object.assign(EXACT, {
  "percorso database non impostato": "database path not set",
  "release Ubuntu non determinabile": "cannot determine Ubuntu release",
  "nessun dato da ubuntu.com": "no data from ubuntu.com",
  "il nome del set è obbligatorio": "the set name is required",
  "autenticazione annullata": "authentication cancelled",
  "autenticazione negata o helper non autorizzato da polkit": "authentication denied or helper not authorized by polkit",
  "database bloccato": "database locked",
  "nessuna regola nel file": "no rules in the file",
  "file troppo grande (oltre 2 MB)": "file too large (over 2 MB)",
  "Importa": "Import",
  "Le CVE gia' corrette sul kernel installato o non pertinenti restano fuori dall'elenco; il contatore sopra dice quante ne sono nascoste.":
    "CVEs already fixed in the installed kernel, or not relevant, stay out of the list; the counter above says how many are hidden.",
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
    // "Set «nome» importato (3 regole, 1 disabilitate)": il nome del set e' un dato,
    // quello che va tradotto e' il resto. Si traduce il guscio con la forma vuota e
    // si ricompone; i frammenti dentro le parentesi passano gia' da EXACT/PATTERNS.
    // "regola 7: <errore>" dall'import: si traduce il prefisso e l'errore per conto suo
    // (i pattern degli errori sono ancorati a inizio stringa)
    const rule = /^regola (\d+): (.*)$/s.exec(out);
    if (rule) out = `rule ${rule[1]}: ${tr(rule[2])}`;
    // "Ordina per <colonna>": la colonna passa dal dizionario
    const sortBy = /^Sort by (.+)$/.exec(out);
    if (sortBy && EXACT[sortBy[1]] !== undefined) out = `Sort by ${EXACT[sortBy[1]]}`;
    const imp = /^Set «(.*)» importato \((.*)\)$/.exec(out);
    if (imp) {
      // i conteggi sono una lista di pezzi ("3 regole, 1 disabilitate"): ognuno passa
      // da PATTERNS/EXACT, cosi' il toast in inglese esce per intero tradotto
      const parts = imp[2].split(", ").map((x) => tr(x)).join(", ");
      out = `Imported set «${imp[1]}» (${parts})`;
    }
    if (out === t) return s;
  }
  return s.replace(t, out);
}

// PRE/CODE esclusi: i blocchi di comandi delle note di mitigazione non si
// traducono, e i pattern di tr() spezzerebbero i comandi multi-riga.
const I18N_SKIP = new Set(["SCRIPT", "STYLE", "PRE", "CODE"]);

/** Sostituisce nei nodi di testo e negli attributi titolo/placeholder del sottoalbero. */
function applyLang(root) {
  // Le etichette del widget nativo di scelta file NON sono text node ne' attributi: sono
  // un pseudo-elemento (::file-selector-button) che il toolkit disegna nella lingua di
  // sistema. Si localizzano con regole CSS agganciate a html[lang] (sotto, in style.css),
  // perche' applyLang qui dentro non puo' raggiungerle in nessun modo.
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
  // il testo del widget nativo di scelta file non e' un text node ne' un attributo:
  // va sostituito con il valore localizzato via CSS (i18n-file-label sotto).
  for (const el of root.querySelectorAll?.("input[type=file]") ?? []) {
    el.style.setProperty("--file-choose", JSON.stringify(tr("Scegli file")));
    el.style.setProperty("--file-none", JSON.stringify(tr("nessun file selezionato")));
  }
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

/** Figli per replaceChildren: filtra null/undefined/false, come fa gia' h().
 *  Serve perche' il DOM NON lo fa: `el.replaceChildren(x, null)` converte null nel
 *  testo "null" (e' la riga "null" comparsa in fondo all'elenco CVE). */
const kids = (...a) => a.flat().filter((c) => c !== null && c !== undefined && c !== false);

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

/** Dopo un'applicazione o una mitigazione le viste "lettura dal kernel" non valgono piu'. */
function invalidateReadViews() {
  liveView.rules = null;
  liveView.status = null;
  liveView.error = null;
  nftView.data = null;
  historyView.rows = null;
  historyView.error = null;
  cveView.expo = null;
}

// ---------- pannelli a pagina intera (niente popup) ----------
// Regole, set, import, info e conferme non sono dialog: sono pannelli che sostituiscono
// la pagina dentro <main>. Su telefono un dialog modale non e' utilizzabile (campi
// stretti, tastiera che copre meta' schermo, rotellina del mouse al posto dello scroll),
// e il pulsante "Annulla" di dlg-import non era nemmeno collegato: closeOnButtons veniva
// chiamato solo su dlg-rule e dlg-set. Un pannello ha una sola via di uscita, collegata
// per tutti allo stesso modo.
const PANEL_IDS = ["panel-rule", "panel-set", "panel-import", "panel-info"];
let openPanelId = null;

function showPanel(id, focusSel) {
  for (const p of PANEL_IDS) if (p !== id) $("#" + p).hidden = true;
  $("#view").hidden = true;
  const p = $("#" + id);
  p.hidden = false;
  openPanelId = id;
  document.body.classList.add("panel-open");
  // dal punto in alto: su telefono il pannello scorre e la posizione di scroll della
  // pagina resterebbe a meta' del contenuto precedente
  p.scrollTop = 0;
  const target = (focusSel && p.querySelector(focusSel)) ||
    p.querySelector("input:not([type=checkbox]):not([type=file]), select, textarea") ||
    p.querySelector("button");
  if (target) target.focus();
}

function closePanel() {
  if (!openPanelId) return;
  // una conferma rimasta aperta (cambio pagina, "Chiuso" di un altro pannello) va
  // risolta a false: la funzione che la aspettava non deve restare appesa per sempre.
  const pending = panelCancel;
  panelCancel = null;
  $("#" + openPanelId).hidden = true;
  openPanelId = null;
  $("#view").hidden = false;
  document.body.classList.remove("panel-open");
  if (pending) pending();
}

// Annulla/Chiudi di un pannello info: se una conferma e' ancora aperta va risolta a
// false, altrimenti chiuderla cambiando pagina lascia la chiamata in await per sempre.
let panelCancel = null;

const panelIsOpen = () => openPanelId !== null;
const panelEl = () => (openPanelId ? $("#" + openPanelId) : null);

function closeOnButtons(root) {
  root.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", closePanel));
}

function ep(addr, port) {
  return port ? `${addr} : ${port}` : addr;
}

// Le etichette delle celle non sono solo la testa della tabella: su telefono il CSS
// trasforma ogni riga in una scheda a due colonne e recupera il nome del campo da
// data-label (stessa informazione, due usi).
const RULE_COLS = ["Azione", "Direzione", "Interfaccia", "Protocollo", "Sorgente", "Destinazione", "Commento"];

function ruleCells(s) {
  const cells = [
    h("td", {}, h("span", { class: `act-${s.action}` }, s.action), s.log !== "off" ? " ✎" : ""),
    h("td", {}, s.direction),
    h("td", {}, s.interface || "—"),
    h("td", {}, s.proto === "any" ? "tutti" : s.proto),
    h("td", { class: "mono" }, ep(s.src, s.sport)),
    h("td", { class: "mono" }, ep(s.dst, s.dport)),
    h("td", { class: "comment", title: s.comment || "" }, s.comment || ""),
  ];
  cells.forEach((c, i) => c.setAttribute("data-label", RULE_COLS[i]));
  return cells;
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

// ---------- barra sinistra a scomparsa (stile Orbit) ----------
// Le quattro voci che stavano nella barra superiore sono ora pagine della barra
// sinistra: una sola vista alla volta in #view, nessun dialog. La lista dei set
// compare solo sotto la pagina Firewall (come le chat di un bot in Orbit).

const ICON = {
  shield: '<path d="M12 3l7 3v5c0 4.6-3 8.2-7 10-4-1.8-7-5.4-7-10V6l7-3z"/>',
  list: '<path d="M4 6h16M4 12h16M4 18h9"/>',
  layers: '<path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/>',
  alert: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.5h.01"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>',
  radar: '<circle cx="12" cy="12" r="2"/><path d="M8.5 15.5a5 5 0 0 1 0-7M15.5 8.5a5 5 0 0 1 0 7M5.6 18.4a9 9 0 0 1 0-12.8M18.4 5.6a9 9 0 0 1 0 12.8"/>',
};

/** Icona a trattini (niente font esterni: CSP = script-src 'self', offline). */
function icon(paths) {
  const el = document.createElement("span");
  el.className = "ico";
  el.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" ` +
    `stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
  return el;
}

const PAGES = [
  { view: "firewall", label: "Firewall", hint: "Set di regole e applicazione a UFW", icon: ICON.shield },
  { view: "live", label: "Stato UFW", hint: "Legge le regole presenti ora in UFW (chiede l'autenticazione)", icon: ICON.list },
  { view: "nft", label: "Ruleset completo", hint: "Tutte le tabelle e catene del kernel (UFW, Docker, libvirt\u2026), in sola lettura", icon: ICON.layers },
  { view: "report", label: "Report", hint: "Porte TCP e UDP in ascolto e processi che le aprono", icon: ICON.radar },
  { view: "cve", label: "CVE", hint: "Vulnerabilit\u00e0 del kernel Ubuntu in uso (Ubuntu Security API)", icon: ICON.alert },
  { view: "history", label: "Storico", hint: "Applicazioni passate con esito e dettagli", icon: ICON.clock },
];

// viste a elenco: scrolla solo il corpo, titoli e filtri restano fissi in alto
const FILL_VIEWS = new Set(["cve", "nft"]);

const rail = {
  collapsed: localStorage.getItem("pyla.rail.collapsed") === "1",
  drawerOpen: false, // cassetto aperto, solo su finestra stretta (non persistito)
  narrow: false,
};

const NARROW = window.matchMedia ? window.matchMedia("(max-width: 820px)") : null;
rail.narrow = !!(NARROW && NARROW.matches);

/** Applica lo stato della barra: larghezza 0 se nascosta; su finestra stretta
 *  diventa cassetto sopra il contenuto (fascia sul bordo per aprire, velo per chiudere). */
function railApply() {
  const sb = $("#sidebar");
  if (!sb) return;
  const hidden = rail.narrow ? !rail.drawerOpen : rail.collapsed;
  sb.classList.toggle("collapsed", hidden);
  const btn = $("#btn-rail");
  if (btn) btn.setAttribute("aria-expanded", String(!hidden));
  document.querySelectorAll(".drawer-edge, .drawer-backdrop").forEach((el) => el.remove());
  if (rail.narrow) {
    document.body.append(
      rail.drawerOpen
        ? h("div", { class: "drawer-backdrop", onclick: () => railToggle() })
        : h("div", { class: "drawer-edge", title: "Apri la barra laterale", onclick: () => railToggle() })
    );
  }
}

function railToggle() {
  if (NARROW) rail.narrow = NARROW.matches; // rilegge la larghezza reale: niente valori stantii
  if (rail.narrow) rail.drawerOpen = !rail.drawerOpen;
  else {
    rail.collapsed = !rail.collapsed;
    localStorage.setItem("pyla.rail.collapsed", rail.collapsed ? "1" : "0");
  }
  railApply();
}

/** Scelta una pagina o un set, il cassetto si richiude da solo (come in Orbit). */
function railCloseDrawer() {
  if (rail.narrow && rail.drawerOpen) {
    rail.drawerOpen = false;
    railApply();
  }
}

if (NARROW) {
  const onNarrow = (e) => {
    rail.narrow = e.matches;
    rail.drawerOpen = false;
    railApply();
  };
  if (NARROW.addEventListener) NARROW.addEventListener("change", onNarrow);
  else NARROW.addListener(onNarrow); // Safari/WebKit vecchi
}

/** Contatori nelle voci della barra: dicono cosa c'è dentro una pagina senza aprirla. */
function navBadge(view) {
  if (view === "firewall" && state.rulesets.length) return String(state.rulesets.length);
  if (view === "cve" && cveView.watch) return String(cveView.watch.items.length);
  if (view === "history" && historyView.rows) return String(historyView.rows.length);
  if (view === "report" && reportView.data) return String(reportView.data.sockets.length);
  return null;
}

function renderNav() {
  const nav = $("#main-nav");
  if (!nav) return;
  nav.replaceChildren(...PAGES.map((p) => {
    const badge = navBadge(p.view);
    return h(
      "button",
      {
        class: `nav-item${state.view === p.view ? " active" : ""}`,
        title: p.hint,
        onclick: () => setView(p.view),
      },
      icon(p.icon),
      h("span", { class: "nav-label" }, p.label),
      badge ? h("span", { class: "pill muted" }, badge) : null
    );
  }));
  const sub = $("#sets-rail");
  if (sub) sub.hidden = state.view !== "firewall";
}

/** Titolo, sottotitolo e azioni della barra superiore: cambiano con la pagina. */
function renderHeader() {
  const page = PAGES.find((p) => p.view === state.view) || PAGES[0];
  const title = $("#view-title");
  const sub = $("#view-sub");
  const actions = $("#view-actions");
  const rs = state.selected;
  let name = page.label, note = page.hint;
  if (state.view === "firewall") {
    if (rs) {
      const on = rs.rules.filter((r) => r.enabled).length;
      name = rs.name;
      note = `${on}/${rs.rules.length} regole abilitate` + (rs.active ? " \u00b7 applicato" : "");
    } else note = "Seleziona un set o creane uno nuovo.";
  } else if (state.view === "live" && liveView.status) {
    const st = liveView.status;
    note = `${st.enabled ? "attivo" : "disattivato"} \u00b7 entrata ${st.defaults.incoming}, uscita ${st.defaults.outgoing}, ` +
      `inoltro ${st.defaults.routed} \u00b7 ${(liveView.rules || []).length} regole utente`;
  } else if (state.view === "nft" && nftView.data) {
    const chains = nftView.data.tables.reduce((a, t) => a + t.chains.length, 0);
    note = `${nftView.data.tables.length} tabelle \u00b7 ${chains} catene`;
  } else if (state.view === "report" && reportView.data) {
    const ss = reportView.data.sockets;
    const net = ss.filter((x) => x.scope !== "locale").length;
    note = `${ss.length} in ascolto \u00b7 ${net} raggiungibili dalla rete \u00b7 ` +
      (reportView.data.privileged ? "processi di tutti gli utenti" : "solo i tuoi processi");
  } else if (state.view === "cve" && cveView.page) {
    const sys = cveView.page.system;
    note = `kernel ${sys.kernel} \u00b7 ${cveView.items.length} CVE in cache locale su ${cveView.page.total} di ubuntu.com`;
  }
  title.textContent = name;
  sub.textContent = note;
  actions.replaceChildren(...kids(viewActions()));
}

/** Bottoni di servizio della pagina corrente (in alto a destra, stile Orbit). */
function viewActions() {
  switch (state.view) {
    case "live":
      return [h("button", {
        class: "ghost", title: "Rilegge UFW (può chiedere l'autenticazione)",
        onclick: () => { liveView.rules = null; liveView.error = null; setView("live"); },
      }, "Aggiorna")];
    case "nft":
      return [
        h("button", {
          class: "ghost", title: "Rilegge il ruleset del kernel (può chiedere l'autenticazione)",
          onclick: () => { nftView.data = null; setView("nft"); },
        }, "Aggiorna"),
        h("button", {
          class: "ghost",
          onclick: async () => { await navigator.clipboard.writeText(nftView.data.text); toast("Copiato"); },
        }, "Copia testo"),
      ];
    case "cve":
      return [h("button", { class: "ghost", onclick: () => setView("cve") }, "Aggiorna")];
    case "report":
      return [
        h("button", {
          class: "ghost", title: "Rilegge le porte in ascolto",
          onclick: () => reportReload(reportView.data?.privileged || false),
        }, "Aggiorna"),
        reportView.data && !reportView.data.privileged ? h("button", {
          class: "ghost", title: "Legge i processi di tutti gli utenti come root (chiede l'autenticazione)",
          onclick: () => reportReload(true),
        }, "Mostra tutti i processi") : null,
      ].filter(Boolean);
    case "history":
      return [h("button", { class: "ghost", onclick: () => { historyView.rows = null; historyView.error = null; setView("history"); } }, "Aggiorna")];
    default:
      return [];
  }
}

function setView(view) {
  if (!PAGES.some((p) => p.view === view)) view = "firewall";
  // cambiare pagina chiude il pannello aperto: la barra laterale resta sempre cliccabile
  // (non c'e' nessun modale che la blocca) e il contenuto sotto deve tornare visibile.
  closePanel();
  state.view = view;
  localStorage.setItem("pyla.view", view);
  railCloseDrawer();
  renderNav();
  const box = $("#view");
  box.className = "view" + (FILL_VIEWS.has(view) ? " fill" : "");
  box.replaceChildren();
  const r = VIEW_RENDER[view]();
  // le viste di lettura dal kernel sono asincrone: il sottotitolo si completa quando arrivano i dati
  if (r && typeof r.then === "function") r.then(() => renderHeader()).catch(() => {});
  else renderHeader();
}

// ---------- sidebar ----------

function renderRulesets() {
  const ul = $("#rulesets");
  ul.replaceChildren(...kids(
    ...state.rulesets.map((r) =>
      h(
        "li",
        {
          // confronto su ID e nome: un set appena importato puo' arrivare dal backend
          // con id non numerico (mock, bridge web) ma con lo stesso nome della riga; la
          // selezione deve evidenziare comunque la voce che stai guardando.
          class: state.selectedId != null && state.selectedId === r.id ? "selected" : "",
          onclick: () => selectRuleset(r.id),
        },
        h("div", { class: "name" }, r.name, r.active ? h("span", { class: "pill ok" }, "applicato") : null),
        h("div", { class: "meta" }, `${r.enabled}/${r.rules} regole abilitate`)
      )
    )
  ));
}

async function loadRulesets() {
  state.rulesets = await call("list_rulesets");
  renderRulesets();
  renderNav();
}

async function selectRuleset(id) {
  const rs = await call("get_ruleset", { id });
  // il dettaglio puo' riportare l'id in una forma diversa da quella della lista (il
  // DB restituisce numeri, un bridge web potrebbe serializzarli): la selezione in
  // sidebar si fa sul nome quando gli id non coincidono, cosi' la voce evidenziata e'
  // sempre il set che stai guardando.
  const row = state.rulesets.find((r) => r.id === (rs?.id ?? id)) ||
    state.rulesets.find((r) => r.name === rs?.name);
  state.selectedId = row ? row.id : id;
  state.selected = rs;
  if (state.view !== "firewall") return setView("firewall");
  renderRulesets();
  renderDetail();
  renderHeader();
}

async function refreshSelected() {
  await loadRulesets();
  if (state.selected) await selectRuleset(state.selectedId ?? state.selected.id);
}

// ---------- dettaglio set ----------

function renderDetail() {
  if (state.view !== "firewall") return; // la vista #view ospita la pagina attiva
  const rs = state.selected;
  const box = $("#view");
  if (!rs) {
    box.replaceChildren(...kids(
      h("div", { class: "empty" }, "Seleziona un set o creane uno nuovo.", h("br"),
        "Per partire dalle regole attuali usa ", h("b", {}, "Importa da UFW"), ".")
    ));
    return;
  }

  const head = h(
    "div",
    { class: "view-head" },
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
      { class: "rules plain" },
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

  box.replaceChildren(...kids(
    head,
    body,
    h("p", { class: "hint" },
      "L'ordine conta: UFW applica la prima regola che corrisponde. ",
      "Le regole disabilitate restano nel set ma non vengono scritte in UFW. ",
      "Le modifiche diventano effettive solo con «Anteprima e applica».")
  ));
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

/** `prefill` (solo per una regola nuova) sovrascrive i valori di partenza: lo usa il Report. */
function editRule(rule, prefill = null) {
  editingRule = rule;
  const f = $("#rule-form");
  const s = rule || {
    enabled: true, action: "allow", direction: "in", interface: "", proto: "tcp",
    src: "any", sport: "", dst: "any", dport: "", log: "off", comment: "",
    ...(prefill || {}),
  };
  $("#rule-title").textContent = rule ? "Modifica regola" : "Nuova regola";
  for (const k of ["action", "direction", "interface", "proto", "src", "sport", "dst", "dport", "log", "comment"]) {
    f.elements[k].value = s[k] ?? "";
  }
  f.elements.enabled.checked = rule ? rule.enabled : true;
  $("#rule-error").hidden = true;
  showPanel("panel-rule", "input[name=src]");
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
  closePanel();
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
      closePanel();
    } catch (e) {
      $("#set-error").textContent = String(e);
      $("#set-error").hidden = false;
    }
  };
  showPanel("panel-set", "input[name=name]");
}

function newSet() {
  setDialog("Nuovo set di regole", "", "", async (name, description) => {
    const id = await invoke("create_ruleset", { name, description, copyFrom: null });
    await selectRuleset(id);
    await loadRulesets();
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
    await selectRuleset(id);
    await loadRulesets();
  });
}

async function deleteSet() {
  const rs = state.selected;
  const extra = rs.active
    ? "È il set applicato: le regole in UFW restano come sono, ma PYLA non lo considererà più attivo."
    : "Le regole in UFW non vengono toccate.";
  if (!(await confirmDialog(`Eliminare il set «${rs.name}»?`, extra))) return;
  await call("delete_ruleset", { id: rs.id });
  state.selected = null;
  await loadRulesets();
  renderDetail();
}

// Import di un set da file JSONC. Il parsing e la validazione stanno nel backend
// (pyla_core::import): qui si raccoglie il testo e si mostrano gli esiti, inclusi i
// motivi di scarto con la riga del file, che sennò resterebbero invisibili.
// Un modello di file reale sta in examples/stealth.jsonc (nel pacchetto:
// /usr/share/doc/pyla/examples); i profili pubblici si caricano da pyla-dev/pyla-profiles.
function importDialog() {
  const f = $("#import-form");
  $("#import-error").hidden = true;
  $("#import-text").value = "";
  $("#import-file").value = "";
  // l'elenco dei profili resta (e' in cache): si toglie solo la selezione precedente
  for (const r of document.querySelectorAll("#import-list tbody tr")) r.setAttribute("aria-selected", "false");
  f.onsubmit = async (ev) => {
    ev.preventDefault();
    const text = $("#import-text").value;
    if (!text.trim()) {
      $("#import-error").textContent = tr("Incolla il contenuto del file o scegli un file.");
      $("#import-error").hidden = false;
      return;
    }
    // nome di riserva = nome del file scelto (senza estensione), poi "Set importato"
    const file = $("#import-file").files[0];
    const fromList = window.__pylaImportFallback;
    window.__pylaImportFallback = null;
    const fallback = file ? file.name.replace(/\.(jsonc?|json)$/i, "")
      : (fromList || "Set importato");
    const submit = f.querySelector("button[type=submit]");
    submit.disabled = true;
    try {
      const out = await call("import_file", { text, fallbackName: fallback });
      closePanel();
      // prima si seleziona, POI si ricarica la lista: loadRulesets() richiama
      // renderNav(), che in questo build riscrive anche le voci della sidebar e
      // cancellerebbe l'evidenziazione del set appena importato.
      await selectRuleset(out.id);
      await loadRulesets();
      // conteggio onesto: quante regole attive e quante disabilitate dal file
      // conteggio onesto: quante regole attive e quante disabilitate dal file
      const bits = [`${out.rules} regole`];
      if (out.disabled) bits.push(`${out.disabled} disabilitate`);
      toast(tr(`Set «${out.name}» importato (${bits.join(", ")})`));
    } catch (e) {
      // l'errore del parser arriva gia' con la riga: "regola 7 (riga 12): ..."
      $("#import-error").textContent = String(e);
      $("#import-error").hidden = false;
    } finally {
      submit.disabled = false;
    }
  };
  showPanel("panel-import", "#import-text");
}

// file scelto -> lo leggiamo qui e lo mettiamo nella textarea: l'utente vede cosa
// sta importando prima di confermare, e un file grande resta verificabile
function bindImportFileInput() {
  // il pannello di import mostra sempre i profili pubblici: si caricano all'apertura
  $("#btn-import-file").addEventListener("click", () => { importDialog(); loadProfiles(); });
  // Profili pubblici: il repository GitHub pyla-dev/pyla-profiles, uno per cartella
  // (profiles/<id>/profile.jsonc). Il backend compone l'indirizzo dall'id, quindi da qui
  // non si puo' far scaricare altro. L'elenco si chiede solo quando l'utente lo apre.
  // Rischio dal README del profilo ("hard", "medium (balanced for daily use)"): la prima
  // parola diventa una pill colorata come la priorita' delle CVE, il resto va sotto.
  const RISK_CLASS = { critical: "prio-critical", hard: "prio-high", high: "prio-high",
    medium: "prio-medium", low: "prio-low", easy: "prio-low" };
  function riskCell(risk) {
    const m = /^(\S+)\s*(.*)$/.exec(risk || "");
    if (!m) return h("span", { class: "chain-meta" }, "—");
    return [h("span", { class: `pill ${RISK_CLASS[m[1].toLowerCase()] || "prio-low"}` }, m[1]),
      m[2] ? h("span", { class: "chain-meta" }, m[2]) : null];
  }

  // Elenco in cache per la sessione: GitHub si interroga alla prima apertura del
  // pannello (o alla successiva, se quella volta la rete non ha risposto).
  let profilesCache = null;
  async function loadProfiles() {
    const list = $("#import-list");
    const note = $("#import-files-note");
    if (profilesCache && list.querySelector("tbody")) return;
    list.replaceChildren();
    list.hidden = true;
    note.textContent = tr("Lettura dei profili da GitHub…");
    note.hidden = false;
    let profiles;
    try {
      profiles = profilesCache ?? await call("list_profiles");
    } catch (e) {
      note.textContent = tr(`Elenco dei profili non disponibile: ${e}`);
      return;
    }
    profilesCache = profiles;
    if (!profiles?.length) {
      note.textContent = tr("Nessun profilo nel repository.");
      return;
    }
    note.hidden = true;
    list.appendChild(h("table", { class: "rules cve profiles" },
      h("thead", {}, h("tr", {}, h("th", {}, "Nome"), h("th", {}, "Target"), h("th", {}, "Rischio"))),
      h("tbody", {}, profiles.map((p) =>
        h("tr", { role: "option", "aria-selected": "false", "data-id": p.id, onclick: () => pickProfile(p.id) },
          h("td", { class: "p-name" }, h("strong", {}, p.name || p.id),
            h("span", { class: "chain-meta mono" }, `${p.id} · ${Math.max(1, Math.round((p.size || 0) / 1024))} KB`)),
          h("td", {}, p.target || h("span", { class: "chain-meta" }, "—")),
          h("td", { class: "p-risk" }, riskCell(p.risk)))))));
    list.hidden = false;
  }

  // scelta di un profilo: il backend lo scarica e il testo va nella textarea, dove
  // l'utente lo vede (e puo' ancora correggerlo) prima di importarlo.
  async function pickProfile(id) {
    const rows = [...$("#import-list").querySelectorAll("tbody tr")];
    for (const r of rows) r.setAttribute("aria-selected", String(r.dataset.id === id));
    rows.find((r) => r.dataset.id === id)?.scrollIntoView?.({ block: "nearest" });
    try {
      const text = await call("read_profile", { id });
      $("#import-text").value = text;
      // l'id del profilo diventa il nome di riserva del set se nel JSONC non c'e' "name"
      $("#import-file").value = "";
      window.__pylaImportFallback = id;
      $("#import-error").hidden = true;
    } catch (e) {
      $("#import-error").textContent = tr(`Profilo non scaricabile: ${e}`);
      $("#import-error").hidden = false;
    }
  }

  // tastiera sul listbox: frecce per spostarsi tra i profili (e caricarli)
  $("#import-list").addEventListener("keydown", (ev) => {
    if (ev.key !== "ArrowDown" && ev.key !== "ArrowUp") return;
    const rows = [...$("#import-list").querySelectorAll("tbody tr")];
    if (!rows.length) return;
    ev.preventDefault();
    const cur = rows.findIndex((r) => r.getAttribute("aria-selected") === "true");
    const next = cur < 0 ? 0 : Math.min(rows.length - 1, Math.max(0, cur + (ev.key === "ArrowDown" ? 1 : -1)));
    pickProfile(rows[next].dataset.id);
  });

  $("#import-file").addEventListener("change", async () => {
    const file = $("#import-file").files[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      $("#import-error").textContent = tr("File troppo grande (oltre 2 MB).");
      $("#import-error").hidden = false;
      return;
    }
    try {
      $("#import-text").value = await file.text();
      $("#import-error").hidden = true;
    } catch (e) {
      $("#import-error").textContent = tr(`Lettura del file fallita: ${e}`);
      $("#import-error").hidden = false;
    }
  });
}

async function importLive(button) {
  const name = `UFW ${new Date().toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" })}`;
  await busy(button, "Autenticazione…", async () => {
    const id = await call("import_live", { name });
    invalidateReadViews();
    await loadRulesets();
    await selectRuleset(id);
    toast("Regole importate da UFW");
  });
}

// ---------- dialog generico ----------

function infoDialog(content, buttons) {
  $("#info-body").replaceChildren(...kids(...[content].flat()));
  $("#info-actions").replaceChildren(...kids(...buttons));
  showPanel("panel-info", "#info-actions button");
}

function confirmDialog(title, text, okLabel = "Conferma", okClass = "primary") {
  return new Promise((resolve) => {
    // il pannello non ha l'evento "close" del dialog: la promessa si risolve per per-
    // verso. Esc e Annulla passano da qui (data-cancel), altrimenti una conferma chiusa
    // con Esc lascerebbe il pannello aperto sopra una scelta non fatta.
    const done = (v) => {
      panelCancel = null;
      closePanel();
      resolve(v);
    };
    panelCancel = () => done(false);
    infoDialog(
      [h("h3", {}, title), text ? h("p", {}, text) : null],
      [
        h("button", { class: "ghost", "data-cancel": "", onclick: () => done(false) }, "Annulla"),
        h("button", { class: okClass, onclick: () => done(true) }, okLabel),
      ]
    );
  });
}



const closeButton = () => h("button", { "data-cancel": "", onclick: () => closePanel() }, "Chiudi");

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
        "In UFW ci sono regole che PYLA non sa gestire (route o per applicazione). ",
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
      invalidateReadViews();
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
    h("button", { class: "ghost", "data-cancel": "", onclick: () => closePanel() }, "Annulla"),
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
  invalidateReadViews();
  await loadStatus();
  await refreshSelected();
  renderHeader();
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

const liveView = { rules: null, loading: false, error: null };

/** Vista "Stato UFW": le regole utente presenti ora in UFW (era un dialog). */
async function viewLive() {
  const box = $("#view");
  if (liveView.rules === null && !liveView.loading) {
    box.replaceChildren(h("p", { class: "hint" },
      "Lettura delle regole attuali di UFW\u2026 ", "Pu\u00f2 chiedere l'autenticazione."));
    liveView.loading = true;
    try {
      const st = await call("live_status");
      state.status = { ...st, rules: null };
      renderStatus();
      liveView.rules = st.rules || [];
      liveView.status = st;
      liveView.error = null;
    } catch (e) {
      liveView.error = String(e);
    } finally {
      liveView.loading = false;
    }
    if (state.view !== "live") return;
    renderHeader();
  }
  if (liveView.error) {
    box.replaceChildren(...kids(
      h("p", { class: "error" }, liveView.error),
      h("p", {}, h("button", { class: "ghost", onclick: () => { liveView.rules = null; liveView.error = null; viewLive(); } }, "Riprova"))
    ));
    return;
  }
  if (liveView.rules === null) return; // caricamento in corso su un'altra vista
  const st = liveView.status;
  const rules = liveView.rules;
  const parts = [
    h("h3", {}, "Regole utente presenti ora in UFW"),
    h("dl", { class: "kv" },
      h("dt", {}, "Stato"), h("dd", {}, st.enabled ? "attivo" : "disattivato"),
      h("dt", {}, "Policy"), h("dd", {}, `entrata ${st.defaults.incoming}, uscita ${st.defaults.outgoing}, inoltro ${st.defaults.routed}`),
      h("dt", {}, "Log"), h("dd", {}, st.loglevel || "—")),
  ];
  if (!rules.length) {
    parts.push(h("p", {}, "Nessuna regola utente."));
  } else {
    parts.push(
      h("table", { class: "rules plain" },
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
  box.replaceChildren(...kids(...parts));
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

const historyView = { rows: null, loading: false };

/** Vista "Storico": le applicazioni passate con esito e dettagli (era un dialog). */
async function viewHistory() {
  const box = $("#view");
  if (historyView.rows === null && !historyView.loading) {
    historyView.loading = true;
    try {
      historyView.rows = await call("history", { limit: 50 });
    } catch (e) {
      historyView.rows = [];
      historyView.error = String(e);
    } finally {
      historyView.loading = false;
    }
    if (state.view !== "history") return;
    renderNav();
    renderHeader();
  }
  const rows = historyView.rows || [];
  const parts = [h("h3", {}, `${rows.length} applicazioni registrate`)];
  if (historyView.error) parts.push(h("p", { class: "error" }, historyView.error));
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
  box.replaceChildren(...kids(...parts));
}

// ---------- report: servizi in ascolto (come la scheda Report di Gufw) ----------

const reportView = {
  data: null, loading: false, error: null, filter: "",
  hideLocal: localStorage.getItem("pyla.report.hideLocal") === "1",
};

const SCOPE_PILL = { locale: "muted", tutte: "warn", "link-local": "muted", indirizzo: "" };
// etichette proprie: "tutte"/"locale" da sole sono gia' usate altrove nel dizionario EN
const SCOPE_LABEL = { locale: "solo locale", tutte: "tutte le interfacce", "link-local": "link-local", indirizzo: "un indirizzo" };

function reportReload(privileged) {
  reportView.data = null;
  reportView.error = null;
  if (state.view === "report") { $("#view").replaceChildren(); return viewReport(privileged); }
}

/** Vista "Report": legge /proc senza password; `privileged` passa dall'helper (root). */
async function viewReport(privileged = false) {
  const box = $("#view");
  if (reportView.data === null && !reportView.loading) {
    box.replaceChildren(h("p", { class: "hint" }, "Lettura delle porte in ascolto\u2026",
      privileged ? " Pu\u00f2 chiedere l'autenticazione." : ""));
    reportView.loading = true;
    try {
      reportView.data = await call("listening_report", { privileged });
      reportView.error = null;
    } catch (e) {
      reportView.error = String(e);
      // l'autenticazione annullata non deve far sparire l'elenco gia' leggibile senza root
      if (privileged) {
        try { reportView.data = await invoke("listening_report", { privileged: false }); } catch (_) { /* resta l'errore */ }
      }
    } finally {
      reportView.loading = false;
    }
    if (state.view !== "report") return;
    renderNav();
    renderHeader();
  }
  if (!reportView.data) {
    box.replaceChildren(...kids(
      reportView.error ? h("p", { class: "error" }, reportView.error) : null,
      h("p", {}, h("button", { class: "ghost", onclick: () => reportReload(false) }, "Riprova"))
    ));
    return;
  }
  const d = reportView.data;
  const parts = [
    h("p", { class: "hint" },
      "Servizi che accettano connessioni TCP o datagrammi UDP su questa macchina. ",
      "Quelli in ascolto solo su loopback (locale) non sono raggiungibili dalla rete. ",
      "Con ", h("b", { class: "nowrap" }, "+ Regola"), " crei una regola allow per la porta nel set selezionato."),
    reportView.error ? h("p", { class: "error" }, reportView.error) : null,
    h("div", { class: "nft-toolbar" },
      h("input", {
        type: "search", placeholder: "Filtra (es. 22, udp, sshd, root)",
        value: reportView.filter,
        oninput: (ev) => { reportView.filter = ev.target.value; renderReportBody(); },
      }),
      h("label", { class: "inline" },
        h("input", {
          type: "checkbox", checked: reportView.hideLocal,
          onchange: (ev) => {
            reportView.hideLocal = ev.target.checked;
            try { localStorage.setItem("pyla.report.hideLocal", ev.target.checked ? "1" : "0"); } catch (_) {}
            renderReportBody();
          },
        }),
        " nascondi quelle solo locali")),
    h("div", { id: "report-body" }),
  ];
  if (!d.privileged && d.unresolved > 0)
    parts.push(h("p", { class: "hint" },
      d.unresolved === 1
        ? "1 porta appartiene a un processo di un altro utente (servizio di sistema): "
        : `${d.unresolved} porte appartengono a processi di altri utenti (servizi di sistema): `,
      "il nome compare con Mostra tutti i processi, che li legge come root."));
  box.replaceChildren(...kids(...parts));
  renderReportBody();
}

// stesse etichette della testata: su telefono la tabella diventa a schede (data-label)
const REPORT_COLS = ["Protocollo", "Porta", "Indirizzo", "Ascolto", "Processo", "Utente", ""];
function withLabels(cols, row) {
  [...row.children].forEach((td, i) => cols[i] && td.setAttribute("data-label", tr(cols[i])));
  return row;
}

function renderReportBody() {
  const box = $("#report-body");
  if (!box || !reportView.data) return;
  const q = reportView.filter.trim().toLowerCase();
  const rows = reportView.data.sockets.filter((x) => {
    if (reportView.hideLocal && x.scope === "locale") return false;
    if (!q) return true;
    return [x.proto, String(x.port), x.addr, x.process || "", x.user || "", x.cmdline || ""]
      .some((v) => v.toLowerCase().includes(q));
  });
  if (!rows.length) {
    box.replaceChildren(h("p", {}, reportView.data.sockets.length
      ? "Nessuna porta corrisponde al filtro." : "Nessuna porta in ascolto."));
    return;
  }
  box.replaceChildren(
    h("table", { class: "rules plain report" },
      h("thead", {}, h("tr", {},
        h("th", {}, "Protocollo"), h("th", {}, "Porta"), h("th", {}, "Indirizzo"), h("th", {}, "Ascolto"),
        h("th", {}, "Processo"), h("th", {}, "Utente"), h("th", {}, ""))),
      h("tbody", {}, rows.map((x) =>
        withLabels(REPORT_COLS, h("tr", { class: x.scope === "locale" ? "dim" : "" },
          h("td", { class: "mono" }, `${x.proto}${x.family === 6 ? "6" : ""}`),
          h("td", { class: "mono" }, x.port),
          h("td", { class: "mono" }, x.addr),
          h("td", {}, h("span", { class: `pill ${SCOPE_PILL[x.scope] ?? ""}` }, SCOPE_LABEL[x.scope] ?? x.scope)),
          h("td", { title: x.cmdline || "" },
            x.process ? [x.process, x.pid ? h("span", { class: "chain-meta" }, ` pid ${x.pid}`) : null] : "\u2014"),
          h("td", {}, x.user || String(x.uid)),
          h("td", { class: "ctl" },
            h("button", {
              class: "icon", title: "Crea una regola allow per questa porta nel set selezionato",
              onclick: () => ruleFromReport(x),
            }, "+ Regola"))))
      )))
  );
}

/** "+ Regola": apre l'editor nel set selezionato (o in quello applicato), gia' compilato. */
async function ruleFromReport(x) {
  const target = state.selected ||
    state.rulesets.find((r) => r.active) || state.rulesets[0];
  if (!target) {
    toast("Crea prima un set di regole nella pagina Firewall.", true);
    return;
  }
  await selectRuleset(target.id);
  editRule(null, {
    action: "allow", direction: "in", proto: x.proto, dport: String(x.port),
    comment: x.process || "",
  });
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
  invalidateReadViews();
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
  box.replaceChildren(...kids(...(tables.length ? tables : [h("p", { class: "hint" }, "Nessuna corrispondenza.")])));
}

/** Vista "Ruleset completo": tabelle e catene del kernel, in sola lettura (era un dialog). */
async function viewNft() {
  const box = $("#view");
  if (!nftView.data) {
    box.replaceChildren(h("p", { class: "hint" },
      "Lettura del ruleset del kernel\u2026 ", "Pu\u00f2 chiedere l'autenticazione."));
    try {
      nftView.data = await call("full_ruleset");
    } catch (e) {
      box.replaceChildren(...kids(
        h("p", { class: "error" }, String(e)),
        h("p", {}, h("button", { class: "ghost", onclick: () => viewNft() }, "Riprova"))
      ));
      return;
    }
    if (state.view !== "nft") return;
    renderHeader();
  }
  const owners = ["", "ufw", "docker", "libvirt", "kernel"];
  box.replaceChildren(...kids(
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
    h("div", { id: "nft-body", class: "nft-body" })
  ));
  renderNftBody();
}

// ---------- CVE (Ubuntu Security API) ----------

const cveView = { watch: null, page: null, items: [], filter: "", loading: false, mit: null, sort: null, tab: "ubuntu",
  // "nascondi corrette": on di default. Su questa macchina 407 CVE in cache su 415 sono gia'
  // corrette o non pertinenti: senza il flag l'elenco utile e' sepolto. Persiste come la lingua
  // (localStorage, non DB: e' una preferenza di visualizzazione, non un dato del firewall).
  // Vale solo per l'elenco Ubuntu: nella scheda "Seguite" una CVE corretta e' informazione
  // cercata (la stavi seguendo perche' ti riguardava), quindi li non si nasconde niente.
  hideResolved: localStorage.getItem("pyla.cve.hideResolved") !== "0" };

/** CVE "a posto": gia' corretta sul kernel installato o mai pertinente.
 *  "update" (corretta upstream, pacchetto da aggiornare) NON conta: serve un'azione. */
function cveResolved(c) {
  return c.verdict === "fixed" || c.verdict === "not-affected";
}

function cveHideResolvedSet(on) {
  cveView.hideResolved = on;
  localStorage.setItem("pyla.cve.hideResolved", on ? "1" : "0");
}

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
  await cveRefresh(true);
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
  if (!ok) return cveRefresh(true);
  let r;
  try {
    r = await call("mitigate", { id: k.id, on });
    cveView.expo = null; // il ruleset è cambiato: i verdetti precedenti non valgono più
  } finally {
    await cveRefresh(true);
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

/**
 * Nota di mitigazione Ubuntu: il testo arriva dall'advisory GIA' multilineo
 * (pallini "- ", passi numerati, blocchi di comandi indentati). In un <p> l'HTML
 * collassa capolinea e indentazione: diventa un muro di testo illeggibile (era il
 * caso di CVE-2026-98432). Qui viene spezzato e ricomposto rispettando la
 * struttura del messaggio, senza riscriverne una parola.
 */
const MIT_CMD = /^(sudo|printf|echo|nft|sed|sysctl|ip|apt|dpkg|tee|systemctl|modprobe|rmmod|update-initramfs|install)\b|^\$ /;

/** Pallino "Requires: ...": l'etichetta prima dei due punti va in grassetto. */
function mitLead(s) {
  const m = /^([A-Z][A-Za-z ]{2,18}):\s+([\s\S]+)$/.exec(s);
  return m ? h("li", {}, h("b", {}, m[1] + ":"), " ", m[2]) : h("li", {}, s);
}

function mitNoteBox(c) {
  const raw = String(c.mitigation || "").replace(/\r\n/g, "\n").split("\n");
  while (raw.length && !raw[0].trim()) raw.shift();
  while (raw.length && !raw[raw.length - 1].trim()) raw.pop();
  if (!raw.length) return null;
  // indent comune del blocco (le note Ubuntu sono rientrate nel messaggio): va
  // rimosso, ma NON l'indentazione relativa, che distingue i comandi dal testo.
  const base = Math.min(...raw.filter((l) => l.trim()).map((l) => l.match(/^ */)[0].length));
  const body = [];
  let list = null, lastLi = null, pre = null, preBase = 0, mode = "";
  // preBase = indent della prima riga del blocco: l'indentazione RELATIVA delle
  // righe successive si conserva (annidamento printf/nft, continuation "\").
  const startPre = (line, rel) => { if (!pre) { pre = []; preBase = rel; } pre.push(line.slice(Math.min(preBase, line.match(/^ */)[0].length))); };
  const flushPre = () => { if (pre) { body.push(h("pre", { class: "mit-cmd" }, pre.join("\n"))); pre = null; preBase = 0; } };
  const flushList = () => { flushPre(); list = null; lastLi = null; };
  for (const line0 of raw) {
    const line = line0.slice(Math.min(base, line0.match(/^ */)[0].length));
    const text = line.trim();
    const rel = line.match(/^ */)[0].length;
    if (!text) { flushList(); mode = ""; continue; }
    const bullet = /^[-\u2022*]\s+(.*)$/.exec(text);
    const step = /^(\d+)[.)]\s+(.*)$/.exec(text);
    if (bullet) {
      flushPre();
      if (!list) { list = h("ul", { class: "mit-facts" }); body.push(list); }
      lastLi = mitLead(bullet[1]); list.append(lastLi); mode = "bullet";
    } else if (step) {
      flushList();
      body.push(h("p", { class: "mit-step" }, h("b", {}, step[1] + ". "), step[2]));
      mode = "step";
    } else if (rel >= 2 && mode === "bullet" && lastLi) {
      lastLi.append(" " + text);                 // continuazione del pallino
    } else if (rel >= 2 && !/^[A-Z]/.test(text) && (mode === "step" || mode === "pre")) {
      startPre(line, rel); mode = "pre";     // blocco di comandi
    } else if (MIT_CMD.test(text)) {
      flushList(); startPre(line, rel); mode = "pre";
    } else {
      flushList(); body.push(h("p", {}, text)); mode = "text";
    }
  }
  flushList();
  return h("div", { class: "mit-note" },
    h("div", { class: "mit-note-head" },
      h("b", {}, "Mitigazione Ubuntu:"),
      h("span", { class: "spacer" }),
      h("button", {
        class: "ghost small", title: "Copia il testo della mitigazione",
        onclick: async () => { await navigator.clipboard.writeText(c.mitigation); toast("Copiato"); },
      }, "Copia")),
    ...body);
}

/**
 * Descrizione dell'advisory nello STESSO riquadro e con lo stesso font della nota
 * di mitigazione: prima era un <pre class="cmds"> monospazio, cioe' un altro tipo
 * di contenuto rispetto al testo dell'advisory (che e' prosa, wrap a ~75 colonne).
 * white-space: pre-wrap perche' i capolinea del changelog kernel e le righe
 * indentate (es. i log KASAN) sono parte del messaggio.
 */
function cveDescBox(c) {
  const text = String(c.description || "").replace(/\r\n/g, "\n").replace(/^\s+|\s+$/g, "");
  if (!text) return null;
  return h("details", { class: "mit-note" },
    h("summary", { class: "mit-note-head" },
      h("b", {}, "Descrizione completa"),
      h("span", { class: "spacer" }),
      h("button", {
        class: "ghost small", title: "Copia il testo della descrizione",
        onclick: async (ev) => {
          ev.preventDefault();               // il click non deve aprire/chiudere il box
          await navigator.clipboard.writeText(c.description); toast("Copiato");
        },
      }, "Copia")),
    h("div", { class: "mit-text" }, text));
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
    c.mitigation ? mitNoteBox(c) : null,
    c.verdict === "vulnerable" || c.verdict === "update" ? mitBox(c) : null,
    cveDescBox(c)
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
  $("#cve-tabs").replaceChildren(...kids(
    h("button", { class: `cve-tab${cveView.tab === "ubuntu" ? " active" : ""}`, onclick: () => cveTabSet("ubuntu") },
      "Vulnerabilità Ubuntu"),
    h("button", { class: `cve-tab${cveView.tab === "seguite" ? " active" : ""}`, onclick: () => cveTabSet("seguite") },
      "Seguite", w ? h("span", { class: "pill muted" }, String(w.items.length)) : null)
  ));
  const ctl = $("#cve-ctl");
  if (cveView.tab === "ubuntu") {
    const hideBox = h("input", {
      type: "checkbox",
      checked: cveView.hideResolved,
      onchange: (ev) => { cveHideResolvedSet(ev.target.checked); renderCveList(); },
    });
    ctl.replaceChildren(...kids(h("input", {
      type: "search", class: "cve-filter", placeholder: "Filtra elenco (es. tcp, mptcp, sctp)",
      value: cveView.filter,
      oninput: (ev) => { cveView.filter = ev.target.value; renderCveList(); },
    }),
    h("label", { class: "inline", title: "Le CVE gia' corrette sul kernel installato o non pertinenti restano fuori dall'elenco; il contatore sopra dice quante ne sono nascoste." },
      hideBox, " nascondi corrette")));
  } else {
    const addInput = h("input", {
      type: "search", class: "cve-id-input", placeholder: "CVE-AAAA-NNNNN", autocomplete: "off",
      onkeydown: (ev) => { if (ev.key === "Enter" && addInput.value.trim()) cveWatch(addInput.value, true); },
    });
    ctl.replaceChildren(...kids(addInput,
      h("button", { class: "ghost", onclick: () => addInput.value.trim() && cveWatch(addInput.value, true) }, "Segui CVE")));
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
      box.replaceChildren(...kids(h("p", { class: "hint" }, "Caricamento…")));
      return;
    }
    box.replaceChildren(...kids(...(w.items.length
      ? w.items.map((c) => cveCard(c, w.system))
      : [h("p", { class: "hint" }, "Nessuna CVE seguita.")])));
    return;
  }
  if (!cveView.page) {
    sub.replaceChildren();
    box.replaceChildren(...kids(h("p", { class: "hint" }, "Caricamento dalla cache locale…")));
    return;
  }
  const sys = cveView.page.system;
  const q = cveView.filter.toLowerCase();
  const matching = cveView.items.filter((c) => !q || `${c.id} ${c.title} ${c.description}`.toLowerCase().includes(q));
  // il flag si applica dopo la ricerca: il contatore deve dire quante ne nasconde A TE, ora
  const hidden = cveView.hideResolved ? matching.filter(cveResolved).length : 0;
  const rows = cveSort(cveView.hideResolved ? matching.filter((c) => !cveResolved(c)) : matching);
  sub.replaceChildren(...kids(
    h("h4", {}, `Kernel ${sys.kernel}: CVE aperte high/critical su ${sys.release} `,
      h("span", { class: "chain-meta" }, `${cveView.items.length} di ${cveView.page.total}`,
        hidden ? ` · ${hidden} corrette nascoste` : "",
        cveView.page.updated_at
          ? h("span", { class: "chain-meta" }, ` · dati ubuntu.com del ${new Date(cveView.page.updated_at * 1000).toLocaleString()}`)
          : null))
  ));
  const watched = new Set((w?.items || []).map((c) => c.id));
  box.replaceChildren(...kids(
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
    rows.length === 0 && hidden > 0
      ? h("p", { class: "hint" },
          `Nessuna CVE vulnerabile o da aggiornare in elenco: ${hidden} corrette sono nascoste dal filtro. `,
          h("button", { class: "ghost small", onclick: () => { cveHideResolvedSet(false); renderCveBody(); } }, "Mostrale"))
      : cveView.items.length === 0
        ? h("p", { class: "hint" }, "Cache CVE vuota: primo scaricamento da ubuntu.com in corso, la lista si popolerà a breve.")
        : null
  ));
}

async function cveLoadWatch() {
  cveView.watch = await call("cve_watched");
  renderCveBody();
  renderNav();
}

// Cache locale: la lista arriva subito; ubuntu.com viene interrogato in background
// dall'app e un evento "cve-refreshed" aggiorna tutto quando i dati nuovi arrivano.
async function cveLoadList() {
  cveView.page = await call("cve_kernel", { limit: 2000 });
  cveView.items = cveView.page.items;
  renderCveBody();
  if (state.view === "cve") renderHeader();
}

listenEvent("cve-refreshed", () => {
  // la cache locale e' cambiata: se la vista CVE e' aperta rileggila, altrimenti
  // aggiorna solo il contatore nella barra (i dati nuovi si vedono aprendo la pagina)
  if (!$("#cve-body")) {
    cveLoadWatch().then(() => renderNav()).catch(() => {});
    return;
  }
  cveLoadWatch().catch(() => {});
  cveLoadList().catch(() => {});
});

async function cveWatch(id, watch) {
  // il backend normalizza l'id (trim + maiuscole) e restituisce la lista: il toast
  // usa l'id canonico, cosi' "cve-2026-98435" digitato a mano non crea un doppione
  const ids = (await call("cve_watch_set", { id, watch })) || [];
  const canon = ids.find((x) => x.toUpperCase() === id.trim().toUpperCase()) || id.trim().toUpperCase();
  toast(watch ? `${canon} seguita` : `${canon} rimossa`);
  // Speculare anche nello stato locale: se il reload tarda o fallisce la riga non
  // resta sullo schermo (era il fastidio: toast "rimossa" e card ancora li').
  if (cveView.watch && !watch) {
    cveView.watch.items = cveView.watch.items.filter((c) => c.id.toUpperCase() !== canon);
    renderCveBody();
  }
  await cveLoadWatch();
}

/** Struttura della vista CVE: titolo, tab e controlli fissi in alto; solo #cve-body scrolla. */
function cveShell() {
  $("#view").replaceChildren(
    h("div", { class: "cve-tabs", id: "cve-tabs" }),
    h("div", { id: "cve-sub" }),
    h("div", { class: "nft-toolbar cve-toolbar", id: "cve-ctl" }),
    h("div", { id: "cve-body", class: "cve-body" }, h("p", { class: "hint" }, "Caricamento dalla cache locale…"))
  );
  renderCveBody();
}

/** `keepList`: dopo una mitigazione o una verifica, l'elenco già caricato resta. */
async function cveRefresh(keepList = false) {
  if (state.view !== "cve") return;
  if (!keepList) {
    cveView.items = [];
    cveView.page = null;
  }
  cveShell();
  await cveLoadMit().catch(() => {});
  await Promise.allSettled([cveLoadWatch(), cveLoadList()]);
  if (state.view === "cve") renderHeader();
}

// ---------- avvio ----------

// cosa renderizza ogni pagina: la vista attiva occupa #view (i dialog restano solo
// per conferme, anteprima applica e dettagli del report)
const VIEW_RENDER = {
  firewall: () => { renderDetail(); renderHeader(); },
  live: viewLive,
  nft: viewNft,
  cve: () => cveRefresh(false),
  report: () => viewReport(),
  history: viewHistory,
};

async function init() {
  for (const id of PANEL_IDS) closeOnButtons($("#" + id));
  // Esc chiude il pannello: su desktop e' la scorciatoia che la gente prova per prima, e
  // con i dialog rimossi non c'e' piu' il comportamento nativo a coprirlo.
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape" || !panelIsOpen()) return;
    ev.preventDefault();
    const cancel = panelEl().querySelector("[data-cancel]");
    if (cancel) cancel.click();
    else closePanel();
  });
  $("#btn-new-set").addEventListener("click", newSet);
  $("#btn-import").addEventListener("click", (ev) => importLive(ev.currentTarget));
  bindImportFileInput();
  $("#btn-rail").addEventListener("click", railToggle);
  $("#btn-toggle-fw").addEventListener("click", (ev) => toggleFirewall(ev.currentTarget));

  // Ctrl+B nasconde/mostra la barra, come in Orbit (non la usa nessun campo testo qui)
  document.addEventListener("keydown", (ev) => {
    if ((ev.ctrlKey || ev.metaKey) && !ev.shiftKey && !ev.altKey && ev.key.toLowerCase() === "b") {
      ev.preventDefault();
      railToggle();
    }
  });

  const saved = localStorage.getItem("pyla.view");
  state.view = PAGES.some((p) => p.view === saved) ? saved : "firewall";
  railApply();
  renderNav();

  state.info = await call("app_info");
  // versione in alto a sinistra; il tooltip porta il path del DB, utile nei report
  const vBadge = $("#app-version");
  if (vBadge) {
    vBadge.textContent = "v" + (state.info.version || "?");
    vBadge.title = `PYLA ${state.info.version || "?"}\ndatabase: ${state.info.db_path}\nhelper: ${state.info.helper_path}`;
  }
  if (!state.info.helper_installed) {
    const w = $("#helper-warning");
    w.textContent =
      `Helper non installato (${state.info.helper_path}): puoi preparare i set, ma per leggere o applicare le regole ` +
      "esegui una volta  sudo packaging/install-helper.sh  dalla cartella del progetto.";
    w.hidden = false;
  }
  await loadStatus();
  await loadRulesets();
  if (state.view !== "firewall") {
    setView(state.view);
    return;
  }
  const active = state.rulesets.find((r) => r.active) || state.rulesets[0];
  if (active) await selectRuleset(active.id);
  else setView("firewall");
}

init();
