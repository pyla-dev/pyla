//! Mitigazioni temporanee per CVE del kernel ancora senza correzione.
//!
//! Sono per sottosistema, non per singola CVE: una CVE il cui titolo inizia con
//! `sctp:`, `mptcp:`, `Bluetooth:`… viene associata alla mitigazione di quel
//! sottosistema. Alcune CVE hanno un'associazione esplicita (es. CVE-2026-98432,
//! che sta nel TCP IPv4 ma è sfruttata via MPTCP).
//!
//! Tutte le mitigazioni sono reversibili e vivono in due soli file gestiti da Pyla:
//! `/etc/sysctl.d/90-pyla-mitigations.conf` e `/etc/modprobe.d/pyla-mitigations.conf`.
//! Ogni blocco inizia con `# pyla:<id>`, così il file si rigenera senza perdere nulla.
//! La lettura dello stato non richiede root; la scrittura la fa `pyla-helper`.

use std::path::Path;

use serde::Serialize;

pub const SYSCTL_FILE: &str = "etc/sysctl.d/90-pyla-mitigations.conf";
pub const MODPROBE_FILE: &str = "etc/modprobe.d/pyla-mitigations.conf";
const MARK: &str = "# pyla:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Scrive `value` in /proc/sys/<path>; annullando torna a `default`.
    Sysctl {
        key: &'static str,
        value: &'static str,
        default: &'static str,
    },
    /// Impedisce il caricamento del modulo (blacklist + install /bin/false) e prova a scaricarlo.
    Module { name: &'static str },
    /// Solo verifica: il modulo è in uso? (nessuna azione possibile senza perdere la funzione)
    InUse {
        modules: &'static [&'static str],
        what: &'static str,
    },
}

#[derive(Debug)]
pub struct Mitigation {
    pub id: &'static str,
    pub label: &'static str,
    /// Prefissi del titolo della CVE (minuscolo, prima dei `:`) che la attivano.
    pub subsystems: &'static [&'static str],
    pub kind: Kind,
    pub impact: &'static str,
}

pub const ALL: &[Mitigation] = &[
    Mitigation {
        id: "mptcp-off",
        label: "Disattiva MPTCP",
        subsystems: &["mptcp"],
        kind: Kind::Sysctl { key: "net.mptcp.enabled", value: "0", default: "1" },
        impact: "Le applicazioni che chiedono Multipath TCP usano TCP normale. Su un portatile non si nota.",
    },
    Mitigation {
        id: "io_uring-off",
        label: "Disattiva io_uring",
        subsystems: &["io_uring"],
        kind: Kind::Sysctl { key: "kernel.io_uring_disabled", value: "2", default: "0" },
        impact: "I programmi che usano io_uring (alcuni database, QEMU, runtime async) falliscono o \
                 ripiegano su un'altra interfaccia. I processi già avviati non cambiano.",
    },
    Mitigation {
        id: "sctp-off",
        label: "Blocca il modulo sctp",
        subsystems: &["sctp"],
        kind: Kind::Module { name: "sctp" },
        impact: "Il protocollo SCTP non è più disponibile (usato solo da telefonia/WebRTC lato server).",
    },
    Mitigation {
        id: "tipc-off",
        label: "Blocca il modulo tipc",
        subsystems: &["tipc"],
        kind: Kind::Module { name: "tipc" },
        impact: "Il protocollo TIPC (cluster) non è più disponibile.",
    },
    Mitigation {
        id: "rds-off",
        label: "Blocca il modulo rds",
        subsystems: &["rds"],
        kind: Kind::Module { name: "rds" },
        impact: "Il protocollo RDS (Oracle/InfiniBand) non è più disponibile.",
    },
    Mitigation {
        id: "atm-off",
        label: "Blocca il modulo atm",
        subsystems: &["atm"],
        kind: Kind::Module { name: "atm" },
        impact: "Il supporto ATM (vecchi modem DSL) non è più disponibile.",
    },
    Mitigation {
        id: "l2tp-off",
        label: "Blocca il modulo l2tp",
        subsystems: &["l2tp"],
        kind: Kind::Module { name: "l2tp_core" },
        impact: "Le VPN L2TP/IPsec smettono di funzionare (WireGuard non è toccato).",
    },
    Mitigation {
        id: "can-off",
        label: "Blocca il modulo can",
        subsystems: &["can"],
        kind: Kind::Module { name: "can" },
        impact: "Il bus CAN (automotive/industriale) non è più disponibile.",
    },
    Mitigation {
        id: "ksmbd-off",
        label: "Blocca il server SMB del kernel (ksmbd)",
        subsystems: &["ksmbd", "smb: server", "smb/server"],
        kind: Kind::Module { name: "ksmbd" },
        impact: "Il server SMB nel kernel non è più disponibile. Samba e l'accesso a share SMB non sono toccati.",
    },
    Mitigation {
        id: "nfsd-off",
        label: "Blocca il server NFS (nfsd)",
        subsystems: &["nfsd"],
        kind: Kind::Module { name: "nfsd" },
        impact: "Questa macchina non può più esportare cartelle via NFS. Montare share NFS altrui funziona ancora.",
    },
    Mitigation {
        id: "bluetooth-off",
        label: "Blocca il Bluetooth",
        subsystems: &["bluetooth"],
        kind: Kind::Module { name: "bluetooth" },
        impact: "IL BLUETOOTH SMETTE DI FUNZIONARE (cuffie, mouse, tastiere). Se il modulo è in uso \
                 l'effetto completo arriva al riavvio.",
    },
    Mitigation {
        id: "kvm-check",
        label: "Uso di KVM",
        subsystems: &["kvm"],
        kind: Kind::InUse { modules: &["kvm_intel", "kvm_amd"], what: "VM KVM/libvirt avviate" },
        impact: "Sfruttabile solo da codice che gira dentro una VM KVM avviata da questa macchina.",
    },
];

/// Associazioni esplicite CVE → mitigazione, con una nota che spiega cosa copre.
pub const CVE_NOTES: &[(&str, &str, &str)] = &[(
    "CVE-2026-98432",
    "mptcp-off",
    "Riduce il rischio, non lo elimina: l'errore è nel TCP IPv4 e l'exploit dimostrato passa da un listener \
     MPTCP. Conta anche chi può raggiungere le porte TCP IPv4 in ascolto (vedi sotto e regole UFW). \
     La correzione vera è il kernel aggiornato.",
)];

pub fn by_id(id: &str) -> Option<&'static Mitigation> {
    ALL.iter().find(|m| m.id == id)
}

/// Sottosistema dal titolo della patch: `"net: sctp: fix…"` → ["net", "sctp", …].
fn prefixes(title: &str) -> Vec<String> {
    let mut out = Vec::new();
    let segs: Vec<&str> = title.split(": ").collect();
    // l'ultimo segmento è la descrizione, i precedenti sono il percorso del sottosistema
    for s in segs.iter().take(segs.len().saturating_sub(1)).take(3) {
        let s = s.trim().to_lowercase();
        out.push(s.clone());
        if let Some((first, _)) = s.split_once('/') {
            out.push(first.to_string()); // "io_uring/rw" → "io_uring"
        }
    }
    if segs.len() >= 3 {
        out.push(format!(
            "{}: {}",
            segs[0].trim().to_lowercase(),
            segs[1].trim().to_lowercase()
        ));
    }
    out
}

/// Mitigazione applicabile a una CVE (associazione esplicita o sottosistema dal titolo) e nota.
pub fn for_cve(id: &str, title: &str) -> Option<(&'static Mitigation, Option<&'static str>)> {
    if let Some((_, m, note)) = CVE_NOTES.iter().find(|(c, _, _)| *c == id) {
        return by_id(m).map(|m| (m, Some(*note)));
    }
    let p = prefixes(title);
    ALL.iter()
        .find(|m| m.subsystems.iter().any(|s| p.iter().any(|x| x == s)))
        .map(|m| (m, None))
}

// ---------- file gestiti ----------

/// Id delle mitigazioni presenti nel file (righe `# pyla:<id>`).
pub fn parse_active(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix(MARK))
        .map(|s| s.trim().to_string())
        .filter(|s| by_id(s).is_some())
        .collect()
}

const HEADER: &str = "# Gestito da Pyla (mitigazioni CVE temporanee). Modificare dall'app.\n";

pub fn render_sysctl(active: &[&Mitigation]) -> String {
    let mut s = String::from(HEADER);
    for m in active {
        if let Kind::Sysctl { key, value, .. } = m.kind {
            s.push_str(&format!("{MARK}{}\n{key} = {value}\n", m.id));
        }
    }
    s
}

pub fn render_modprobe(active: &[&Mitigation]) -> String {
    let mut s = String::from(HEADER);
    for m in active {
        if let Kind::Module { name } = m.kind {
            s.push_str(&format!(
                "{MARK}{}\nblacklist {name}\ninstall {name} /bin/false\n",
                m.id
            ));
        }
    }
    s
}

pub fn sysctl_path(key: &str) -> String {
    format!("proc/sys/{}", key.replace('.', "/"))
}

// ---------- verifica (senza root) ----------

#[derive(Debug, Serialize, Clone)]
pub struct Check {
    pub id: &'static str,
    pub label: &'static str,
    pub impact: &'static str,
    /// Applicabile con il pulsante Mitiga (false per le sole verifiche).
    pub actionable: bool,
    /// Configurata nei file di Pyla.
    pub configured: bool,
    /// mitigata | al-riavvio | esposta | non-in-uso | in-uso
    pub state: &'static str,
    pub facts: Vec<String>,
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel))
        .ok()
        .map(|s| s.trim().to_string())
}

fn loaded(root: &Path, module: &str) -> bool {
    root.join("sys/module").join(module).is_dir()
}

pub fn active_ids(root: &Path) -> Vec<String> {
    let mut v = parse_active(&read(root, SYSCTL_FILE).unwrap_or_default());
    v.extend(parse_active(&read(root, MODPROBE_FILE).unwrap_or_default()));
    v
}

pub fn check(m: &'static Mitigation, root: &Path) -> Check {
    let configured = active_ids(root).iter().any(|x| x == m.id);
    let mut facts = Vec::new();
    let (actionable, state) = match m.kind {
        Kind::Sysctl { key, value, .. } => {
            let live = read(root, &sysctl_path(key));
            facts.push(format!(
                "{key} = {}",
                live.as_deref().unwrap_or("non presente")
            ));
            let ok = live.as_deref() == Some(value);
            (true, if ok { "mitigata" } else { "esposta" })
        }
        Kind::Module { name } => {
            let is_loaded = loaded(root, name);
            facts.push(format!(
                "modulo {name}: {}",
                if is_loaded {
                    "caricato"
                } else {
                    "non caricato (si carica da solo alla prima richiesta)"
                }
            ));
            facts.push(format!(
                "caricamento bloccato: {}",
                if configured { "sì" } else { "no" }
            ));
            let state = match (configured, is_loaded) {
                (true, false) => "mitigata",
                (true, true) => "al-riavvio",
                (false, _) => "esposta",
            };
            (true, state)
        }
        Kind::InUse { modules, what } => {
            let users: u32 = modules
                .iter()
                .filter_map(|mo| read(root, &format!("sys/module/{mo}/refcnt")))
                .filter_map(|r| r.parse::<u32>().ok())
                .sum();
            facts.push(format!("{what}: {users}"));
            (false, if users > 0 { "in-uso" } else { "non-in-uso" })
        }
    };
    Check {
        id: m.id,
        label: m.label,
        impact: m.impact,
        actionable,
        configured,
        state,
        facts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(title: &str) -> Option<&'static str> {
        for_cve("CVE-0000-0000", title).map(|(m, _)| m.id)
    }

    #[test]
    fn classify() {
        assert_eq!(
            id("sctp: check RCV_SHUTDOWN after the sendmsg connect wait"),
            Some("sctp-off")
        );
        assert_eq!(id("net: sctp: fix something"), Some("sctp-off"));
        assert_eq!(id("Bluetooth: hci_sync: fix UAF"), Some("bluetooth-off"));
        assert_eq!(id("io_uring/rw: fix task_work"), Some("io_uring-off"));
        assert_eq!(
            id("io_uring: fix task_work add use-after-free with SQPOLL"),
            Some("io_uring-off")
        );
        assert_eq!(
            id("KVM: x86: Re-pend GET_NESTED_STATE_PAGES"),
            Some("kvm-check")
        );
        assert_eq!(id("mptcp: options: reset DSS fields"), Some("mptcp-off"));
        assert_eq!(id("audit: fix exe mark UAF in kill_rules()"), None);
        assert_eq!(id("can we fix this without a colon"), None);
        let (m, note) = for_cve("CVE-2026-98432", "ipv4: free inet_opt").unwrap();
        assert_eq!(m.id, "mptcp-off");
        assert!(note.is_some());
    }

    #[test]
    fn files_roundtrip() {
        let act = [by_id("mptcp-off").unwrap(), by_id("sctp-off").unwrap()];
        let s = render_sysctl(&act);
        let m = render_modprobe(&act);
        assert!(s.contains("net.mptcp.enabled = 0") && !s.contains("sctp"));
        assert!(m.contains("install sctp /bin/false") && !m.contains("mptcp ="));
        assert_eq!(parse_active(&s), vec!["mptcp-off"]);
        assert_eq!(parse_active(&m), vec!["sctp-off"]);
        assert!(parse_active("# pyla:bogus\n").is_empty());
    }

    /// Sistema reale: `cargo test -p pyla-core -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_checks() {
        for m in ALL {
            let c = check(m, Path::new("/"));
            println!("{:14} {:11} {:?}", c.id, c.state, c.facts);
        }
    }
}
