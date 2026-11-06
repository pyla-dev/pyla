//! Exposure check v3 — quali listener TCP sono raggiungibili dall'esterno.
//!
//! Stima, non sonda: simula una connessione TCP **nuova** (SYN) dall'esterno
//! verso ogni listener e percorre le catene base con hook `input` del ruleset
//! nftables live (famiglie inet/ip/ip6, salti `jump`/`goto` seguiti).
//! Semantica: prima-verdetto-risolve; a ogni catena senza verdetto vale la sua
//! policy; e.g. `policy accept; drop ip protocol tcp` = chiuso.
//! Semplificazioni dichiarate: le regole `ct state` senza `new`/`sync` non
//! matchano (connessione nuova); accetta con condizioni non valutabili (saddr,
//! interfacce diverse da lo, set/mappa) diventano «condizionata»; sintassi
//! ignota segnalata come condizione, mai ignorata in silenzio; le estensioni
//! header IPv6 (`rt`, `exthdr`, `hbh`, `frag`, `auth`) non matchano il SYN TCP
//! ipotizzato (che non porta Routing Header/nexthdr option) e gli statement non
//! terminanti (`log`, `notrack`, `ct set`, `mark set`, `flow add`, `queue`) non
//! sono condizioni di match.
//!
//! v3: un listener dual-stack (ascolta su `::`) viene valutato **due volte**,
//! una per famiglia di protocollo (IPv4 e IPv6), perche' le catene `ip` e `ip6`
//! sono percorsi distinti del kernel. Il verdetto mostrato e' il piu'
//! permissivo tra le due famiglie (se una delle due arriva alla porta, la porta
//! e' raggiungibile), e `per_family` riporta il verdetto di ciascuna. Prima di
//! v3 la valutazione si fermava alla prima decisione con le tabelle `ip` valutate
//! prima di `ip6`: un `drop` IPv4 mascherava una `accept` IPv6 (falso negativo).

use std::net::Ipv6Addr;
use std::path::Path;

use serde::Serialize;

use crate::nft::{parse_ruleset, NftChain, NftTable};

/// Listener TCP letto da /proc/net/tcp e /proc/net/tcp6 (stato LISTEN).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Listener {
    pub addr: String,
    pub port: u16,
    pub family: u8,
    /// "locale" | "tutte" | "link-local" | "indirizzo"
    pub scope: &'static str,
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel)).ok()
}

pub fn listeners(root: &Path) -> Vec<Listener> {
    let mut out = Vec::new();
    for (rel, fam) in [("proc/net/tcp", 4u8), ("proc/net/tcp6", 6)] {
        let Some(text) = read(root, rel) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.get(3) != Some(&"0A") {
                continue;
            }
            let Some((hex, p)) = f.get(1).and_then(|a| a.split_once(':')) else {
                continue;
            };
            let Ok(port) = u16::from_str_radix(p, 16) else {
                continue;
            };
            let Some((addr, scope)) = parse_addr(hex, fam) else {
                continue;
            };
            out.push(Listener {
                addr,
                port,
                family: fam,
                scope,
            });
        }
    }
    out.sort_by(|a, b| (a.port, &a.addr).cmp(&(b.port, &b.addr)));
    out.dedup();
    out
}

fn parse_addr(hex: &str, fam: u8) -> Option<(String, &'static str)> {
    if fam == 4 {
        let ip = u32::from_str_radix(hex, 16).ok()?.to_le_bytes();
        let scope = if ip[0] == 127 {
            "locale"
        } else if ip == [0, 0, 0, 0] {
            "tutte"
        } else {
            "indirizzo"
        };
        Some((format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]), scope))
    } else {
        if hex.len() != 32 {
            return None;
        }
        let mut oct = [0u8; 16];
        for g in 0..4 {
            let w = u32::from_str_radix(&hex[g * 8..g * 8 + 8], 16).ok()?;
            oct[g * 4..g * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let ip = Ipv6Addr::from(oct);
        let scope = if ip.is_loopback() {
            "locale"
        } else if ip.is_unspecified() {
            "tutte"
        } else if (ip.segments()[0] & 0xffc0) == 0xfe80 {
            "link-local"
        } else {
            "indirizzo"
        };
        Some((ip.to_string(), scope))
    }
}

// ---------- valutazione contro il ruleset ----------

#[derive(Debug, Clone, Serialize)]
pub struct Exposure {
    pub addr: String,
    pub port: u16,
    pub family: u8,
    pub scope: &'static str,
    /// "locale" | "aperta" | "condizionata" | "bloccata" | "ignota".
    /// Per i dual-stack e' il verdetto piu' permissivo tra le famiglie.
    pub verdict: &'static str,
    /// Perché: regola/catena che decide, o condizioni espressioni non valutate.
    pub detail: String,
    /// Popolato solo quando le famiglie discordano (ascolto su `::`): verdetto e
    /// motivo per singola famiglia di protocollo (4, 6).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub per_family: Vec<FamilyVerdict>,
}

/// Verdetto del listener per una famiglia di protocollo (4 = IPv4, 6 = IPv6).
#[derive(Debug, Clone, Serialize)]
pub struct FamilyVerdict {
    pub family: u8,
    pub verdict: &'static str,
    pub detail: String,
}

pub fn assess(listeners: &[Listener], ruleset_text: &str) -> Vec<Exposure> {
    let tables = parse_ruleset(ruleset_text);
    listeners.iter().map(|l| assess_one(l, &tables)).collect()
}

fn assess_one(l: &Listener, tables: &[NftTable]) -> Exposure {
    if l.scope == "locale" {
        return Exposure {
            addr: l.addr.clone(),
            port: l.port,
            family: l.family,
            scope: l.scope,
            verdict: "locale",
            detail: "in ascolto solo su loopback: non raggiungibile dalla rete".into(),
            per_family: Vec::new(),
        };
    }
    let (v4, v6) = covered_families(l);
    let fams: Vec<u8> = match (v4, v6) {
        (true, true) => vec![4, 6],
        (true, false) => vec![4],
        _ => vec![6],
    };
    let parts: Vec<FamilyVerdict> = fams
        .iter()
        .map(|&pf| assess_family(l, tables, pf))
        .collect();
    let deciding = parts
        .iter()
        .max_by_key(|f| rank(f.verdict))
        .cloned()
        .unwrap_or(FamilyVerdict {
            family: fams[0],
            verdict: "ignota",
            detail: String::new(),
        });
    let discordanti = parts.iter().any(|f| f.verdict != deciding.verdict);
    Exposure {
        addr: l.addr.clone(),
        port: l.port,
        family: l.family,
        scope: l.scope,
        verdict: deciding.verdict,
        detail: deciding.detail,
        per_family: if discordanti { parts } else { Vec::new() },
    }
}

/// "aperta" batte "condizionata", che batte "ignota", che batte "bloccata":
/// se una famiglia raggiunge la porta la porta e' raggiungibile; se una famiglia
/// non e' valutabile non si puo' dichiarare la porta chiusa.
fn rank(v: &str) -> u8 {
    match v {
        "aperta" => 4,
        "condizionata" => 3,
        "ignota" => 2,
        "bloccata" => 1,
        _ => 0,
    }
}

/// Valuta il SYN verso il listener assumendo un pacchetto della famiglia `pf`
/// (4 o 6): solo le catene inet della famiglia data, con `visited` proprio (le
/// tabelle `ip` e `ip6` possono avere lo stesso nome, es. `filter`).
fn assess_family(l: &Listener, tables: &[NftTable], pf: u8) -> FamilyVerdict {
    let fv = |verdict: &'static str, detail: String| FamilyVerdict {
        family: pf,
        verdict,
        detail,
    };
    let mut chains: Vec<(&NftTable, &NftChain)> = Vec::new();
    for t in tables {
        let fam_ok = t.family == "inet"
            || (t.family == "ip" && pf == 4)
            || ((t.family == "ip6" || t.family == "ipv6") && pf == 6);
        if !fam_ok {
            continue;
        }
        for c in &t.chains {
            if c.hook.as_deref().is_some_and(|h| h.contains("hook input")) {
                chains.push((t, c));
            }
        }
    }
    chains.sort_by_key(|(_, c)| hook_priority(c.hook.as_deref().unwrap_or("")));
    if chains.is_empty() {
        return fv("ignota", "nessuna catena con hook input nel ruleset".into());
    }
    let mut visited = Vec::new();
    for (t, c) in chains {
        match eval_chain(t, c, l, pf, &mut visited) {
            Some(Term::Accept { conds, src }) => {
                return fv(
                    if conds.is_empty() {
                        "aperta"
                    } else {
                        "condizionata"
                    },
                    fmt_src(&src, &conds),
                )
            }
            Some(Term::Killed { src }) => return fv("bloccata", fmt_src(&src, &[])),
            None => {
                if c.policy.as_deref() == Some("drop") {
                    return fv(
                        "bloccata",
                        format!(
                            "nessuna regola corrisponde; policy drop di {}:{}",
                            t.family, c.name
                        ),
                    );
                }
            }
        }
    }
    fv(
        "aperta",
        "nessuna regola intercetta il traffico e tutte le catene input hanno policy accept".into(),
    )
}

/// Famiglie di catene da valutare: :: copre anche IPv4 (v4-mapped).
fn covered_families(l: &Listener) -> (bool, bool) {
    match l.family {
        4 => (true, false),
        _ => {
            let also4 = l
                .addr
                .parse::<Ipv6Addr>()
                .is_ok_and(|i| i.is_unspecified() || i.to_ipv4().is_some());
            (also4, true)
        }
    }
}

#[derive(Debug)]
enum Term {
    Accept { conds: Vec<String>, src: String },
    Killed { src: String },
}

fn fmt_src(src: &str, conds: &[String]) -> String {
    if conds.is_empty() {
        src.to_string()
    } else {
        format!("{src} — condizioni non valutate: {}", conds.join(", "))
    }
}

fn hook_priority(hook: &str) -> i32 {
    let w = hook
        .split_whitespace()
        .skip_while(|w| *w != "priority")
        .nth(1)
        .unwrap_or("filter");
    w.parse().unwrap_or(match w {
        "raw" => -300,
        "conntrack" => -200,
        "mangle" => -150,
        "security" => 50,
        _ => 0,
    })
}

fn eval_chain<'a>(
    t: &'a NftTable,
    c: &'a NftChain,
    l: &Listener,
    pf: u8,
    visited: &mut Vec<(&'a str, &'a str, &'a str)>,
) -> Option<Term> {
    // la chiave include la famiglia della tabella: `table ip filter` e
    // `table ip6 filter` hanno lo stesso nome e catene omonime (INPUT)
    if visited.contains(&(t.family.as_str(), t.name.as_str(), c.name.as_str())) {
        return None;
    }
    visited.push((t.family.as_str(), t.name.as_str(), c.name.as_str()));
    for r in &c.rules {
        let toks: Vec<&str> = r.text.split_whitespace().collect();
        let Some(vi) = toks.iter().position(|w| {
            matches!(
                *w,
                "accept" | "drop" | "reject" | "return" | "jump" | "goto" | "continue"
            )
        }) else {
            continue;
        };
        let (matches_slice, term) = (trim_at_statement(&toks[..vi]), &toks[vi..]);
        match term[0] {
            "continue" => continue,
            "return" => {
                let (m, _) = rule_matches(matches_slice, l, pf);
                if m {
                    return None;
                }
            }
            "jump" | "goto" => {
                let (m, _) = rule_matches(matches_slice, l, pf);
                if !m {
                    continue;
                }
                let dst = term.get(1).copied().unwrap_or("");
                if let Some(target) = t.chains.iter().find(|x| x.name == dst) {
                    if let Some(r2) = eval_chain(t, target, l, pf, visited) {
                        return Some(r2);
                    }
                }
            }
            v @ ("accept" | "drop" | "reject") => {
                let (m, conds) = rule_matches(matches_slice, l, pf);
                if !m {
                    continue;
                }
                let src = format!("{}:{} → {}", t.family, c.name, r.text);
                // anche un blocco con condizioni non valutabili è «dipende»:
                // meglio «condizionata» che assumere che cada su di noi
                return Some(if v == "accept" || !conds.is_empty() {
                    Term::Accept { conds, src }
                } else {
                    Term::Killed { src }
                });
            }
            _ => {}
        }
    }
    None
}

/// Tronca la parte di match di una regola al primo **statement** non terminante
/// (`log`, `notrack`, `ct set`, `mark set`, `flow add`, `queue`, `helper`,
/// `synproxy`, `obj set`): tutto cio' che segue non e piu' una condizione di
/// match. Se restasse, il parser lo scambierebbe per condizione e tramuterebbe
/// un `drop` pieno in «condizionata» (es. `... log prefix "[UFW BLOCK]"`).
fn trim_at_statement<'a>(toks: &'a [&'a str]) -> &'a [&'a str] {
    let mut i = 0usize;
    while i < toks.len() {
        let t = toks[i];
        let is_statement = matches!(
            t,
            "log" | "notrack" | "helper" | "expect" | "synproxy" | "obj"
        ) || (matches!(t, "ct" | "mark" | "meta" | "meter" | "flow")
            && toks.get(i + 1).copied().is_some_and(|n| {
                matches!(
                    n,
                    "set" | "add" | "update" | "delete" | "destroy" | "timeout"
                )
            }))
            || t == "queue"
            || t == "vmap";
        if is_statement {
            return &toks[..i];
        }
        i += 1;
    }
    toks
}

/// Valuta la sola parte di match di una regola contro una connessione TCP
/// **nuova** (SYN) proveniente dall'esterno verso `l`. Ritorna
/// (matcha?, condizioni non valutabili): se matcha con condizioni il verdetto
/// eventuale diventa «condizionata». Sintassi ignota = condizione,
/// mai ignorata in silenzio.
fn rule_matches(toks: &[&str], l: &Listener, pf: u8) -> (bool, Vec<String>) {
    let mut conds: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < toks.len() {
        let t = toks[i];
        // forma generica: <parola> [!=] <valore>
        let neg = toks.get(i + 1) == Some(&"!=");
        let vi = i + if neg { 2 } else { 1 };
        let val = toks.get(vi).copied().unwrap_or("").trim_matches('"');
        match t {
            "ct" => {
                if toks.get(vi) == Some(&"state") {
                    let (vals, used) = ct_state_set(&toks[vi + 1..]);
                    let known = vals.iter().all(|v| {
                        matches!(
                            v.as_str(),
                            "new"
                                | "sync"
                                | "established"
                                | "related"
                                | "untracked"
                                | "invalid"
                                | "available"
                                | "confirmed"
                                | "snat"
                                | "dnat"
                                | "expected"
                                | "seen-reply"
                                | "assured"
                        )
                    });
                    if !known {
                        conds.push(format!("ct state {}", vals.join(",")));
                    } else {
                        // la SYN nuova è «new»; «sync» solo traffico backup conntrack
                        let m = vals.iter().any(|v| v == "new");
                        if !(m ^ neg) {
                            return (false, conds);
                        }
                    }
                    i = vi + 1 + used;
                    continue;
                }
                // ct status/mark/direction: non valutabili → condizione
                conds.push(toks[i..toks.len().min(vi + 1)].join(" "));
                i = vi + 1;
                continue;
            }
            "iifname" | "iif" => {
                // dall'esterno non arriva mai da lo; sulle altre interfacce
                // non sappiamo da quale arriva il traffico → condizione
                if val == "lo" {
                    if neg {
                        i = vi + 1;
                        continue;
                    }
                    return (false, conds);
                }
                conds.push(format!("{t}{} {val}", if neg { " !=" } else { "" }));
                i = vi + 1;
                continue;
            }
            "oifname" | "oif" => {
                conds.push(format!("{t}{} {val}", if neg { " !=" } else { "" }));
                i = vi + 1;
                continue;
            }
            "dport" => match port_cmp(toks, vi, l.port) {
                Some((m, next)) => {
                    if !m {
                        return (false, conds);
                    }
                    i = next;
                    continue;
                }
                None => {
                    conds.push(format!("dport {}", toks[vi..].join(" ")));
                    break;
                }
            },
            "tcp" => {
                // protocollo: è tcp, resto da vedere (dport, flags, option…)
                i = vi;
                continue;
            }
            "udp" | "udp-lite" | "icmp" | "icmpv6" | "igmp" | "esp" | "ah" | "sctp" | "gre"
            | "ospf" | "arp" => return (false, conds),
            // Estensioni/headers IPv6: il SYN ipotizzato non porta Routing
            // Header, Hop-by-Hop, fragmenti o ESP/AH, quindi non matchano.
            // `rt`/`exthdr`/`hbh`/`frag` sono IPv6-only: su IPv4 non matchano.
            // Estensioni header IPv6: il SYN TCP ipotizzato non porta Routing
            // Header, Hop-by-Hop, fragmenti, ESP/AH: la regola non si applica.
            "rt" | "exthdr" | "hbh" | "frag" | "auth" => return (false, conds),
            // `limit rate N/minute`: condizione di rate-limit non valutabile
            "limit" if toks.get(vi) == Some(&"rate") => {
                conds.push(format!("limit {}", toks[vi + 1..].join(" ")));
                break;
            }
            // `xt match "icmp6"`: modulo x_tables, non valutabile
            "xt" => {
                conds.push(format!("xt {}", toks[vi..].join(" ")));
                break;
            }
            p @ ("ip" | "ip6") => {
                // `ip ...` descrive header IPv4: non matcha mai un pacchetto
                // IPv6, e `ip6 ...` non matcha mai un IPv4 (stessa porta,
                // percorsi distinti nel kernel)
                if (p == "ip" && pf != 4) || (p == "ip6" && pf != 6) {
                    return (false, conds);
                }
                match val {
                    "protocol" | "nexthdr" => {
                        // `ip protocol <proto>` / `ip6 nexthdr <proto>`: vi punta
                        // alla keyword, il valore (ed eventualmente `!=`) viene DOPO
                        let bang = toks.get(vi + 1) == Some(&"!=");
                        let pv = toks
                            .get(vi + 1 + if bang { 1 } else { 0 })
                            .copied()
                            .unwrap_or("");
                        let np = bang;
                        let m = match pv {
                            "tcp" => !np,
                            // l4proto diversi da tcp: il SYN ipotizzato non
                            // matcha. `ipv6-icmp`/`icmpx`/`ipcomp`/`ipv6-frag`
                            // sono i nomi con cui nft stampaproto l'header.
                            "udp" | "icmp" | "icmpv6" | "ipv6-icmp" | "ipcomp" | "ipv6-frag"
                            | "igmp" | "esp" | "ah" | "sctp" | "gre" | "ospf" | "ipv6" | "ipv4"
                            | "ipip" | "ipip6" | "vrrp" | "pim" | "udplite" | "17" | "1" | "58"
                            | "2" | "132" | "43" | "44" | "51" | "47" | "115" | "0" => np,
                            _ => {
                                conds.push(toks[i..(vi + 3).min(toks.len())].join(" "));
                                true
                            }
                        };
                        if !m {
                            return (false, conds);
                        }
                        i = vi + 2 + if bang { 1 } else { 0 };
                        continue;
                    }
                    // `ip saddr <prefisso>`: `val` e la keyword, l'indirizzo e'
                    // il token dopo (la keyword stessa non e' mai un prefisso)
                    "saddr" | "daddr" => {
                        let sb = toks.get(vi + 1) == Some(&"!=");
                        let addr = toks
                            .get(vi + 1 + if sb { 1 } else { 0 })
                            .copied()
                            .unwrap_or("")
                            .trim_matches('"');
                        if !(addr == "0.0.0.0/0" || addr == "::/0" || addr.is_empty()) {
                            conds.push(format!(
                                "ip{} {}{} {addr}",
                                if p == "ip6" { "6" } else { "" },
                                val,
                                if sb { " !" } else { "" }
                            ));
                        }
                        i = vi + 2 + if sb { 1 } else { 0 };
                        continue;
                    }
                    _ => {
                        conds.push(toks[i..(vi + 1).min(toks.len())].join(" "));
                        i = vi + 1;
                        continue;
                    }
                }
            }
            "meta" => {
                match val {
                    "l4proto" => {
                        let bang = toks.get(vi + 1) == Some(&"!=");
                        let pv = toks
                            .get(vi + 1 + if bang { 1 } else { 0 })
                            .copied()
                            .unwrap_or("");
                        let np = bang;
                        let m = match pv {
                            "tcp" => !np,
                            "udp" | "icmp" | "icmpv6" | "ipv6-icmp" | "ipcomp" | "ipv6-frag"
                            | "igmp" | "esp" | "ah" | "sctp" | "gre" | "ospf" | "17" | "1"
                            | "58" | "2" | "132" | "43" | "44" | "51" | "47" => np,
                            _ => {
                                conds.push(toks[i..(vi + 3).min(toks.len())].join(" "));
                                true
                            }
                        };
                        if !m {
                            return (false, conds);
                        }
                        i = vi + 2 + if bang { 1 } else { 0 };
                        continue;
                    }
                    "iifname" | "oifname" => {
                        let mb = toks.get(vi + 1) == Some(&"!=");
                        let iface = toks
                            .get(vi + 1 + if mb { 1 } else { 0 })
                            .copied()
                            .unwrap_or("")
                            .trim_matches('"');
                        if iface == "lo" {
                            // dall'esterno il SYN non arriva mai da lo
                            if mb {
                                i = vi + 3;
                                continue;
                            }
                            return (false, conds);
                        }
                        conds.push(format!("meta {val}{} {iface}", if mb { " !" } else { "" }));
                        i = vi + 2 + if mb { 1 } else { 0 };
                        continue;
                    }
                    "pkttype" => {
                        let mb = toks.get(vi + 1) == Some(&"!=");
                        let ty = toks
                            .get(vi + 1 + if mb { 1 } else { 0 })
                            .copied()
                            .unwrap_or("");
                        if !((ty == "host") ^ mb) {
                            return (false, conds);
                        }
                        i = vi + 2 + if mb { 1 } else { 0 };
                        continue;
                    }
                    _ => {
                        conds.push(toks[i..(vi + 1).min(toks.len())].join(" "));
                        i = vi + 1;
                        continue;
                    }
                }
            }
            "fib" => {
                // fib daddr type local: il destinatario siamo noi → vero
                if toks.get(vi) == Some(&"daddr") && toks.get(vi + 1) == Some(&"type") {
                    let bang = toks.get(vi + 2) == Some(&"!=");
                    let ty = toks
                        .get(vi + 2 + if bang { 1 } else { 0 })
                        .copied()
                        .unwrap_or("");
                    let is_local = ty == "local";
                    if !(is_local ^ bang) {
                        return (false, conds);
                    }
                    i = vi + 2 + if bang { 2 } else { 1 };
                    continue;
                }
                conds.push(format!("fib {}", toks[vi..].join(" ")));
                break;
            }
            other => {
                conds.push(if vi < toks.len() {
                    format!("{other} {val}")
                } else {
                    other.to_string()
                });
                i = vi + 1;
                continue;
            }
        }
    }
    (true, conds)
}

/// Set di `ct state`: `new`, `established,related`, `{ new, untracked }`.
/// Ritorna (valori, token consumiti).
fn ct_state_set(toks: &[&str]) -> (Vec<String>, usize) {
    if toks.is_empty() {
        return (Vec::new(), 0);
    }
    if toks[0] == "{" {
        let mut vals = Vec::new();
        let mut i = 1;
        while i < toks.len() && toks[i] != "}" {
            if toks[i] != "," {
                vals.extend(toks[i].split(',').map(|s| s.trim().to_string()));
            }
            i += 1;
        }
        return (vals, i + 1);
    }
    let vals = toks[0].split(',').map(|s| s.trim().to_string()).collect();
    (vals, 1)
}

/// `dport` con eventuale `!=`: ritorna (match?, token consumiti da `at`).
fn port_cmp(toks: &[&str], at: usize, port: u16) -> Option<(bool, usize)> {
    let neg = toks.get(at) == Some(&"!=");
    let j = at + if neg { 1 } else { 0 };
    let (hit, used) = port_set(&toks[j..], port)?;
    Some((hit ^ neg, j + used))
}

/// Porta singola, intervallo `a-b`, lista `{ 22, 80 }`.
/// None = sintassi non interpretata (set/mappe `$x`, `@x`, vmap…).
fn port_set(toks: &[&str], port: u16) -> Option<(bool, usize)> {
    if toks.is_empty() {
        return None;
    }
    if toks[0] == "{" {
        let mut i = 1;
        let mut hit = false;
        while i < toks.len() && toks[i] != "}" {
            if toks[i] == "," {
                i += 1;
                continue;
            }
            if toks[i].starts_with(['$', '@']) || toks[i].contains('.') {
                return None;
            }
            hit |= port_one(toks[i], port)?;
            i += 1;
        }
        if toks.get(i) != Some(&"}") {
            return None;
        }
        return Some((hit, i + 1));
    }
    if toks[0].starts_with(['$', '@']) || toks[0].contains('.') {
        return None;
    }
    Some((port_one(toks[0], port)?, 1))
}

/// `22` o `22-80`: Some(p == port). None se non numerica.
/// Nelle liste nft la virgola è appiccicata al valore (`{ 53, 67 }`).
fn port_one(tok: &str, port: u16) -> Option<bool> {
    let tok = tok.trim_end_matches(',');
    if let Some((a, b)) = tok.split_once('-') {
        let (a, b) = (a.parse::<u16>().ok()?, b.parse::<u16>().ok()?);
        return Some((a..=b).contains(&port));
    }
    Some(tok.parse::<u16>().ok()? == port)
}
#[cfg(test)]
mod tests {

    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("pyla-exp-{}", std::process::id()));
        std::fs::create_dir_all(root.join("proc/net")).unwrap();
        std::fs::write(
            root.join("proc/net/tcp"),
            "  sl  local_address rem_address   st\n\
             0: 0100007F:13AD 00000000:0000 0A\n\
             1: 00000000:0016 00000000:0000 0A\n\
             2: 00000000:14EB 00000000:0000 0A\n\
             3: 080200C0:0035 00000000:0000 0A\n",
        )
        .unwrap();
        std::fs::write(
            root.join("proc/net/tcp6"),
            "  sl  local_address                         rem_address                             st\n\
             0: 00000000000000000000000001000000:13AD 00000000000000000000000000000000:0000 0A\n\
             1: 00000000000000000000000000000000:22B8 00000000000000000000000000000000:0000 0A\n\
             2: 000080FE000000000000000000000000:0147 00000000000000000000000000000000:0000 0A\n",
        )
        .unwrap();
        root
    }

    #[test]
    fn parse_proc_listeners() {
        let ls = listeners(&fixture_root());
        let find = |a: &str, p: u16| {
            ls.iter()
                .find(|x| x.addr == a && x.port == p)
                .map(|x| x.scope)
        };
        assert_eq!(find("127.0.0.1", 5037), Some("locale"));
        assert_eq!(find("0.0.0.0", 22), Some("tutte"));
        assert_eq!(find("192.0.2.8", 53), Some("indirizzo"));
        assert_eq!(find("::", 8888), Some("tutte"));
        assert_eq!(find("fe80::1", 0), None);
        // fe80:: = word0 «000080FE» (little-endian), porta 0x0147=327
        assert_eq!(find("fe80::", 327), Some("link-local"));
        std::fs::remove_dir_all(fixture_root()).ok();
    }

    const UFW: &str = "\
table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
		iifname \"lo\" accept
		jump ufw-before-input
	}
	chain ufw-before-input {
		ct state new jump ufw-user-input
		reject
	}
	chain ufw-user-input {
		tcp dport 22 ip saddr 198.51.100.0/24 accept
		tcp dport { 53, 67 } accept
	}
}
table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		drop ip protocol tcp tcp dport 9999
	}
}
";

    fn l(addr: &str, port: u16, fam: u8, scope: &'static str) -> Listener {
        Listener {
            addr: addr.into(),
            port,
            family: fam,
            scope,
        }
    }

    fn verdict(a: &str, p: u16, fam: u8) -> String {
        let e = assess(&[l(a, p, fam, "tutte")], UFW);
        e[0].verdict.to_string()
    }

    #[test]
    fn verdicts_against_ufw_layout() {
        // ssh accettata solo da una rete: condizionata
        assert_eq!(verdict("0.0.0.0", 22, 4), "condizionata");
        // dns nella lista senza condizioni: aperta
        assert_eq!(verdict("0.0.0.0", 53, 4), "aperta");
        // porta fuori lista: il reject in ufw-before-input la blocca
        assert_eq!(verdict("0.0.0.0", 8080, 4), "bloccata");
        // :: copre IPv4: 8888 non c'è in nessuna regola → reject di inet; per il
        // SYN IPv4 la catena ip filter (priority filter=0, dopo inet a 0? stesso
        // ordine stabile) non arriva prima del reject
        assert_eq!(verdict("::", 8080, 6), "bloccata");
    }

    #[test]
    fn policy_semantics() {
        // policy accept + drop tcp: il SYN tcp è bloccato dalla policy-chains
        let rs = "table inet f {\n chain input {\n  type filter hook input priority 0; policy accept;\n  drop ip protocol tcp\n }\n}\n";
        assert_eq!(
            assess(&[l("0.0.0.0", 1, 4, "tutte")], rs)[0].verdict,
            "bloccata"
        );
        // nessuna catena input
        assert_eq!(
            assess(&[l("0.0.0.0", 1, 4, "tutte")], "")[0].verdict,
            "ignota"
        );
        // tutte policy accept senza regole: aperta
        let rs2 = "table inet f {\n chain input {\n  type filter hook input priority 0; policy accept;\n }\n}\n";
        assert_eq!(
            assess(&[l("0.0.0.0", 1, 4, "tutte")], rs2)[0].verdict,
            "aperta"
        );
        // loopback: mai valutata col firewall
        assert_eq!(
            assess(&[l("127.0.0.1", 1, 4, "locale")], "")[0].verdict,
            "locale"
        );
    }

    /// v3: lo stesso listener su `::` ha percorsi distinti per IPv4 e IPv6.
    /// IPv4: dport 3389 in `table ip` -> drop. IPv6: stessa porta accettata in
    /// `table ip6`. Prima di v3 vinceva la decisione IPv4 (tabelle `ip` valutate
    /// prima di `ip6`) e la porta risultava falsamente "bloccata".
    #[test]
    fn dual_stack_split_verdicts() {
        let rs = "\
table ip filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t\ttcp dport 3389 drop
\t}
}
table ip6 filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t\ttcp dport 3389 accept
\t}
}
";
        let e = &assess(&[l("::", 3389, 6, "tutte")], rs)[0];
        assert_eq!(
            e.verdict, "aperta",
            "IPv6 accetta: la porta e' raggiungibile"
        );
        let by: std::collections::BTreeMap<u8, &str> =
            e.per_family.iter().map(|f| (f.family, f.verdict)).collect();
        assert_eq!(by.get(&4), Some(&"bloccata"), "IPv4 drop");
        assert_eq!(by.get(&6), Some(&"aperta"), "IPv6 accept");
        // un listener solo IPv4 non e' influenzato dalle catene ip6: nessuna
        // catena input per la sua famiglia = verdetto non esprimibile, non "aperta"
        let only6 = "table ip6 f {\n chain input {\n  type filter hook input priority 0; policy accept;\n  tcp dport 3389 accept\n }\n}\n";
        assert_eq!(
            assess(&[l("0.0.0.0", 3389, 4, "tutte")], only6)[0].verdict,
            "ignota"
        );
        // e il suo speculare: listener IPv6 con sole catene ip -> ignota per v6
        let only4 = "table ip f {\n chain input {\n  type filter hook input priority 0; policy accept;\n  tcp dport 3389 accept\n }\n}\n";
        assert_eq!(
            assess(&[l("::", 3389, 6, "tutte")], only4)[0].verdict,
            "aperta"
        );
        let only4_both = "table ip f {\n chain input {\n  type filter hook input priority 0; policy accept;\n  tcp dport 3389 drop\n }\n}\n";
        let e3 = &assess(&[l("::", 3389, 6, "tutte")], only4_both)[0];
        assert_eq!(
            e3.verdict, "ignota",
            "v4 bloccata + v6 non valutabile: non si dichiara chiusa"
        );
        let by3: std::collections::BTreeMap<u8, &str> = e3
            .per_family
            .iter()
            .map(|f| (f.family, f.verdict))
            .collect();
        assert_eq!(by3.get(&4), Some(&"bloccata"));
        assert_eq!(by3.get(&6), Some(&"ignota"));
        // omonimia di tabelle/catene: `ip filter`/`INPUT` e `ip6 filter`/`INPUT`
        // non devono essere scambiate per la stessa catena gia' visitata
        let same_name = "\
table ip filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t\tjump COMMON
\t}
\tchain COMMON {
\t\ttcp dport 3389 drop
\t}
}
table ip6 filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t\tjump COMMON
\t}
\tchain COMMON {
\t\ttcp dport 3389 accept
\t}
}
";
        let e2 = &assess(&[l("::", 3389, 6, "tutte")], same_name)[0];
        let by2: std::collections::BTreeMap<u8, &str> = e2
            .per_family
            .iter()
            .map(|f| (f.family, f.verdict))
            .collect();
        assert_eq!(by2.get(&4), Some(&"bloccata"));
        assert_eq!(by2.get(&6), Some(&"aperta"));
    }

    /// v3b: gli statement non terminanti e le keyword a due token non devono
    /// degradare un verdetto pieno ne' generare condizioni fantasma.
    #[test]
    fn statements_and_two_token_keywords() {
        // `log` non e' una condizione: un drop con log resta "bloccata"
        let rs = "\
table ip6 filter {
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tct state new limit rate 3/minute log prefix \"[X] \" drop
\t}
}
";
        let e = &assess(&[l("::", 3389, 6, "tutte")], rs)[0];
        assert_eq!(
            e.verdict, "condizionata",
            "il rate-limit resta condizione, il log no"
        );
        let conds = e
            .detail
            .split("condizioni non valutate:")
            .nth(1)
            .unwrap_or("");
        assert!(
            !conds.contains("log"),
            "log non deve essere una condizione: {conds}"
        );
        assert!(
            conds.contains("limit"),
            "il rate-limit resta una condizione: {conds}"
        );

        // `meta l4proto tcp` e `ip protocol tcp`: il valore viene dopo la keyword
        let one = "table ip6 f {\n chain input {\n  type filter hook input priority filter; policy drop;\n  meta l4proto tcp tcp dport 3389 accept\n }\n}\n";
        assert_eq!(
            assess(&[l("::", 3389, 6, "tutte")], one)[0].verdict,
            "aperta"
        );
        let two = "table ip f {\n chain input {\n  type filter hook input priority filter; policy drop;\n  ip protocol tcp tcp dport { 3389, 3390 } accept\n }\n}\n";
        let e2 = &assess(&[l("0.0.0.0", 3389, 4, "tutte")], two)[0];
        assert_eq!(
            e2.verdict, "aperta",
            "ip protocol tcp + set di dport: {}",
            e2.detail
        );

        // `ip6 saddr fe80::/10 ... accept`: la condizione e' l'indirizzo, non la keyword
        let three = "table ip6 f {\n chain input {\n  type filter hook input priority filter; policy drop;\n  ip6 saddr fe80::/10 meta l4proto tcp tcp dport 3389 accept\n }\n}\n";
        let e3 = &assess(&[l("::", 3389, 6, "tutte")], three)[0];
        assert_eq!(e3.verdict, "condizionata");
        assert!(
            e3.detail.contains("ip6 saddr fe80::/10"),
            "condizione corretta: {}",
            e3.detail
        );
        assert!(
            !e3.detail.contains("saddr saddr"),
            "nessun raddoppio della keyword: {}",
            e3.detail
        );

        // estensioni header IPv6: il SYN probe non porta Routing Header
        let rt = "table ip6 f {\n chain input {\n  type filter hook input priority filter; policy drop;\n  tcp dport 3389 accept\n  rt type 0 drop\n }\n}\n";
        assert_eq!(
            assess(&[l("::", 3389, 6, "tutte")], rt)[0].verdict,
            "aperta"
        );
    }

    /// Ruleset nft live: prima l'helper Pyla (root, stesso testo visto dalla GUI),
    /// poi `nft list ruleset` (da root) e infine il dump in `/tmp/nft-live.txt`.
    /// Senza root `nft list ruleset` non restituisce nulla e ogni listener
    /// risulterebbe "ignota": per questo l'helper e' la via primaria.
    fn live_ruleset() -> (String, &'static str) {
        // PYLA_LIVE_DUMP=1: usa il dump gia' preso (571 righe, stesso ruleset),
        // senza attendere il prompt di polkit (auth_admin_keep scade dopo 5 min).
        if std::env::var("PYLA_LIVE_DUMP").is_ok_and(|v| v == "1") {
            let d = std::fs::read_to_string("/tmp/nft-live.txt").unwrap_or_default();
            if !d.trim().is_empty() {
                return (d, "dump /tmp/nft-live.txt");
            }
        }
        let helper = std::process::Command::new("pkexec")
            .args(["/usr/local/libexec/pyla/pyla-helper", "ruleset"])
            .output();
        if let Ok(o) = &helper {
            if o.status.success() {
                if let Ok(v) =
                    serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&o.stdout))
                {
                    if let Some(t) = v.get("text").and_then(|t| t.as_str()) {
                        return (t.to_string(), "helper (pkexec)");
                    }
                }
            }
        }
        let nft = std::process::Command::new("nft")
            .args(["list", "ruleset"])
            .output();
        if let Ok(o) = &nft {
            let t = String::from_utf8_lossy(&o.stdout).into_owned();
            if !t.trim().is_empty() {
                return (t, "nft list ruleset");
            }
        }
        (
            std::fs::read_to_string("/tmp/nft-live.txt").unwrap_or_default(),
            "dump /tmp/nft-live.txt",
        )
    }

    /// Sistema reale: `cargo test -p pyla-core -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_exposure() {
        let ls = listeners(Path::new("/"));
        let (rs, src) = live_ruleset();
        println!("ruleset da {src}: {} righe", rs.lines().count());
        let tables = crate::nft::parse_ruleset(&rs);
        let hooks: Vec<String> = tables
            .iter()
            .flat_map(|t| {
                t.chains
                    .iter()
                    .filter(|c| c.hook.is_some())
                    .map(|c| format!("{}.{} [{}]", t.family, t.name, c.name))
            })
            .collect();
        println!("catene con hook: {}", hooks.join(", "));
        let mut counts: std::collections::BTreeMap<&'static str, usize> = Default::default();
        for e in assess(&ls, &rs) {
            *counts.entry(e.verdict).or_insert(0) += 1;
            let split = if e.per_family.is_empty() {
                String::new()
            } else {
                format!(
                    "  [{}]",
                    e.per_family
                        .iter()
                        .map(|f| format!("v{}={}", f.family, f.verdict))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            };
            println!(
                "{:8} {:>5} {:10} {} — {}{split}",
                e.family, e.port, e.verdict, e.addr, e.detail
            );
        }
        println!("riepilogo: {counts:?}");
        assert!(
            !rs.trim().is_empty(),
            "nessun ruleset: eseguire con root o con l'helper installato"
        );
    }
}
