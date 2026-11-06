//! Lettura del ruleset completo del kernel dal testo di `nft list ruleset`,
//! solo per mostrarlo (PYLA non modifica nulla fuori dalle regole utente di UFW).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NftRule {
    /// Testo della regola senza la parte `counter packets N bytes M`.
    pub text: String,
    pub packets: Option<u64>,
    pub bytes: Option<u64>,
    /// Catena di destinazione di `jump`/`goto`, se c'è.
    pub target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NftChain {
    pub name: String,
    /// Per le catene base: `filter hook input priority filter`.
    pub hook: Option<String>,
    pub policy: Option<String>,
    /// Chi l'ha creata, dedotto dal nome: ufw, docker, libvirt o `None`.
    pub owner: Option<String>,
    pub rules: Vec<NftRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NftTable {
    pub family: String,
    pub name: String,
    /// Avviso `# Warning: table ... is managed by iptables-nft` che precede la tabella.
    pub note: Option<String>,
    pub chains: Vec<NftChain>,
    /// Set, mappe, flowtable...: mostrati come testo.
    pub other: Vec<String>,
}

fn owner_of(chain: &str) -> Option<String> {
    let c = chain.to_ascii_lowercase();
    let o = if c.starts_with("ufw") {
        "ufw"
    } else if c.starts_with("docker") {
        "docker"
    } else if c.starts_with("libvirt") {
        "libvirt"
    } else {
        return None;
    };
    Some(o.to_string())
}

fn braces(line: &str) -> i32 {
    line.matches('{').count() as i32 - line.matches('}').count() as i32
}

fn parse_rule(line: &str) -> NftRule {
    let words: Vec<&str> = line.split_whitespace().collect();
    let mut packets = None;
    let mut bytes = None;
    let mut kept: Vec<&str> = Vec::with_capacity(words.len());
    let mut i = 0;
    while i < words.len() {
        if words[i] == "counter"
            && words.get(i + 1) == Some(&"packets")
            && words.get(i + 3) == Some(&"bytes")
        {
            packets = words.get(i + 2).and_then(|w| w.parse().ok());
            bytes = words.get(i + 4).and_then(|w| w.parse().ok());
            i += 5;
            continue;
        }
        kept.push(words[i]);
        i += 1;
    }
    let target = kept
        .windows(2)
        .find(|w| w[0] == "jump" || w[0] == "goto")
        .map(|w| w[1].to_string());
    NftRule {
        text: kept.join(" "),
        packets,
        bytes,
        target,
    }
}

/// Interpreta l'output testuale di `nft list ruleset`.
pub fn parse_ruleset(text: &str) -> Vec<NftTable> {
    let mut tables: Vec<NftTable> = Vec::new();
    let mut note: Option<String> = None;
    let mut lines = text.lines();

    while let Some(line) = lines.next() {
        let t = line.trim();
        if let Some(c) = t.strip_prefix('#') {
            note = Some(c.trim().to_string());
            continue;
        }
        let Some(head) = t.strip_prefix("table ").and_then(|h| h.strip_suffix('{')) else {
            continue;
        };
        let mut parts = head.split_whitespace();
        let (family, name) = match (parts.next(), parts.next()) {
            (Some(f), Some(n)) => (f.to_string(), n.to_string()),
            (Some(n), None) => ("ip".to_string(), n.to_string()),
            _ => continue,
        };
        let mut table = NftTable {
            family,
            name,
            note: note.take(),
            chains: Vec::new(),
            other: Vec::new(),
        };

        // dentro la tabella: blocchi chain/set/map/... fino alla '}' di chiusura
        while let Some(line) = lines.next() {
            let t = line.trim();
            if t == "}" {
                break;
            }
            if t.is_empty() {
                continue;
            }
            if let Some(name) = t.strip_prefix("chain ").and_then(|h| h.strip_suffix('{')) {
                let mut chain = NftChain {
                    name: name.trim().to_string(),
                    hook: None,
                    policy: None,
                    owner: owner_of(name.trim()),
                    rules: Vec::new(),
                };
                for line in lines.by_ref() {
                    let t = line.trim();
                    if t == "}" {
                        break;
                    }
                    if t.is_empty() {
                        continue;
                    }
                    if let Some(def) = t.strip_prefix("type ") {
                        for part in def.split(';').map(str::trim).filter(|p| !p.is_empty()) {
                            match part.strip_prefix("policy ") {
                                Some(p) => chain.policy = Some(p.to_string()),
                                None => chain.hook = Some(part.to_string()),
                            }
                        }
                        continue;
                    }
                    chain.rules.push(parse_rule(t));
                }
                table.chains.push(chain);
            } else {
                // altro blocco: lo teniamo come testo fino a bilanciare le graffe
                let mut block = vec![t.to_string()];
                let mut depth = braces(t);
                while depth > 0 {
                    let Some(l) = lines.next() else { break };
                    depth += braces(l);
                    block.push(l.trim().to_string());
                }
                table.other.push(block.join("\n"));
            }
        }
        tables.push(table);
    }
    tables
}

#[cfg(test)]
mod tests {
    use super::*;

    // estratto anonimizzato di `nft list ruleset` (indirizzi RFC 5737, contatori di esempio)
    const SAMPLE: &str = "\
# Warning: table ip filter is managed by iptables-nft, do not touch!
table ip filter {
	chain ufw-before-logging-input {
	}

	chain INPUT {
		type filter hook input priority filter; policy drop;
		counter packets 1000000 bytes 900000000 jump LIBVIRT_INP
		counter packets 1000020 bytes 900002000 jump ufw-before-input
	}

	chain ufw-user-input {
		ip saddr 198.51.100.0/24 iifname \"eth1\" tcp dport 22 counter packets 0 bytes 0 accept
		ip saddr 192.0.2.6 counter packets 0 bytes 0 accept
	}

	chain DOCKER {
		ip daddr 172.17.0.2 iifname != \"docker0\" oifname \"docker0\" tcp dport 8080 counter packets 0 bytes 0 accept
	}
}
table ip raw {
	set blocked {
		type ipv4_addr
		elements = { 10.0.0.1,
			     10.0.0.2 }
	}

	chain PREROUTING {
		type filter hook prerouting priority raw; policy accept;
		ip daddr 127.0.0.1 iifname != \"lo\" tcp dport 9000 counter packets 0 bytes 0 drop
	}
}
";

    #[test]
    fn parses_tables_chains_and_counters() {
        let t = parse_ruleset(SAMPLE);
        assert_eq!(t.len(), 2);
        assert_eq!((t[0].family.as_str(), t[0].name.as_str()), ("ip", "filter"));
        assert!(t[0].note.as_deref().unwrap().contains("iptables-nft"));
        assert_eq!(t[1].note, None);

        let input = &t[0].chains[1];
        assert_eq!(
            input.hook.as_deref(),
            Some("filter hook input priority filter")
        );
        assert_eq!(input.policy.as_deref(), Some("drop"));
        assert_eq!(input.owner, None);
        assert_eq!(input.rules[1].text, "jump ufw-before-input");
        assert_eq!(input.rules[1].packets, Some(1000020));
        assert_eq!(input.rules[1].target.as_deref(), Some("ufw-before-input"));

        let user = &t[0].chains[2];
        assert_eq!(user.owner.as_deref(), Some("ufw"));
        assert_eq!(
            user.rules[0].text,
            "ip saddr 198.51.100.0/24 iifname \"eth1\" tcp dport 22 accept"
        );
        assert_eq!(t[0].chains[3].owner.as_deref(), Some("docker"));
        assert!(t[0].chains[0].rules.is_empty());

        assert_eq!(t[1].other.len(), 1);
        assert!(t[1].other[0].ends_with('}'));
        assert_eq!(t[1].chains[0].rules[0].bytes, Some(0));
    }
}
