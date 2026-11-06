//! Traduzione da/verso UFW.
//!
//! Lo stato reale si legge dalle righe `### tuple ###` di `/etc/ufw/user.rules`
//! e `user6.rules` (formato macchina stabile di UFW, leggibile solo da root);
//! interruttore e policy di default da `ufw.conf` e `/etc/default/ufw`,
//! leggibili da tutti.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::model::{Action, Direction, LogLevel, Proto, RuleSpec};

pub const USER_RULES: &str = "/etc/ufw/user.rules";
pub const USER6_RULES: &str = "/etc/ufw/user6.rules";
pub const UFW_CONF: &str = "/etc/ufw/ufw.conf";
pub const UFW_DEFAULTS: &str = "/etc/default/ufw";

/// Una regola presente in UFW. `spec` è `None` quando Pyla non sa
/// rappresentarla (regole route, regole per applicazione, ...).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveRule {
    pub spec: Option<RuleSpec>,
    pub raw: String,
    pub v6: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Defaults {
    pub incoming: String,
    pub outgoing: String,
    pub routed: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UfwStatus {
    pub enabled: bool,
    pub loglevel: String,
    pub defaults: Defaults,
    /// `None` quando le regole non sono state lette (serve root).
    pub rules: Option<Vec<LiveRule>>,
}

impl UfwStatus {
    /// Le regole rappresentabili, nell'ordine in cui UFW le valuta.
    pub fn specs(&self) -> Vec<RuleSpec> {
        self.rules
            .iter()
            .flatten()
            .filter_map(|r| r.spec.clone())
            .collect()
    }

    pub fn unsupported(&self) -> Vec<&LiveRule> {
        self.rules
            .iter()
            .flatten()
            .filter(|r| r.spec.is_none())
            .collect()
    }
}

/// Argomenti per `ufw` (senza il nome del comando) che creano la regola.
/// Ordine della grammatica di UFW:
/// `ACTION in|out [on IF] [log|log-all] [proto P] from A [port X] to B [port Y] [comment C]`.
pub fn rule_args(r: &RuleSpec) -> Vec<String> {
    let mut a: Vec<String> = vec![r.action.as_str().into(), r.direction.as_str().into()];
    if let Some(i) = &r.interface {
        a.extend(["on".into(), i.clone()]);
    }
    match r.log {
        LogLevel::Off => {}
        LogLevel::Log => a.push("log".into()),
        LogLevel::LogAll => a.push("log-all".into()),
    }
    if r.proto != Proto::Any {
        a.extend(["proto".into(), r.proto.as_str().into()]);
    }
    a.extend(["from".into(), r.src.clone()]);
    if let Some(p) = &r.sport {
        a.extend(["port".into(), p.clone()]);
    }
    a.extend(["to".into(), r.dst.clone()]);
    if let Some(p) = &r.dport {
        a.extend(["port".into(), p.clone()]);
    }
    if let Some(c) = &r.comment {
        a.extend(["comment".into(), c.clone()]);
    }
    a
}

/// Argomenti per cancellare la regola (`ufw delete ...`, il commento non conta).
pub fn delete_args(r: &RuleSpec) -> Vec<String> {
    let mut a = vec!["delete".to_string()];
    a.extend(rule_args(&r.match_key()));
    a
}

/// Riga di comando leggibile, solo per mostrarla all'utente.
pub fn display_command(args: &[String]) -> String {
    let quoted: Vec<String> = args
        .iter()
        .map(|s| {
            if s.is_empty() || s.contains(|c: char| c.is_whitespace() || "'\"$;&|".contains(c)) {
                format!("'{}'", s.replace('\'', "'\\''"))
            } else {
                s.clone()
            }
        })
        .collect();
    format!("ufw {}", quoted.join(" "))
}

/// Interpreta una riga `### tuple ### ...`:
/// `action proto dport dst sport src [dapp sapp] direction[_iface] [comment=HEX]`.
pub fn parse_tuple(line: &str, v6: bool) -> Option<LiveRule> {
    let body = line.trim().strip_prefix("### tuple ###")?.trim();
    let raw = body.to_string();
    let unsupported = || {
        Some(LiveRule {
            spec: None,
            raw: raw.clone(),
            v6,
        })
    };

    let mut tokens: Vec<&str> = body.split_whitespace().collect();
    let comment = match tokens.last() {
        Some(t) if t.starts_with("comment=") => {
            let hex = &tokens.pop().unwrap()["comment=".len()..];
            Some(decode_hex(hex)?)
        }
        _ => None,
    };
    // 7 token = regola semplice; 9 = regola con applicazioni (non gestita).
    if tokens.len() != 7 {
        return unsupported();
    }
    let (action_tok, proto, dport, dst, sport, src, dir) = (
        tokens[0], tokens[1], tokens[2], tokens[3], tokens[4], tokens[5], tokens[6],
    );

    let (action_s, log) = match action_tok.split_once('_') {
        None => (action_tok, LogLevel::Off),
        Some((a, "log")) => (a, LogLevel::Log),
        Some((a, "log-all")) => (a, LogLevel::LogAll),
        Some(_) => return unsupported(),
    };
    let Some(action) = Action::parse(action_s) else {
        return unsupported();
    };
    let Some(proto) = Proto::parse(proto) else {
        return unsupported();
    };

    if dir.contains('!') {
        return unsupported();
    }
    let (direction, interface) = match dir.split_once('_') {
        Some((d, i)) => (d, Some(i.to_string())),
        None => (dir, None),
    };
    let direction = match direction {
        "in" => Direction::In,
        "out" => Direction::Out,
        _ => return unsupported(),
    };

    let addr = |a: &str| match a {
        "0.0.0.0/0" | "::/0" => "any".to_string(),
        other => other.to_string(),
    };
    let port = |p: &str| (p != "any").then(|| p.to_string());

    let spec = RuleSpec {
        action,
        direction,
        interface,
        log,
        proto,
        src: addr(src),
        sport: port(sport),
        dst: addr(dst),
        dport: port(dport),
        comment,
    };
    Some(LiveRule {
        spec: Some(spec),
        raw,
        v6,
    })
}

/// Unisce le regole di `user.rules` e `user6.rules`: una regola con sorgente e
/// destinazione `any` UFW la scrive in entrambi i file, ma per Pyla è una sola.
pub fn merge_rules(v4: &str, v6: &str) -> Vec<LiveRule> {
    let mut out: Vec<LiveRule> = v4.lines().filter_map(|l| parse_tuple(l, false)).collect();
    for r in v6.lines().filter_map(|l| parse_tuple(l, true)) {
        let dup = r.spec.as_ref().is_some_and(|s| {
            s.src == "any" && s.dst == "any" && out.iter().any(|o| o.spec.as_ref() == Some(s))
        });
        if !dup {
            out.push(r);
        }
    }
    out
}

fn decode_hex(hex: &str) -> Option<String> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

fn conf_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.trim().split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
    })
}

pub fn parse_conf(ufw_conf: &str, defaults: &str) -> UfwStatus {
    let policy = |k| conf_value(defaults, k).unwrap_or_default().to_lowercase();
    UfwStatus {
        enabled: conf_value(ufw_conf, "ENABLED").as_deref() == Some("yes"),
        loglevel: conf_value(ufw_conf, "LOGLEVEL").unwrap_or_default(),
        defaults: Defaults {
            incoming: policy("DEFAULT_INPUT_POLICY"),
            outgoing: policy("DEFAULT_OUTPUT_POLICY"),
            routed: policy("DEFAULT_FORWARD_POLICY"),
        },
        rules: None,
    }
}

/// Legge interruttore e policy (non serve root).
pub fn read_conf(root: &Path) -> std::io::Result<UfwStatus> {
    let read = |p: &str| std::fs::read_to_string(root.join(p.trim_start_matches('/')));
    Ok(parse_conf(&read(UFW_CONF)?, &read(UFW_DEFAULTS)?))
}

/// Legge lo stato completo, regole incluse (serve root).
pub fn read_status(root: &Path) -> std::io::Result<UfwStatus> {
    let read = |p: &str| std::fs::read_to_string(root.join(p.trim_start_matches('/')));
    let mut st = read_conf(root)?;
    st.rules = Some(merge_rules(&read(USER_RULES)?, &read(USER6_RULES)?));
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: &str = "\
*filter
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 198.51.100.0/24 in_eth1 comment=737368206c6162
-A ufw-user-input -i eth1 -p tcp --dport 22 -s 198.51.100.0/24 -j ACCEPT

### tuple ### allow tcp 22 0.0.0.0/0 any 192.0.2.9 in
### tuple ### allow any any 0.0.0.0/0 any 192.0.2.6 in
### tuple ### allow tcp 22 192.0.2.8 any 192.0.2.50 in
### tuple ### deny_log-all udp 53,123 0.0.0.0/0 any 0.0.0.0/0 out_eth0
### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in
### END RULES ###
";
    const V6: &str = "\
### tuple ### allow tcp 80 ::/0 any ::/0 in
### tuple ### allow tcp 22 ::/0 any fe80::/10 in
";

    #[test]
    fn parses_tuples() {
        let rules = merge_rules(V4, V6);
        let specs: Vec<_> = rules.iter().filter_map(|r| r.spec.clone()).collect();

        assert_eq!(specs[0].interface.as_deref(), Some("eth1"));
        assert_eq!(specs[0].comment.as_deref(), Some("ssh lab"));
        assert_eq!(specs[0].src, "198.51.100.0/24");
        assert_eq!(specs[0].dst, "any");
        assert_eq!(specs[0].dport.as_deref(), Some("22"));

        assert_eq!(specs[2].proto, Proto::Any);
        assert_eq!(specs[2].dport, None);
        assert_eq!(specs[3].dst, "192.0.2.8");

        assert_eq!(specs[4].action, Action::Deny);
        assert_eq!(specs[4].log, LogLevel::LogAll);
        assert_eq!(specs[4].direction, Direction::Out);

        // route e regole per applicazione: lette ma non gestite
        assert_eq!(rules.iter().filter(|r| r.spec.is_none()).count(), 2);
        // la regola any/any su porta 80 compare una sola volta, quella v6 specifica resta
        assert_eq!(
            specs
                .iter()
                .filter(|s| s.dport.as_deref() == Some("80"))
                .count(),
            1
        );
        assert!(specs.iter().any(|s| s.src == "fe80::/10"));
    }

    #[test]
    fn parsed_rules_are_already_normalized() {
        for s in merge_rules(V4, V6).into_iter().filter_map(|r| r.spec) {
            assert_eq!(s.normalized().unwrap(), s);
        }
    }

    /// Righe nel formato reale di /etc/ufw/user.rules (indirizzi RFC 5737).
    #[test]
    fn parses_realistic_rules() {
        const REAL: &str = "\
### tuple ### allow tcp 22 0.0.0.0/0 any 198.51.100.0/24 in_eth1 comment=737368206c61622065746831
### tuple ### allow tcp 22 0.0.0.0/0 any 203.0.113.0/24 in_eth2 comment=737368206c61622065746832
### tuple ### allow tcp 22 0.0.0.0/0 any 192.0.2.9 in
### tuple ### allow any any 0.0.0.0/0 any 192.0.2.6 in
### tuple ### allow tcp 22 192.0.2.8 any 192.0.2.50 in comment=737368207669612076706e
";
        let st = UfwStatus {
            rules: Some(merge_rules(REAL, "")),
            ..Default::default()
        };
        assert!(st.unsupported().is_empty());
        let cmds: Vec<String> = st
            .specs()
            .iter()
            .map(|s| display_command(&rule_args(s)))
            .collect();
        assert_eq!(
            cmds,
            [
                "ufw allow in on eth1 proto tcp from 198.51.100.0/24 to any port 22 comment 'ssh lab eth1'",
                "ufw allow in on eth2 proto tcp from 203.0.113.0/24 to any port 22 comment 'ssh lab eth2'",
                "ufw allow in proto tcp from 192.0.2.9 to any port 22",
                "ufw allow in from 192.0.2.6 to any",
                "ufw allow in proto tcp from 192.0.2.50 to 192.0.2.8 port 22 comment 'ssh via vpn'",
            ]
        );
        // reimportate nel DB e riapplicate, devono risultare già allineate
        assert!(crate::plan(&st, &st.specs()).unwrap().in_sync);
    }

    #[test]
    fn builds_args() {
        let s = parse_tuple(
            "### tuple ### allow tcp 22 0.0.0.0/0 any 198.51.100.0/24 in_eth1 comment=737368206c6162",
            false,
        )
        .unwrap()
        .spec
        .unwrap();
        assert_eq!(
            display_command(&rule_args(&s)),
            "ufw allow in on eth1 proto tcp from 198.51.100.0/24 to any port 22 comment 'ssh lab'"
        );
        assert_eq!(
            display_command(&delete_args(&s)),
            "ufw delete allow in on eth1 proto tcp from 198.51.100.0/24 to any port 22"
        );
    }

    #[test]
    fn parses_conf() {
        let st = parse_conf(
            "ENABLED=yes\nLOGLEVEL=low\n",
            "DEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\n",
        );
        assert!(st.enabled);
        assert_eq!(st.defaults.incoming, "drop");
        assert_eq!(st.defaults.outgoing, "accept");
    }
}
