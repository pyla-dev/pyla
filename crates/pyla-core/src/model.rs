use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Reject,
    Limit,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Reject => "reject",
            Action::Limit => "limit",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            "reject" => Action::Reject,
            "limit" => Action::Limit,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Any,
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Any => "any",
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "any" => Proto::Any,
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum LogLevel {
    #[default]
    #[serde(rename = "off")]
    Off,
    #[serde(rename = "log")]
    Log,
    #[serde(rename = "log-all")]
    LogAll,
}

/// Una regola UFW, nella forma che Pyla sa rappresentare.
/// Gli indirizzi sono `"any"`, un IP o una rete CIDR; le porte sono
/// `22`, `80,443` oppure `6000:6007`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleSpec {
    pub action: Action,
    pub direction: Direction,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub log: LogLevel,
    pub proto: Proto,
    pub src: String,
    #[serde(default)]
    pub sport: Option<String>,
    pub dst: String,
    #[serde(default)]
    pub dport: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("interfaccia non valida: {0}")]
    Interface(String),
    #[error("indirizzo non valido: {0}")]
    Address(String),
    #[error("sorgente e destinazione devono essere entrambe IPv4 o entrambe IPv6")]
    MixedFamilies,
    #[error("porte non valide: {0}")]
    Ports(String),
    #[error("con più porte o un intervallo va scelto il protocollo tcp o udp")]
    PortsNeedProto,
    #[error("commento non valido: {0}")]
    Comment(String),
}

const MAX_COMMENT: usize = 120;

impl RuleSpec {
    /// Valida la regola e la riporta alla forma canonica in cui UFW la salva
    /// (reti allineate al prefisso, host senza /32, campi vuoti -> None),
    /// così il confronto con lo stato reale è un semplice `==`.
    pub fn normalized(&self) -> Result<RuleSpec, ValidationError> {
        let interface = match self.interface.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(i) => {
                let ok = i.len() <= 15
                    && i.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
                if !ok {
                    return Err(ValidationError::Interface(i.to_string()));
                }
                Some(i.to_string())
            }
        };

        let (src, src_fam) = normalize_addr(&self.src)?;
        let (dst, dst_fam) = normalize_addr(&self.dst)?;
        if let (Some(a), Some(b)) = (src_fam, dst_fam) {
            if a != b {
                return Err(ValidationError::MixedFamilies);
            }
        }

        let sport = normalize_ports(self.sport.as_deref())?;
        let dport = normalize_ports(self.dport.as_deref())?;
        let multi = |p: &Option<String>| p.as_deref().is_some_and(|p| p.contains([',', ':']));
        if self.proto == Proto::Any && (multi(&sport) || multi(&dport)) {
            return Err(ValidationError::PortsNeedProto);
        }

        let comment = match self.comment.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(c) => {
                if c.chars().count() > MAX_COMMENT {
                    return Err(ValidationError::Comment(format!(
                        "più di {MAX_COMMENT} caratteri"
                    )));
                }
                if c.chars().any(char::is_control) {
                    return Err(ValidationError::Comment("caratteri di controllo".into()));
                }
                Some(c.to_string())
            }
        };

        Ok(RuleSpec {
            action: self.action,
            direction: self.direction,
            interface,
            log: self.log,
            proto: self.proto,
            src,
            sport,
            dst,
            dport,
            comment,
        })
    }

    /// Chiave di confronto che ignora il commento (per trovare duplicati:
    /// UFW salta una regola identica anche se il commento è diverso).
    pub fn match_key(&self) -> RuleSpec {
        RuleSpec {
            comment: None,
            ..self.clone()
        }
    }

    /// Descrizione breve leggibile, es. `allow in on eth1 tcp da 198.51.100.0/24 a any:22`.
    pub fn summary(&self) -> String {
        let mut s = format!("{} {}", self.action.as_str(), self.direction.as_str());
        if let Some(i) = &self.interface {
            s += &format!(" on {i}");
        }
        if self.proto != Proto::Any {
            s += &format!(" {}", self.proto.as_str());
        }
        let ep = |a: &str, p: &Option<String>| match p {
            Some(p) => format!("{a}:{p}"),
            None => a.to_string(),
        };
        s += &format!(
            " da {} a {}",
            ep(&self.src, &self.sport),
            ep(&self.dst, &self.dport)
        );
        s
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

fn normalize_addr(raw: &str) -> Result<(String, Option<Family>), ValidationError> {
    let raw = raw.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("any") {
        return Ok(("any".into(), None));
    }
    let err = || ValidationError::Address(raw.to_string());
    let (ip_s, prefix) = match raw.split_once('/') {
        Some((ip, p)) => (ip, Some(p.parse::<u8>().map_err(|_| err())?)),
        None => (raw, None),
    };
    let ip: IpAddr = ip_s.parse().map_err(|_| err())?;
    match ip {
        IpAddr::V4(v4) => {
            let p = prefix.unwrap_or(32);
            if p > 32 {
                return Err(err());
            }
            if p == 0 {
                return Ok(("any".into(), None));
            }
            let mask = u32::MAX << (32 - p);
            let net = Ipv4Addr::from(u32::from(v4) & mask);
            let s = if p == 32 {
                net.to_string()
            } else {
                format!("{net}/{p}")
            };
            Ok((s, Some(Family::V4)))
        }
        IpAddr::V6(v6) => {
            let p = prefix.unwrap_or(128);
            if p > 128 {
                return Err(err());
            }
            if p == 0 {
                return Ok(("any".into(), None));
            }
            let mask = u128::MAX << (128 - p as u32);
            let net = Ipv6Addr::from(u128::from(v6) & mask);
            let s = if p == 128 {
                net.to_string()
            } else {
                format!("{net}/{p}")
            };
            Ok((s, Some(Family::V6)))
        }
    }
}

fn normalize_ports(raw: Option<&str>) -> Result<Option<String>, ValidationError> {
    let raw = match raw.map(str::trim) {
        None | Some("") => return Ok(None),
        Some(r) if r.eq_ignore_ascii_case("any") => return Ok(None),
        Some(r) => r,
    };
    let err = || ValidationError::Ports(raw.to_string());
    let port = |s: &str| -> Result<u16, ValidationError> {
        match s.trim().parse::<u16>() {
            Ok(p) if p > 0 => Ok(p),
            _ => Err(err()),
        }
    };
    let mut items = Vec::new();
    // UFW accetta al massimo 15 porte, gli intervalli contano due.
    let mut weight = 0;
    for item in raw.split(',') {
        if let Some((a, b)) = item.split_once(':') {
            let (a, b) = (port(a)?, port(b)?);
            if a >= b {
                return Err(err());
            }
            items.push(format!("{a}:{b}"));
            weight += 2;
        } else {
            items.push(port(item)?.to_string());
            weight += 1;
        }
    }
    if weight > 15 {
        return Err(ValidationError::Ports(format!("{raw} (massimo 15 porte)")));
    }
    Ok(Some(items.join(",")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(src: &str, dst: &str, dport: Option<&str>, proto: Proto) -> RuleSpec {
        RuleSpec {
            action: Action::Allow,
            direction: Direction::In,
            interface: None,
            log: LogLevel::Off,
            proto,
            src: src.into(),
            sport: None,
            dst: dst.into(),
            dport: dport.map(Into::into),
            comment: None,
        }
    }

    #[test]
    fn normalizes_networks_and_hosts() {
        let r = spec("198.51.100.7/24", "192.0.2.8/32", Some("22"), Proto::Tcp)
            .normalized()
            .unwrap();
        assert_eq!(r.src, "198.51.100.0/24");
        assert_eq!(r.dst, "192.0.2.8");
        let r = spec("0.0.0.0/0", "", None, Proto::Any)
            .normalized()
            .unwrap();
        assert_eq!((r.src.as_str(), r.dst.as_str()), ("any", "any"));
        let r = spec("fe80::1/10", "any", None, Proto::Any)
            .normalized()
            .unwrap();
        assert_eq!(r.src, "fe80::/10");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(spec("192.0.2.300", "any", None, Proto::Any)
            .normalized()
            .is_err());
        assert!(spec("10.0.0.1", "::1", None, Proto::Any)
            .normalized()
            .is_err());
        assert_eq!(
            spec("any", "any", Some("80,443"), Proto::Any).normalized(),
            Err(ValidationError::PortsNeedProto)
        );
        assert!(spec("any", "any", Some("2000:1000"), Proto::Tcp)
            .normalized()
            .is_err());
        assert!(spec("any", "any", Some("0"), Proto::Tcp)
            .normalized()
            .is_err());
        let mut r = spec("any", "any", None, Proto::Any);
        r.interface = Some("eth0; rm".into());
        assert!(r.normalized().is_err());
    }

    #[test]
    fn ports_are_canonical() {
        let r = spec("any", "any", Some(" 80, 443 ,6000:6007"), Proto::Tcp)
            .normalized()
            .unwrap();
        assert_eq!(r.dport.as_deref(), Some("80,443,6000:6007"));
    }
}
