//! Import di un set di regole da testo JSON/JSONC.
//!
//! Il parser non è una libreria esterna: toglie i commenti e basta, poi passa il
//! testo a `serde_json`. Serve per leggere i set d'esempio versionati nel repo
//! (es. `examples/stealth.jsonc`) senza duplicarli in JSON puro.

use std::collections::HashSet;

use serde::Deserialize;

use crate::model::{LogLevel, Proto, RuleSpec};

/// Numero massimo di regole importabili: un file scritto a mano non deve poter
/// trasformarsi in migliaia di invocazioni `ufw` (limite di UFW sulle regole).
pub const MAX_RULES: usize = 200;

/// Versione del formato dei file dei profili che questo parser sa leggere. Il
/// contratto (repo `pyla-profiles`) e' che dentro un numero di versione il set di
/// campi non cambi mai: un campo nuovo arriva solo con il numero dopo. Per questo
/// `format_version` e' un campo noto e un valore piu' alto di questo non e' un
/// errore JSON ma un messaggio che dice cosa fare.
pub const SUPPORTED_FORMAT_VERSION: u32 = 1;

/// Valore usato quando il file non dichiara `format_version`: cosi' i file scritti
/// prima che il campo esistesse continuano a importarsi.
pub const MISSING_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    /// Versione del formato: assente = `MISSING_FORMAT_VERSION`, see
    /// `SUPPORTED_FORMAT_VERSION`.
    #[serde(default)]
    format_version: Option<u32>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    /// `false` per tenere fuori dal set alcune regole del file.
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    // azione/direzione/protocollo ammettono anche i sinonimi di ufw ("permit",
    // "deny"/"refuse", "reject-with …"), quindi restano stringhe e si validano a mano.
    action: String,
    #[serde(default = "default_direction")]
    direction: String,
    #[serde(default)]
    interface: Option<String>,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default = "default_any")]
    src: String,
    #[serde(default)]
    sport: Option<String>,
    #[serde(default = "default_any")]
    dst: String,
    #[serde(default)]
    dport: Option<String>,
    #[serde(default)]
    log: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    /// Deroga locale allo stato del set. Assente = eredita `enabled` del file;
    // `false` esplicito = la regola entra in PYLA ma spenta, non cancellata.
    #[serde(default)]
    enabled: Option<bool>,
}

fn default_true() -> bool {
    true
}
fn default_any() -> String {
    "any".into()
}
fn default_direction() -> String {
    "in".into()
}

/// Metadati del set importato (nome e descrizione, se presenti nel file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub name: String,
    pub description: String,
    /// Versione del formato dichiarata dal file (gia' risolta: un file senza
    /// `format_version` risulta `MISSING_FORMAT_VERSION`).
    pub format_version: u32,
}

/// Un set importato e già normalizzato, pronto da mettere in database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub meta: Meta,
    /// Regole nell'ordine del file, sempre popolate, anche quelle disabilitate:
    /// l'indice coincide con la posizione della regola nel file, così gli errori
    /// puntano a quella e il conteggio resta onesto. Lo stato di ogni riga sta in
    /// `states` (`Some(false)` = spenta nel file).
    pub rules: Vec<Option<RuleSpec>>,
    /// Stato di ogni regola, parallelamente a `rules`: `Some(false)` = spenta nel
    /// file (in PYLA entra come riga disabilitata), `None` = attiva.
    pub states: Vec<Option<bool>>,
}

impl Imported {
    /// Regole pronte per il database come `(spec, enabled)`, nell'ordine del file:
    /// quelle disabilitate nel file diventano `(spec, false)` invece di sparire, così
    /// chi importa le vede in PYLA e può riattivarle dal dettaglio del set.
    #[must_use]
    pub fn entries(&self) -> Vec<(RuleSpec, bool)> {
        self.entries_with_state().into_iter().flatten().collect()
    }

    /// Quante regole sono attive e quante spente, per il messaggio di esito
    /// dell'import: chi importa deve vedere lo stesso numero di righe che ottiene.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        let e = self.entries();
        (
            e.iter().filter(|(_, en)| *en).count(),
            e.iter().filter(|(_, en)| !*en).count(),
        )
    }

    /// Idem di `entries`, con `None` al posto delle posizioni senza regola (oggi non
    /// succede: ogni regola del file produce una voce, attiva o spenta). Serve a
    /// chi deve mantenere le posizioni nel database allineate al file.
    #[must_use]
    pub fn entries_with_state(&self) -> Vec<Option<(RuleSpec, bool)>> {
        self.states
            .iter()
            .zip(self.rules.iter())
            .map(|(state, spec)| match (state, spec) {
                // spenta nel file: la regola c'era, va in PYLA come riga disabilitata
                (Some(false), Some(spec)) => Some((spec.clone(), false)),
                (_, Some(spec)) => Some((spec.clone(), true)),
                (_, None) => None,
            })
            .collect()
    }
}

/// Errore di import, con il numero della riga quando è possibile ricostruirlo.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    #[error("JSON non valido: {message} (riga {line})")]
    Json { message: String, line: usize },
    #[error("regola {n}: {message}")]
    Rule { n: usize, message: String },
    #[error("format_version {got} non supportato: PYLA {pyla} legge al massimo la versione {max}; aggiorna PYLA prima di importare questo profilo")]
    Format { got: u32, max: u32, pyla: String },
    #[error("{0}")]
    Other(String),
}

/// Sostituisce i commenti (`//`, `/* … */`) con spazi, lasciando intatte le
/// stringhe: il testo resta della stessa lunghezza e le righe non si spostano.
fn blank_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut in_string = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            out.push(c);
            if c == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1]);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_string = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            let mut depth = 1usize;
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    depth += 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    depth -= 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else {
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Toglie le virgole finali prima di `}` o `]` (trattate come JSONC), mantenendo
/// la lunghezza: `[ 1, 2, ]` -> `[ 1, 2  ]`.
fn drop_trailing_commas(src: &str) -> String {
    let blanked = src.as_bytes();
    let mut out: Vec<u8> = blanked.to_vec();
    let mut in_string = false;
    let mut i = 0usize;
    while i < out.len() {
        let c = out[i];
        if in_string {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if c == b',' {
            let mut j = i + 1;
            while j < out.len() && matches!(out[j], b' ' | b'\t' | b'\r' | b'\n') {
                j += 1;
            }
            if j < out.len() && matches!(out[j], b'}' | b']') {
                out[i] = b' ';
            }
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Legge un set da testo JSON/JSONC. `fallback_name` è usato se il file non ha `name`.
pub fn parse(text: &str, fallback_name: &str) -> Result<Imported, ImportError> {
    // I commenti si tolgono SENZA accorciare il testo (i byte non stringa diventano
    // spazi): così gli offset di serde_json corrispondono alle righe reali del file.
    let blanked = blank_comments(text);
    let jsonc = drop_trailing_commas(&blanked);
    // Se il JSONC e' un oggetto, la lista dei campi top-level noti finisce nel
    // messaggio quando il file contiene una chiave sconosciuta: chi importa un
    // profilo di un'altra versione deve poter leggere cosa si poteva scrivere qui.
    let hint = top_level_hint(&jsonc);
    // Il JSONC ripulito ha gli stessi byte per riga del file (i commenti sono
    // diventati spazi), quindi gli offset di serde_json sono quelli reali.
    let raw: Raw = match serde_json::from_str(&jsonc) {
        Ok(v) => v,
        Err(err) => {
            // `line`/`column` di serde_json sono offset appiattiti sul testo
            // mascherato, che ha gli stessi newline del file: la riga reale si
            // ricalcola contando gli a-capo che precedono la colonna dell'errore.
            return Err(ImportError::Json {
                message: match &hint {
                    Some(h) if err.to_string().contains("unknown field") => {
                        format!("{err} — {h}")
                    }
                    _ => err.to_string(),
                },
                // `line` di serde_json e' gia' la riga reale del file: i commenti
                // sostituiti da spazi non hanno spostato le righe
                line: err.line(),
            });
        }
    };

    // Il numero di versione si controlla PRIMA delle regole: un profilo scritto per
    // una PYLA piu' recente deve dirlo in modo leggibile, non con un errore JSON che
    // punta a un campo che questa versione non conosce.
    let format_version = raw.format_version.unwrap_or(MISSING_FORMAT_VERSION);
    if format_version > SUPPORTED_FORMAT_VERSION {
        return Err(ImportError::Format {
            got: format_version,
            max: SUPPORTED_FORMAT_VERSION,
            // Versione del crate, quindi sempre allineata a Cargo.toml: chi
            // importa un profilo troppo nuovo deve sapere quale PYLA serve.
            pyla: env!("CARGO_PKG_VERSION").to_string(),
        });
    }

    if raw.rules.is_empty() {
        return Err(ImportError::Other("nessuna regola nel file".into()));
    }
    if raw.rules.len() > MAX_RULES {
        return Err(ImportError::Other(format!(
            "troppe regole: {} (massimo {MAX_RULES})",
            raw.rules.len()
        )));
    }

    let name = match raw.name.as_deref().map(str::trim) {
        None | Some("") => fallback_name.trim().to_string(),
        Some(n) => n.to_string(),
    };
    let description = raw.description.unwrap_or_default();

    // Duplicati si confrontano sul profilo SENZA commento: due regole uguali con
    // commenti diversi sono la stessa regola scritta due volte, e in UFW la seconda
    // non aggiunge nulla (la prima vince già).
    let mut seen: HashSet<Profile> = HashSet::new();
    let mut rules = Vec::with_capacity(raw.rules.len());
    let mut states: Vec<Option<bool>> = Vec::with_capacity(raw.rules.len());
    for (idx, r) in raw.rules.iter().enumerate() {
        let n = idx + 1;
        let spec = match to_spec(r) {
            Ok(s) => s,
            Err(message) => return Err(ImportError::Rule { n, message }),
        };
        let spec = match spec.normalized() {
            Ok(s) => s,
            Err(err) => {
                return Err(ImportError::Rule {
                    n,
                    message: err.to_string(),
                })
            }
        };
        // Stato della regola: eredita `enabled` del file, salvo deroga esplicita.
        // Falso = la regola resta nel set ma spenta (la si riattiva dal dettaglio),
        // non viene scartata: un file che ne contiene una "spenta" deve poterla
        // mostrare, altrimenti l'utente non sa che esisteva.
        let enabled = r.enabled.unwrap_or(raw.enabled);
        // `states` conserva lo stato EFFETTIVO della regola: se il file ha
        // "enabled": false a livello di set, la deroga per-regola manca ma la
        // regola e' spenta lo stesso, e va marcata come spenta (non "assente").
        states.push(if enabled { None } else { Some(false) });
        if !enabled {
            // La spec si tiene comunque: in PYLA la regola entra come riga SPENTA,
            // non sparisce. Non finisce nel set dei duplicati: una regola spenta non
            // e' nell'insieme attivo, quindi non puo' nasconderne una attiva.
            rules.push(Some(spec));
            continue;
        }
        if !seen.insert(profile(&spec)) {
            return Err(ImportError::Rule {
                n,
                message: format!("duplicato di una regola precedente: {}", spec.summary()),
            });
        }
        rules.push(Some(spec));
    }

    Ok(Imported {
        meta: Meta {
            name,
            description,
            format_version,
        },
        rules,
        states,
    })
}

/// Lista dei campi accettati a livello di file, usata solo per il messaggio di
/// errore quando il JSONC e' un oggetto: `None` se l'oggetto non e' riconoscibile.
fn top_level_hint(jsonc: &str) -> Option<String> {
    let start = jsonc.find('{')?;
    let mut depth = 0usize;
    let mut end = None;
    for (idx, ch) in jsonc.char_indices().skip(start) {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(idx);
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &jsonc[start..end? + 1];
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let keys: Vec<String> = value.as_object()?.keys().cloned().collect();
    if keys.is_empty() {
        return None;
    }
    Some(format!(
        "i campi accettati a livello di file sono: {} (i campi delle regole stanno dentro \"rules\")",
        keys.join(", ")
    ))
}

/// Identità strutturale di una regola, al netto del commento.
type Profile = (
    u8,
    u8,
    Option<String>,
    Proto,
    String,
    Option<String>,
    String,
    Option<String>,
);

fn profile(s: &RuleSpec) -> Profile {
    (
        s.action as u8,
        s.direction as u8,
        s.interface
            .clone()
            .map(|i| i.trim().to_string())
            .filter(|i| !i.is_empty()),
        s.proto,
        s.src.clone(),
        s.sport.clone(),
        s.dst.clone(),
        s.dport.clone(),
    )
}

fn to_spec(r: &RawRule) -> Result<RuleSpec, String> {
    let action = match r.action.trim().to_ascii_lowercase().as_str() {
        "allow" | "permit" => crate::model::Action::Allow,
        "deny" | "drop" | "refuse" => crate::model::Action::Deny,
        "reject" => crate::model::Action::Reject,
        "limit" => crate::model::Action::Limit,
        other => {
            return Err(format!(
                "azione non valida {other:?} (allow, deny, reject, limit)"
            ))
        }
    };
    let direction = match r.direction.trim().to_ascii_lowercase().as_str() {
        "in" | "incoming" => crate::model::Direction::In,
        "out" | "outgoing" => crate::model::Direction::Out,
        other => return Err(format!("direzione non valida {other:?} (in, out)")),
    };
    let proto = match r.proto.as_deref().map(str::trim) {
        None | Some("") | Some("any") => Proto::Any,
        // `Proto::parse` vuole il minuscolo: qui si normalizza, così il file può
        // scrivere "TCP" come lo scriveresti sulla rigione di ufw.
        Some(raw_proto) => match Proto::parse(&raw_proto.to_ascii_lowercase()) {
            Some(p) => p,
            None => {
                return Err(format!(
                    "protocollo non valido {raw_proto:?} (tcp, udp, any)"
                ))
            }
        },
    };
    let log = match r.log.as_deref().map(str::trim) {
        None | Some("") | Some("off") => LogLevel::Off,
        Some(v) if v.eq_ignore_ascii_case("log") => LogLevel::Log,
        Some(v) if v.eq_ignore_ascii_case("log-all") => LogLevel::LogAll,
        Some(other) => return Err(format!("log non valido {other:?} (off, log, log-all)")),
    };
    Ok(RuleSpec {
        action,
        direction,
        interface: r.interface.clone(),
        log,
        proto,
        src: r.src.clone(),
        sport: r.sport.clone(),
        dst: r.dst.clone(),
        dport: r.dport.clone(),
        comment: r.comment.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, Direction};

    const STEALTH: &str = include_str!("../../../examples/stealth.jsonc");

    fn rule(action: &str, proto: &str, dport: &str) -> String {
        format!(r#"{{ "action": "{action}", "proto": "{proto}", "dport": "{dport}" }}"#)
    }

    #[test]
    fn stealth_example_imports() {
        let got = parse(STEALTH, "fallback").expect("l'esempio deve importarsi");
        assert_eq!(got.meta.name, "Stealth silenziosa");
        assert!(!got.meta.description.is_empty());
        // Conteggio vincolato al file: se l'esempio cambia, il test lo dice. Niente
        // derive silenziose tra documento d'esempio e parser. 13 regole nel file,
        // 3 disabilitate (SSH + le due di discovery in LAN) -> 10 attive: la modalita'
        // stealth resta "nessuna porta aperta", la discovery e' un'opzione esplicita.
        assert_eq!(got.rules.len(), 13);
        let entries = got.entries_with_state();
        let on = entries.iter().flatten().filter(|(_, en)| *en).count();
        let off = entries.iter().flatten().filter(|(_, en)| !*en).count();
        assert_eq!(
            (on, off),
            (10, 3),
            "10 attive e 3 spente nel file d'esempio"
        );
        let ssh = entries
            .last()
            .and_then(|e| e.clone())
            .expect("l'ultima regola del file");
        assert!(!ssh.1, "la regola ssh deve risultare spenta");
        // la normalizzazione ha già allineato le reti alla forma canonica
        let deny = got
            .rules
            .iter()
            .flatten()
            .find(|s| s.action == Action::Deny)
            .expect("deny");
        assert_eq!((deny.direction, deny.proto), (Direction::In, Proto::Any));
    }

    #[test]
    fn comments_do_not_break_parsing() {
        let text = "{ // nome\n  \"name\": \"a // non è un commento\",\n  /* regole\n     su più righe */\n  \"rules\": [ ".to_string() + &rule("allow", "tcp", "22") + " ] }";
        let got = parse(&text, "fb").expect("import");
        assert_eq!(got.meta.name, "a // non è un commento");
        assert_eq!(got.rules.len(), 1);
    }

    #[test]
    fn json_error_points_at_the_line() {
        // Errore a riga 4. `line` di serde_json è una colonna appiattita sul testo
        // mascherato, che ha gli stessi byte per riga del file (commenti e virgole
        // finali sostituiti da spazi, mai rimossi): la si ricalcola dai newline.
        let err = parse(
            "{\n  \"name\": \"x\",\n  // commenti che non spostano le righe\n  \"rules\": [ },\n",
            "fb",
        )
        .unwrap_err();
        match err {
            ImportError::Json { message, line } => {
                assert_eq!(line, 4, "riga reale dell'errore ({message})");
            }
            other => panic!("errore atteso Json, trovato {other:?}"),
        }
    }

    #[test]
    fn bad_rule_names_the_position_and_the_field() {
        let text = "{ \"rules\": [ ".to_string()
            + &rule("allow", "tcp", "22")
            + ",\n  "
            + &rule("maybe", "tcp", "80")
            + " ] }";
        match parse(&text, "fb").unwrap_err() {
            ImportError::Rule { n, message } => {
                assert_eq!(n, 2);
                assert!(message.contains("azione non valida"), "{message}");
            }
            other => panic!("errore atteso Rule, trovato {other:?}"),
        }
    }

    #[test]
    fn duplicates_are_rejected() {
        let text = "{ \"rules\": [ ".to_string()
            + &rule("deny", "tcp", "23")
            + ",\n  "
            + r#"{ "action": "deny", "proto": "tcp", "dport": "23", "comment": "altro commento" } ] }"#;
        assert!(matches!(
            parse(&text, "fb").unwrap_err(),
            ImportError::Rule { n: 2, .. }
        ));
    }

    // Le regole spente nel file NON spariscono: restano nel set come righe
    // disabilitate. E' la scelta che rende l'import verificabile: chi importa vede
    // tutto quello che il file conteneva e puo' riattivarla dal dettaglio del set.
    #[test]
    fn disabled_rules_survive_as_disabled_rows() {
        let text = "{ \"rules\": [ ".to_string()
            + &rule("deny", "tcp", "23")
            + ",\n  "
            + r#"{ "action": "deny", "proto": "tcp", "dport": "25", "enabled": false } ] }"#;
        let got = parse(&text, "fb").expect("import");
        let entries = got.entries_with_state();
        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[0], Some((_, true))), "la prima e' attiva");
        let (spec, enabled) = entries[1].clone().expect("la spenta deve arrivare al DB");
        assert!(!enabled);
        assert_eq!(
            spec.dport.as_deref(),
            Some("25"),
            "la spec della regola spenta si mantiene"
        );
    }

    #[test]
    fn set_level_enabled_false_keeps_rules_disabled() {
        let text =
            "{ \"enabled\": false, \"rules\": [ ".to_string() + &rule("deny", "tcp", "23") + " ] }";
        let got = parse(&text, "fb").expect("import");
        let entries = got.entries_with_state();
        assert_eq!(entries.len(), 1);
        // spenta perche' il file lo dice a livello di set: la regola resta nel set,
        // marcata disabilitata, non sparisce
        let (spec, enabled) = entries[0].clone().expect("regola presente");
        assert!(!enabled);
        assert_eq!(spec.dport.as_deref(), Some("23"));
    }

    #[test]
    fn empty_and_oversized_are_refused() {
        assert!(matches!(
            parse(r#"{ "rules": [] }"#, "fb"),
            Err(ImportError::Other(_))
        ));
        let many = (1..=MAX_RULES + 1)
            .map(|i| rule("deny", "tcp", &format!("{}", 10000 + i)))
            .collect::<Vec<_>>()
            .join(",");
        assert!(matches!(
            parse(&format!("{{ \"rules\": [{many}] }}"), "fb"),
            Err(ImportError::Other(_))
        ));
    }

    #[test]
    fn unknown_field_is_reported() {
        match parse(
            r#"{ "rules": [ { "action": "deny", "prot0": "tcp" } ] }"#,
            "fb",
        )
        .unwrap_err()
        {
            ImportError::Json { message, .. } => assert!(message.contains("prot0"), "{message}"),
            other => panic!("errore atteso Json, trovato {other:?}"),
        }
    }

    #[test]
    fn fallback_name_when_missing() {
        let got = parse(
            r#"{ "rules": [ { "action": "deny", "proto": "tcp" } ] }"#,
            "Il mio set",
        )
        .expect("import");
        assert_eq!(got.meta.name, "Il mio set");
    }

    #[test]
    fn ufw_synonyms_are_accepted() {
        let text = r#"{ "rules": [ { "action": "PERMIT", "direction": "INCOMING", "proto": "TCP", "dport": "22" },
          { "action": "refuse", "proto": "udp", "dport": "53", "log": "LOG" } ] }"#;
        let got = parse(text, "fb").expect("import");
        let a = got.rules[0].as_ref().expect("regola 1");
        assert_eq!(
            (a.action, a.direction, a.proto),
            (Action::Allow, Direction::In, Proto::Tcp)
        );
        let b = got.rules[1].as_ref().expect("regola 2");
        assert_eq!((b.action, b.log), (Action::Deny, LogLevel::Log));
    }
}
/// Profili del repository `pyla-profiles` congelati in `tests/fixtures/profiles`:
/// qui si importa la forma REALE dei file, non mock. Lo script
/// `packaging/check-profile-fixtures.sh` verifica che i fixture non siano andati
/// oltre la versione del formato che questo parser sa leggere.
#[cfg(test)]
mod profiles {
    use super::*;

    const STEALTH: &str = include_str!("../../../tests/fixtures/profiles/stealth.jsonc");
    const WORKSTATION: &str =
        include_str!("../../../tests/fixtures/profiles/workstation-laptop.jsonc");
    const HOME_SERVER: &str = include_str!("../../../tests/fixtures/profiles/home-server.jsonc");

    fn counts(im: &Imported) -> (usize, usize) {
        let e = im.entries_with_state();
        (
            e.iter().flatten().filter(|(_, en)| *en).count(),
            e.iter().flatten().filter(|(_, en)| !*en).count(),
        )
    }

    #[test]
    fn repo_profiles_import_as_declared() {
        // Numeri misurati sui file del repository: se il repo cambia e i fixture
        // no, questo test resta verde; quando si allineano, vincola i conteggi.
        let cases = [
            ("stealth", STEALTH, "Silent stealth", 10, 3),
            (
                "workstation-laptop",
                WORKSTATION,
                "Workstation laptop",
                3,
                3,
            ),
            ("home-server", HOME_SERVER, "Home server", 10, 1),
        ];
        for (label, text, name, on, off) in cases {
            let got = parse(text, label).unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(got.meta.name, name, "{label}: nome");
            assert_eq!(got.meta.format_version, 1, "{label}: versione");
            assert_eq!(counts(&got), (on, off), "{label}: conteggio regole");
        }
    }

    #[test]
    fn missing_format_version_means_one() {
        let got = parse(
            r#"{ "rules": [ { "action": "deny", "proto": "tcp" } ] }"#,
            "fb",
        )
        .expect("import senza format_version");
        assert_eq!(got.meta.format_version, MISSING_FORMAT_VERSION);
    }

    #[test]
    fn future_format_version_is_refused_with_an_actionable_message() {
        // Regressione reale: il repository ha aggiunto "format_version": 1 e il
        // parser, che non conosceva la chiave, rispondeva con un errore JSON.
        let err = parse(
            r#"{ "format_version": 2, "rules": [ { "action": "deny", "proto": "tcp" } ] }"#,
            "fb",
        )
        .expect_err("la versione 2 non e' leggibile da questa PYLA");
        match &err {
            ImportError::Format { got, max, pyla } => {
                assert_eq!((*got, *max), (2, SUPPORTED_FORMAT_VERSION));
                assert!(
                    pyla.chars().next().is_some_and(|c| c.is_ascii_digit()),
                    "versione vuota: {pyla}"
                );
                let msg = err.to_string();
                assert!(msg.contains("format_version"), "{msg}");
                assert!(msg.contains("PYLA"), "{msg}");
            }
            other => panic!("errore atteso Format, trovato {other:?}"),
        }
    }

    #[test]
    fn top_level_hint_lists_the_known_fields() {
        let err = parse(
            r#"{ "format_version": 1, "rules": [ { "action": "deny" } ], "baseline": "x" }"#,
            "fb",
        )
        .expect_err("campo top-level sconosciuto");
        match err {
            ImportError::Json { message, line } => {
                assert!(message.contains("baseline"), "{message}");
                assert!(message.contains("i campi accettati"), "{message}");
                assert_eq!(line, 1, "la riga dell'errore deve restare quella reale");
            }
            other => panic!("errore atteso Json, trovato {other:?}"),
        }
    }
}
