//! Database locale (SQLite, WAL): set di regole, regole con flag `enabled`,
//! storico delle applicazioni. È la fonte di verità di Pyla: UFW contiene solo
//! le regole abilitate del set applicato.

use std::path::Path;

use pyla_core::RuleSpec;
use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: i64 = 2;

const SCHEMA: &str = "
CREATE TABLE ruleset (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE TABLE rule (
    id         INTEGER PRIMARY KEY,
    ruleset_id INTEGER NOT NULL REFERENCES ruleset(id) ON DELETE CASCADE,
    position   INTEGER NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    action     TEXT NOT NULL,
    direction  TEXT NOT NULL,
    interface  TEXT,
    log        TEXT NOT NULL DEFAULT 'off',
    proto      TEXT NOT NULL,
    src        TEXT NOT NULL,
    sport      TEXT,
    dst        TEXT NOT NULL,
    dport      TEXT,
    comment    TEXT
);
CREATE INDEX rule_by_set ON rule(ruleset_id, position);
CREATE TABLE apply_log (
    id           INTEGER PRIMARY KEY,
    ts           TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    ruleset_id   INTEGER,
    ruleset_name TEXT NOT NULL,
    ok           INTEGER NOT NULL,
    message      TEXT NOT NULL,
    report       TEXT NOT NULL
);
CREATE TABLE setting (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

/// Schema v2: cache locale delle CVE Ubuntu (refresh lazy in background).
/// `raw` è il JSON dell'API: il verdetto si ricalcola a ogni lettura contro il
/// kernel installato, così un aggiornamento del kernel non richiede un re-fetch.
const SCHEMA_V2: &str = "
CREATE TABLE cve_cache (
    id         TEXT PRIMARY KEY,
    raw        TEXT NOT NULL,
    updated_at INTEGER NOT NULL           -- epoch secondi dell'ultimo fetch
);
CREATE TABLE cve_cache_member (
    key TEXT NOT NULL,                    -- '<release>|<pacchetto>' oppure 'watch'
    id  TEXT NOT NULL REFERENCES cve_cache(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL DEFAULT 0,       -- ordine dell'API (nuove prima)
    PRIMARY KEY (key, id)
);
CREATE TABLE cve_cache_meta (
    key        TEXT PRIMARY KEY,
    total      INTEGER NOT NULL DEFAULT 0,
    fetched_at INTEGER NOT NULL,          -- epoch secondi
    complete   INTEGER NOT NULL DEFAULT 0 -- 1 = tutte le pagine scaricate
);
";

pub type Result<T> = std::result::Result<T, String>;

fn e(err: rusqlite::Error) -> String {
    match err {
        rusqlite::Error::SqliteFailure(f, Some(msg)) if f.extended_code == 2067 => {
            format!("nome già usato ({msg})")
        }
        other => format!("database: {other}"),
    }
}

#[derive(Debug, Serialize)]
pub struct RulesetSummary {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub rules: i64,
    pub enabled: i64,
    pub active: bool,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: i64,
    pub enabled: bool,
    pub position: i64,
    #[serde(flatten)]
    pub spec: RuleSpec,
}

#[derive(Debug, Serialize)]
pub struct Ruleset {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub active: bool,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub id: i64,
    pub ts: String,
    pub ruleset_name: String,
    pub ok: bool,
    pub message: String,
    pub report: serde_json::Value,
}

/// Elenco CVE in cache: id nell'ordine dell'API, totale dichiarato, epoch
/// dell'ultimo fetch e flag "tutte le pagine scaricate".
pub struct CveCacheList {
    pub ids: Vec<String>,
    pub total: usize,
    pub fetched_at: i64,
    pub complete: bool,
}

/// Enum serde <-> testo nel DB (es. `Action::Allow` <-> `"allow"`).
fn enum_to<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

fn enum_from<T: DeserializeOwned>(s: String, col: usize) -> rusqlite::Result<T> {
    serde_json::from_value(serde_json::Value::String(s)).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(err))
    })
}

pub struct Db {
    conn: Connection,
}

impl Db {
    /// Connessione dedicata alla cache/refresh in background. WAL permette letture
    /// concorrenti con la UI; `busy_timeout` evita errori su scritture ravvicinate.
    pub fn open_writer(path: &Path) -> Result<Db> {
        let db = Db::open(path)?;
        db.conn
            .busy_timeout(std::time::Duration::from_millis(5000))
            .map_err(e)?;
        Ok(db)
    }
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        let conn = Connection::open(path).map_err(e)?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
            .map_err(e)?;
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(e)?;
        if version == 0 {
            conn.execute_batch(&format!(
                "BEGIN; {SCHEMA} {SCHEMA_V2} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;"
            ))
            .map_err(e)?;
        } else if version < SCHEMA_VERSION {
            if version < 2 {
                conn.execute_batch(&format!(
                    "BEGIN; {SCHEMA_V2} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;"
                ))
                .map_err(e)?;
            }
        } else if version > SCHEMA_VERSION {
            return Err(format!(
                "il database è di una versione più recente di Pyla (schema {version})"
            ));
        }
        Ok(Db { conn })
    }

    fn setting(&self, key: &str) -> Result<Option<String>> {
        self.conn
            .query_row("SELECT value FROM setting WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()
            .map_err(e)
    }

    fn set_setting(&self, key: &str, value: Option<&str>) -> Result<()> {
        match value {
            Some(v) => self.conn.execute(
                "INSERT INTO setting(key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, v],
            ),
            None => self
                .conn
                .execute("DELETE FROM setting WHERE key = ?1", [key]),
        }
        .map(|_| ())
        .map_err(e)
    }

    /// CVE seguite nella scheda CVE (default: CVE-2026-98432, TCP/IPv4 options, MPTCP).
    pub fn cve_watch(&self) -> Result<Vec<String>> {
        Ok(match self.setting("cve_watch")? {
            Some(v) => v
                .split(',')
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect(),
            None => vec!["CVE-2026-98432".to_string()],
        })
    }

    pub fn set_cve_watch(&self, ids: &[String]) -> Result<()> {
        self.set_setting("cve_watch", Some(&ids.join(",")))
    }

    pub fn active_ruleset(&self) -> Result<Option<i64>> {
        Ok(self.setting("active_ruleset")?.and_then(|v| v.parse().ok()))
    }

    pub fn set_active_ruleset(&self, id: i64) -> Result<()> {
        self.set_setting("active_ruleset", Some(&id.to_string()))
    }

    pub fn list_rulesets(&self) -> Result<Vec<RulesetSummary>> {
        let active = self.active_ruleset()?;
        let mut st = self
            .conn
            .prepare(
                "SELECT s.id, s.name, s.description, s.updated_at,
                        COUNT(r.id), COALESCE(SUM(r.enabled), 0)
                 FROM ruleset s LEFT JOIN rule r ON r.ruleset_id = s.id
                 GROUP BY s.id ORDER BY s.name COLLATE NOCASE",
            )
            .map_err(e)?;
        let rows = st
            .query_map([], |r| {
                let id: i64 = r.get(0)?;
                Ok(RulesetSummary {
                    id,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    updated_at: r.get(3)?,
                    rules: r.get(4)?,
                    enabled: r.get(5)?,
                    active: active == Some(id),
                })
            })
            .map_err(e)?;
        rows.collect::<rusqlite::Result<_>>().map_err(e)
    }

    pub fn get_ruleset(&self, id: i64) -> Result<Ruleset> {
        let (name, description): (String, String) = self
            .conn
            .query_row(
                "SELECT name, description FROM ruleset WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(e)?
            .ok_or_else(|| format!("set {id} non trovato"))?;
        Ok(Ruleset {
            id,
            name,
            description,
            active: self.active_ruleset()? == Some(id),
            rules: self.rules(id)?,
        })
    }

    pub fn rules(&self, ruleset_id: i64) -> Result<Vec<Rule>> {
        let mut st = self
            .conn
            .prepare(
                "SELECT id, enabled, position, action, direction, interface, log, proto,
                        src, sport, dst, dport, comment
                 FROM rule WHERE ruleset_id = ?1 ORDER BY position, id",
            )
            .map_err(e)?;
        let rows = st.query_map([ruleset_id], row_to_rule).map_err(e)?;
        rows.collect::<rusqlite::Result<_>>().map_err(e)
    }

    /// Regole abilitate, nell'ordine in cui vanno in UFW.
    pub fn enabled_specs(&self, ruleset_id: i64) -> Result<Vec<RuleSpec>> {
        Ok(self
            .rules(ruleset_id)?
            .into_iter()
            .filter(|r| r.enabled)
            .map(|r| r.spec)
            .collect())
    }

    fn touch(&self, ruleset_id: i64) -> Result<()> {
        self.conn
            .execute(
                "UPDATE ruleset SET updated_at = datetime('now', 'localtime') WHERE id = ?1",
                [ruleset_id],
            )
            .map(|_| ())
            .map_err(e)
    }

    pub fn create_ruleset(
        &mut self,
        name: &str,
        description: &str,
        specs: &[RuleSpec],
    ) -> Result<i64> {
        let name = name.trim();
        if name.is_empty() {
            return Err("il nome del set è obbligatorio".into());
        }
        let tx = self.conn.transaction().map_err(e)?;
        tx.execute(
            "INSERT INTO ruleset(name, description) VALUES (?1, ?2)",
            params![name, description.trim()],
        )
        .map_err(e)?;
        let id = tx.last_insert_rowid();
        for (i, s) in specs.iter().enumerate() {
            insert_rule(&tx, id, i as i64 + 1, true, s).map_err(e)?;
        }
        tx.commit().map_err(e)?;
        Ok(id)
    }

    /// Copia un set (tutte le regole, anche quelle disabilitate).
    pub fn copy_ruleset(&mut self, from: i64, name: &str, description: &str) -> Result<i64> {
        let rules = self.rules(from)?;
        let id = self.create_ruleset(name, description, &[])?;
        let tx = self.conn.transaction().map_err(e)?;
        for r in &rules {
            insert_rule(&tx, id, r.position, r.enabled, &r.spec).map_err(e)?;
        }
        tx.commit().map_err(e)?;
        Ok(id)
    }

    pub fn update_ruleset(&self, id: i64, name: &str, description: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err("il nome del set è obbligatorio".into());
        }
        self.conn
            .execute(
                "UPDATE ruleset SET name = ?2, description = ?3,
                        updated_at = datetime('now', 'localtime') WHERE id = ?1",
                params![id, name, description.trim()],
            )
            .map(|_| ())
            .map_err(e)
    }

    pub fn delete_ruleset(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM ruleset WHERE id = ?1", [id])
            .map_err(e)?;
        if self.active_ruleset()? == Some(id) {
            self.set_setting("active_ruleset", None)?;
        }
        Ok(())
    }

    /// Inserisce (id = None, in fondo) o aggiorna una regola già validata.
    pub fn save_rule(
        &self,
        ruleset_id: i64,
        id: Option<i64>,
        enabled: bool,
        spec: &RuleSpec,
    ) -> Result<i64> {
        let id = match id {
            Some(id) => {
                self.conn
                    .execute(
                        "UPDATE rule SET enabled = ?3, action = ?4, direction = ?5, interface = ?6,
                                log = ?7, proto = ?8, src = ?9, sport = ?10, dst = ?11, dport = ?12,
                                comment = ?13
                         WHERE id = ?1 AND ruleset_id = ?2",
                        params![
                            id,
                            ruleset_id,
                            enabled,
                            enum_to(&spec.action),
                            enum_to(&spec.direction),
                            spec.interface,
                            enum_to(&spec.log),
                            enum_to(&spec.proto),
                            spec.src,
                            spec.sport,
                            spec.dst,
                            spec.dport,
                            spec.comment
                        ],
                    )
                    .map_err(e)?;
                id
            }
            None => {
                let next: i64 = self
                    .conn
                    .query_row(
                        "SELECT COALESCE(MAX(position), 0) + 1 FROM rule WHERE ruleset_id = ?1",
                        [ruleset_id],
                        |r| r.get(0),
                    )
                    .map_err(e)?;
                insert_rule(&self.conn, ruleset_id, next, enabled, spec).map_err(e)?;
                self.conn.last_insert_rowid()
            }
        };
        self.touch(ruleset_id)?;
        Ok(id)
    }

    fn rule_set_of(&self, rule_id: i64) -> Result<i64> {
        self.conn
            .query_row(
                "SELECT ruleset_id FROM rule WHERE id = ?1",
                [rule_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(e)?
            .ok_or_else(|| format!("regola {rule_id} non trovata"))
    }

    pub fn delete_rule(&self, rule_id: i64) -> Result<()> {
        let set = self.rule_set_of(rule_id)?;
        self.conn
            .execute("DELETE FROM rule WHERE id = ?1", [rule_id])
            .map_err(e)?;
        self.touch(set)
    }

    pub fn set_rule_enabled(&self, rule_id: i64, enabled: bool) -> Result<()> {
        let set = self.rule_set_of(rule_id)?;
        self.conn
            .execute(
                "UPDATE rule SET enabled = ?2 WHERE id = ?1",
                params![rule_id, enabled],
            )
            .map_err(e)?;
        self.touch(set)
    }

    /// Sposta una regola di una posizione verso l'alto (-1) o il basso (+1).
    pub fn move_rule(&mut self, rule_id: i64, delta: i64) -> Result<()> {
        let set = self.rule_set_of(rule_id)?;
        let mut ids: Vec<i64> = self.rules(set)?.iter().map(|r| r.id).collect();
        let Some(i) = ids.iter().position(|&id| id == rule_id) else {
            return Ok(());
        };
        let j = i as i64 + delta.signum();
        if j < 0 || j >= ids.len() as i64 {
            return Ok(());
        }
        ids.swap(i, j as usize);
        let tx = self.conn.transaction().map_err(e)?;
        for (pos, id) in ids.iter().enumerate() {
            tx.execute(
                "UPDATE rule SET position = ?2 WHERE id = ?1",
                params![id, pos as i64 + 1],
            )
            .map_err(e)?;
        }
        tx.commit().map_err(e)?;
        self.touch(set)
    }

    pub fn log_apply(
        &self,
        ruleset_id: i64,
        ruleset_name: &str,
        ok: bool,
        message: &str,
        report: &serde_json::Value,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO apply_log(ruleset_id, ruleset_name, ok, message, report)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ruleset_id, ruleset_name, ok, message, report.to_string()],
            )
            .map(|_| ())
            .map_err(e)
    }

    pub fn history(&self, limit: i64) -> Result<Vec<LogEntry>> {
        let mut st = self
            .conn
            .prepare(
                "SELECT id, ts, ruleset_name, ok, message, report
                 FROM apply_log ORDER BY id DESC LIMIT ?1",
            )
            .map_err(e)?;
        let rows = st
            .query_map([limit], |r| {
                let report: String = r.get(5)?;
                Ok(LogEntry {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    ruleset_name: r.get(2)?,
                    ok: r.get(3)?,
                    message: r.get(4)?,
                    report: serde_json::from_str(&report).unwrap_or(serde_json::Value::Null),
                })
            })
            .map_err(e)?;
        rows.collect::<rusqlite::Result<_>>().map_err(e)
    }

    // ---------- cache CVE (schema v2) ----------

    /// Elenco in cache per una chiave (`<release>|<pacchetto>` o `watch`).
    pub fn cve_cache_list(&self, key: &str) -> Result<Option<CveCacheList>> {
        let meta: Option<(i64, i64, i64)> = self
            .conn
            .query_row(
                "SELECT total, fetched_at, complete FROM cve_cache_meta WHERE key = ?1",
                [key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(e)?;
        let Some((total, fetched_at, complete)) = meta else {
            return Ok(None);
        };
        let mut st = self
            .conn
            .prepare("SELECT id FROM cve_cache_member WHERE key = ?1 ORDER BY seq, id")
            .map_err(e)?;
        let ids = st
            .query_map([key], |r| r.get::<_, String>(0))
            .and_then(|m| m.collect::<rusqlite::Result<_>>())
            .map_err(e)?;
        Ok(Some(CveCacheList {
            ids,
            total: total as usize,
            fetched_at,
            complete: complete != 0,
        }))
    }

    /// CVE presenti in cache: map id -> raw JSON (quelle mancanti non compaiono).
    pub fn cve_cache_raw(
        &self,
        ids: &[String],
    ) -> Result<std::collections::HashMap<String, String>> {
        let mut out = std::collections::HashMap::new();
        // SQLite limita il numero di parametri: chunk da 100.
        for chunk in ids.chunks(100) {
            let ph = vec!["?"; chunk.len()].join(",");
            let sql = format!("SELECT id, raw FROM cve_cache WHERE id IN ({ph})");
            let mut st = self.conn.prepare(&sql).map_err(e)?;
            let ps: Vec<&dyn rusqlite::ToSql> =
                chunk.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
            let rows = st
                .query_map(ps.as_slice(), |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(e)?;
            for row in rows {
                let (id, raw) = row.map_err(e)?;
                out.insert(id, raw);
            }
        }
        Ok(out)
    }

    /// Inserisce/aggiorna CVE (id + raw JSON) e ricostruisce l'elenco per `key`.
    /// `ids` è l'ordine dell'API; `complete` = false se ci sono altre pagine da prendere.
    pub fn cve_cache_store(
        &mut self,
        key: &str,
        total: usize,
        ids: &[String],
        raws: &std::collections::HashMap<String, String>,
        complete: bool,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let tx = self.conn.transaction().map_err(e)?;
        for id in ids {
            if let Some(raw) = raws.get(id) {
                tx.execute(
                    "INSERT INTO cve_cache(id, raw, updated_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(id) DO UPDATE SET raw = excluded.raw, updated_at = excluded.updated_at",
                    params![id, raw, now],
                )
                .map_err(e)?;
            }
        }
        tx.execute("DELETE FROM cve_cache_member WHERE key = ?1", [key])
            .map_err(e)?;
        for (i, id) in ids.iter().enumerate() {
            if raws.contains_key(id) {
                tx.execute(
                    "INSERT OR IGNORE INTO cve_cache_member(key, id, seq) VALUES (?1, ?2, ?3)",
                    params![key, id, i as i64],
                )
                .map_err(e)?;
            }
        }
        tx.execute(
            "INSERT INTO cve_cache_meta(key, total, fetched_at, complete) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO UPDATE SET total = excluded.total, fetched_at = excluded.fetched_at,
               complete = excluded.complete",
            params![key, total as i64, now, complete as i64],
        )
        .map_err(e)?;
        tx.commit().map_err(e)
    }

    /// Mantiene al più `keep` CVE in cache (le aggiornate di recente).
    pub fn cve_cache_prune(&self, keep: usize) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM cve_cache WHERE id NOT IN (
                     SELECT id FROM cve_cache ORDER BY updated_at DESC, id LIMIT ?1)",
                [keep as i64],
            )
            .map(|_| ())
            .map_err(e)
    }
}

fn insert_rule(
    conn: &Connection,
    ruleset_id: i64,
    position: i64,
    enabled: bool,
    s: &RuleSpec,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO rule(ruleset_id, position, enabled, action, direction, interface, log,
                          proto, src, sport, dst, dport, comment)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            ruleset_id,
            position,
            enabled,
            enum_to(&s.action),
            enum_to(&s.direction),
            s.interface,
            enum_to(&s.log),
            enum_to(&s.proto),
            s.src,
            s.sport,
            s.dst,
            s.dport,
            s.comment
        ],
    )
}

fn row_to_rule(r: &rusqlite::Row) -> rusqlite::Result<Rule> {
    Ok(Rule {
        id: r.get(0)?,
        enabled: r.get(1)?,
        position: r.get(2)?,
        spec: RuleSpec {
            action: enum_from(r.get(3)?, 3)?,
            direction: enum_from(r.get(4)?, 4)?,
            interface: r.get(5)?,
            log: enum_from(r.get(6)?, 6)?,
            proto: enum_from(r.get(7)?, 7)?,
            src: r.get(8)?,
            sport: r.get(9)?,
            dst: r.get(10)?,
            dport: r.get(11)?,
            comment: r.get(12)?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyla_core::{Action, Direction, LogLevel, Proto};

    fn spec(src: &str) -> RuleSpec {
        RuleSpec {
            action: Action::Allow,
            direction: Direction::In,
            interface: None,
            log: LogLevel::Off,
            proto: Proto::Tcp,
            src: src.into(),
            sport: None,
            dst: "any".into(),
            dport: Some("22".into()),
            comment: Some("prova".into()),
        }
    }

    #[test]
    fn roundtrip_and_ordering() {
        let mut db = Db::open(Path::new(":memory:")).unwrap();
        let id = db
            .create_ruleset("Casa", "", &[spec("192.0.2.9"), spec("192.0.2.6")])
            .unwrap();
        let rules = db.rules(id).unwrap();
        assert_eq!(rules[0].spec, spec("192.0.2.9"));

        db.move_rule(rules[1].id, -1).unwrap();
        db.set_rule_enabled(rules[0].id, false).unwrap();
        assert_eq!(db.enabled_specs(id).unwrap(), vec![spec("192.0.2.6")]);

        let copy = db.copy_ruleset(id, "Casa 2", "").unwrap();
        assert_eq!(db.rules(copy).unwrap().len(), 2);
        assert!(db
            .create_ruleset("Casa", "", &[])
            .unwrap_err()
            .contains("nome già usato"));

        db.set_active_ruleset(id).unwrap();
        db.delete_ruleset(id).unwrap();
        assert_eq!(db.active_ruleset().unwrap(), None);
        assert_eq!(db.list_rulesets().unwrap().len(), 1);
    }

    #[test]
    fn cve_cache_roundtrip() {
        let mut db = Db::open(Path::new(":memory:")).unwrap();
        assert!(db.cve_cache_list("resolute|linux").unwrap().is_none());

        let ids: Vec<String> = ["CVE-2026-1", "CVE-2026-2"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut raws = std::collections::HashMap::new();
        raws.insert("CVE-2026-1".into(), r#"{"id":"CVE-2026-1"}"#.into());
        raws.insert("CVE-2026-2".into(), r#"{"id":"CVE-2026-2"}"#.into());
        db.cve_cache_store("resolute|linux", 415, &ids, &raws, false)
            .unwrap();

        let l = db.cve_cache_list("resolute|linux").unwrap().unwrap();
        assert_eq!(l.ids, ids);
        assert_eq!(l.total, 415);
        assert!(l.fetched_at > 0 && !l.complete);
        assert_eq!(db.cve_cache_raw(&ids).unwrap().len(), 2);

        // riscrittura parziale: CVE-2026-2 non piu' nell'elenco sparisce dai membri
        db.cve_cache_store("resolute|linux", 1, &ids[..1], &raws, true)
            .unwrap();
        let l = db.cve_cache_list("resolute|linux").unwrap().unwrap();
        assert_eq!(l.ids, vec!["CVE-2026-1".to_string()]);
        assert!(l.complete);

        db.cve_cache_prune(0).unwrap();
        assert!(db.cve_cache_raw(&ids).unwrap().is_empty());
    }
}
