//! Vulnerabilità del kernel Ubuntu (Ubuntu Security API, sola lettura, senza root).
//!
//! Fonte: <https://ubuntu.com/security/cves.json> e `/security/cves/<ID>.json`.
//! Lo stato di ogni CVE si legge per la release in uso (es. `resolute`) e per il
//! pacchetto sorgente del kernel in esecuzione (di solito `linux`); la versione
//! installata si confronta con quella corretta tramite `dpkg --compare-versions`.
//!
//! ## Cache (schema v2)
//! Le CVE vengono salvate in `cve_cache` (raw JSON dell'API) con elenco ordinato
//! per chiave (`<release>|<pacchetto>` per l'elenco kernel, `watch` per le seguite)
//! e timestamp in `cve_cache_meta`. La UI legge SEMPRE dalla cache (istantaneo) e
//! il rinfresco scatta in un thread in background quando i dati sono più vecchi
//! di `TTL`; il verdetto viene ricalcolato a ogni lettura contro il kernel
//! installato, quindi un update del kernel non richiede un nuovo fetch.

use std::process::Command;
use std::time::Duration;

use crate::db::Db;

/// Connessione dedicata alla cache CVE (SQLite WAL: letture concorrenti con la
/// UI e una sola scrittura per volta; busy_timeout nel reader).
pub fn cache() -> Result<Db, String> {
    let path = DB_PATH
        .get()
        .ok_or_else(|| "percorso database non impostato".to_string())?;
    Db::open_writer(path)
}

pub static DB_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

use serde::{Deserialize, Serialize};

const API: &str = "https://ubuntu.com/security/cves";
pub const PAGE: usize = 20; // massimo consentito dall'API
const UA: &str = concat!("pyla/", env!("CARGO_PKG_VERSION"), " (+firewall GUI)");

/// Durata dei dati in cache: oltre questa soglia la prossima lettura avvia
/// un rinfresco in background (i dati vecchi vengono mostrati finché non arriva il nuovo).
pub const TTL: i64 = 6 * 3600;

pub fn epoch_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn cache_key(sys: &System) -> String {
    format!("{}|{}", sys.release, sys.package)
}

#[derive(Serialize, Clone)]
pub struct System {
    pub release: String,
    pub kernel: String,
    pub package: String,
    pub version: String,
}

#[derive(Serialize)]
pub struct CveItem {
    pub id: String,
    pub priority: String,
    pub cvss3: Option<f64>,
    pub published: String,
    pub title: String,
    pub description: String,
    pub mitigation: String,
    pub url: String,
    /// Stato Ubuntu per release + pacchetto (needed, pending, released, not-affected, DNE…).
    pub status: String,
    /// Versione corretta indicata da Ubuntu (vuota se non c'è ancora).
    pub fix_version: String,
    /// vulnerable | update | fixed | not-affected | unknown
    pub verdict: String,
    /// Mitigazione/verifica del sottosistema (id del registro pyla_core::mitigation).
    pub mitigation_id: Option<&'static str>,
    pub mitigation_note: Option<&'static str>,
}

#[derive(Serialize)]
pub struct CvePage {
    pub system: System,
    pub total: usize,
    pub offset: usize,
    /// Epoch secondi dell'ultimo fetch in cache (0 = mai scaricata).
    pub updated_at: i64,
    pub items: Vec<CveItem>,
}

#[derive(Deserialize, Serialize)]
struct ApiList {
    cves: Vec<ApiCve>,
    total_results: usize,
}

#[derive(Deserialize, Serialize)]
struct ApiCve {
    id: String,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    cvss3: Option<f64>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    ubuntu_description: Option<String>,
    #[serde(default)]
    mitigation: Option<String>,
    #[serde(default)]
    packages: Vec<ApiPackage>,
}

#[derive(Deserialize, Serialize)]
struct ApiPackage {
    name: String,
    statuses: Vec<ApiStatus>,
}

#[derive(Deserialize, Serialize)]
struct ApiStatus {
    release_codename: String,
    status: String,
    #[serde(default)]
    description: Option<String>,
}

fn output(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Release, kernel in esecuzione e relativo pacchetto sorgente installato.
pub fn system() -> Result<System, String> {
    let release = output("lsb_release", &["-cs"])
        .or_else(|| {
            std::fs::read_to_string("/etc/os-release")
                .ok()
                .and_then(|s| {
                    s.lines().find_map(|l| {
                        l.strip_prefix("VERSION_CODENAME=")
                            .map(|v| v.trim_matches('"').to_string())
                    })
                })
        })
        .filter(|s| !s.is_empty())
        .ok_or("release Ubuntu non determinabile")?;
    let kernel = output("uname", &["-r"]).ok_or("uname -r fallito")?;
    // linux-image-* viene da linux-signed; i moduli dal sorgente vero (es. `linux`).
    let (package, version) = output(
        "dpkg-query",
        &[
            "-W",
            "-f=${source:Package} ${source:Version}",
            &format!("linux-modules-{kernel}"),
        ],
    )
    .and_then(|s| {
        s.split_once(' ')
            .map(|(p, v)| (p.to_string(), v.to_string()))
    })
    .unwrap_or_else(|| ("linux".to_string(), String::new()));
    Ok(System {
        release,
        kernel,
        package,
        version,
    })
}

fn get_json<T: for<'de> Deserialize<'de>>(url: &str) -> Result<T, String> {
    // Le liste dell'API Ubuntu richiedono 20-40s: il refresh gira in background,
    // quindi qui il timeout e' largo e la UI non aspetta mai la rete.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .user_agent(UA)
        .build()
        .into();
    agent
        .get(url)
        .call()
        .map_err(|e| format!("ubuntu.com: {e}"))?
        .body_mut()
        .with_config()
        .limit(32 << 20)
        .read_json::<T>()
        .map_err(|e| format!("risposta di ubuntu.com non valida: {e}"))
}

fn version_lt(a: &str, b: &str) -> bool {
    Command::new("dpkg")
        .args(["--compare-versions", a, "lt", b])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Prima riga significativa della descrizione del kernel CNA (il titolo della patch).
fn title_of(desc: &str) -> String {
    desc.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .find(|l| !l.starts_with("In the Linux kernel, the following vulnerability"))
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

fn item(c: ApiCve, sys: &System) -> CveItem {
    let st = c
        .packages
        .iter()
        .find(|p| p.name == sys.package)
        .and_then(|p| {
            p.statuses
                .iter()
                .find(|s| s.release_codename == sys.release)
        });
    let (status, fix) = match st {
        Some(s) => (s.status.clone(), s.description.clone().unwrap_or_default()),
        None => (String::new(), String::new()),
    };
    let has_fix = fix.chars().next().is_some_and(|ch| ch.is_ascii_digit());
    let installed_fixed = has_fix && !sys.version.is_empty() && !version_lt(&sys.version, &fix);
    let verdict = match status.as_str() {
        "not-affected" | "DNE" => "not-affected",
        _ if installed_fixed => "fixed",
        "released" => "update",
        "needed" | "pending" | "deferred" | "needs-triage" => "vulnerable",
        _ => "unknown",
    };
    let description = c.description.unwrap_or_default().trim().to_string();
    let ubuntu = c.ubuntu_description.unwrap_or_default();
    let title = title_of(if ubuntu.trim().is_empty() {
        &description
    } else {
        &ubuntu
    });
    let mit = pyla_core::mitigation::for_cve(&c.id, &title);
    CveItem {
        url: format!("https://ubuntu.com/security/{}", c.id),
        mitigation_id: mit.map(|(m, _)| m.id),
        mitigation_note: mit.and_then(|(_, n)| n),
        title,
        id: c.id,
        priority: c.priority.unwrap_or_default(),
        cvss3: c.cvss3,
        published: c.published.unwrap_or_default().chars().take(10).collect(),
        description,
        mitigation: c.mitigation.unwrap_or_default().trim().to_string(),
        status,
        fix_version: if has_fix { fix } else { String::new() },
        verdict: verdict.to_string(),
    }
}

/// CVE del kernel ancora aperte (needed/pending) per questa release, priorità high/critical,
/// dalla più recente. `limit` = quante ne vuoi mostrare (dalla cache, istantaneo).
pub fn kernel_snapshot(limit: usize) -> Result<CvePage, String> {
    let sys = system()?;
    let (ids, total, age_snapshot) = match cache()?.cve_cache_list(&cache_key(&sys))? {
        Some(l) => (l.ids, l.total, l.fetched_at),
        None => (Vec::new(), 0, 0),
    };
    let raws = cache()?.cve_cache_raw(&ids)?;
    let items = ids
        .iter()
        .take(limit)
        .filter_map(|id| raws.get(id))
        .filter_map(|raw| serde_json::from_str::<ApiCve>(raw).ok())
        .map(|c| item(c, &sys))
        .collect::<Vec<CveItem>>();
    Ok(CvePage {
        total,
        offset: items.len(),
        items,
        system: sys,
        updated_at: age_snapshot,
    })
}

/// True se l'elenco in cache va rinfrescato (vuoto, scaduto o incompleto).
pub fn kernel_refresh_needed() -> Result<bool, String> {
    let sys = system()?;
    Ok(match cache()?.cve_cache_list(&cache_key(&sys))? {
        None => true,
        Some(l) => epoch_now() - l.fetched_at > TTL || !l.complete,
    })
}

fn list_url(sys: &System, offset: usize) -> String {
    format!(
        "{API}.json?package={}&version={}&status=needed&status=pending&priority=critical&priority=high\
         &order=newest&limit={PAGE}&offset={offset}",
        sys.package, sys.release
    )
}

/// Rinfresco (da chiamare in background): scarica le pagine nuove dall'offset dove
/// finisce la cache e le unisce agli id già noti (l'API è ordinata per data crescente
/// di pubblicazione, quindi ciò che è in cache resta valido nelle stesse posizioni).
pub fn refresh_kernel() -> Result<usize, String> {
    let sys = system()?;
    let key = cache_key(&sys);
    let (mut ids, mut total, fresh_enough) = match cache()?.cve_cache_list(&key)? {
        Some(l) => (
            l.ids,
            l.total,
            epoch_now() - l.fetched_at <= TTL && l.complete,
        ),
        None => (Vec::new(), 0, false),
    };
    let mut raws = cache()?.cve_cache_raw(&ids)?;
    // A cache integra e recente bastano le novità; altrimenti riprendi/sincronizza.
    let max_pages = if fresh_enough && !raws.is_empty() {
        4
    } else {
        25
    };
    let mut fetched = 0usize;
    let mut offset = if raws.is_empty() { 0 } else { ids.len() };
    let mut complete = false;
    let mut last_err = String::new();
    for _ in 0..max_pages {
        // ubuntu.com risponde a volte con 504/timeout: due tentativi per pagina,
        // poi si salva il gia' scaricato e si riprova alla prossima apertura.
        let mut list = match get_json::<ApiList>(&list_url(&sys, offset)).or_else(|e1| {
            get_json::<ApiList>(&list_url(&sys, offset)).map_err(|e2| format!("{e1} / {e2}"))
        }) {
            Ok(l) => l,
            Err(e) => {
                last_err = e;
                break;
            }
        };
        total = list.total_results;
        let n = list.cves.len();
        for c in list.cves.drain(..) {
            let id = c.id.clone();
            raws.insert(id.clone(), serde_json::to_string(&c).unwrap_or_default());
            if !ids.contains(&id) {
                ids.push(id);
            }
            fetched += 1;
        }
        offset += n;
        if offset >= total || n == 0 {
            complete = true;
            break;
        }
    }
    if fetched == 0 && raws.is_empty() {
        return Err(if last_err.is_empty() {
            "nessun dato da ubuntu.com".into()
        } else {
            last_err
        });
    }
    cache()?.cve_cache_store(&key, total, &ids, &raws, complete)?;
    cache()?.cve_cache_prune(1500)?;
    Ok(fetched)
}

/// True se le CVE seguite vanno rinfrescate.
pub fn watch_refresh_needed() -> Result<bool, String> {
    Ok(match cache()?.cve_cache_list("watch")? {
        None => true,
        Some(l) => epoch_now() - l.fetched_at > TTL,
    })
}

/// Rinfresco delle CVE seguite (thread in background): una richiesta per id, con
/// timeout breve; gli errori non cancellano la copia in cache già presente.
pub fn refresh_watch(ids: &[String]) -> Result<usize, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .user_agent(UA)
        .build()
        .into();
    let mut raws = std::collections::HashMap::new();
    let mut ok_ids = Vec::new();
    for id in ids {
        if let Ok(c) = agent
            .get(format!("{API}/{id}.json"))
            .call()
            .and_then(|mut r| {
                r.body_mut()
                    .with_config()
                    .limit(8 << 20)
                    .read_json::<ApiCve>()
            })
        {
            raws.insert(id.clone(), serde_json::to_string(&c).unwrap_or_default());
            ok_ids.push(id.clone());
        }
    }
    if !ok_ids.is_empty() {
        let key = "watch";
        let mut all = cache()?
            .cve_cache_list(key)?
            .map(|l| l.ids)
            .unwrap_or_default();
        for id in &ok_ids {
            if !all.contains(id) {
                all.push(id.clone());
            }
        }
        // conserva anche i membri già in cache ma non aggiornati adesso
        let existing = cache()?.cve_cache_raw(&all)?;
        for (id, raw) in existing {
            raws.entry(id).or_insert(raw);
        }
        cache()?.cve_cache_store(key, all.len(), &all, &raws, true)?;
    }
    Ok(ok_ids.len())
}

/// Le seguite, lette dalla cache (istantaneo). `Err` solo per errori del DB.
pub fn watched_snapshot() -> Result<(System, Vec<CveItem>), String> {
    let sys = system()?;
    let ids = cache()?
        .cve_cache_list("watch")?
        .map(|l| l.ids)
        .unwrap_or_default();
    let raws = cache()?.cve_cache_raw(&ids)?;
    let items = ids
        .iter()
        .filter_map(|id| raws.get(id))
        .filter_map(|raw| serde_json::from_str::<ApiCve>(raw).ok())
        .map(|c| item(c, &sys))
        .collect();
    Ok((sys, items))
}

pub fn valid_id(id: &str) -> bool {
    let mut p = id.splitn(3, '-');
    matches!(
        (p.next(), p.next(), p.next()),
        (Some("CVE"), Some(y), Some(n))
            if y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit())
            && (4..=8).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(valid_id("CVE-2026-98432"));
        assert!(!valid_id("CVE-26-98432"));
        assert!(!valid_id("CVE-2026-98432; rm"));
        assert!(!valid_id("cve-2026-98432"));
    }

    #[test]
    fn title() {
        let d = "\nIn the Linux kernel, the following vulnerability has been resolved:\nipv4: free inet_opt\nmore";
        assert_eq!(title_of(d), "ipv4: free inet_opt");
    }

    /// Rete + cache: `cargo test -p pyla -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_api() {
        let dir = std::env::temp_dir().join(format!("pyla-cve-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pyla.db");
        let _ = crate::cve::DB_PATH.set(path.clone());
        Db::open(&path).unwrap(); // crea lo schema
        let _ = refresh_watch(&["CVE-2026-98432".to_string()]);
        let _ = refresh_kernel(); // ubuntu.com da' 503/504 a intermittenza: tollerato
        let (sys, items) = watched_snapshot().unwrap();
        let c = items
            .iter()
            .find(|c| c.id == "CVE-2026-98432")
            .expect("watched in cache");
        println!(
            "{} {} {} {:?} {} fix={} verdict={} | {}",
            sys.release,
            sys.package,
            sys.version,
            c.cvss3,
            c.priority,
            c.fix_version,
            c.verdict,
            c.title
        );
        let page = kernel_snapshot(20).unwrap();
        println!("aperte: {} (prime {})", page.total, page.items.len());
        for i in page.items.iter().take(3) {
            println!(
                "  {} {} {} {} {}",
                i.id, i.priority, i.status, i.verdict, i.title
            );
        }
        if page.items.is_empty() {
            println!("NOTA: ubuntu.com non ha restituito dati (503/504), cache vuota: ritentare.");
        }
    }
}
