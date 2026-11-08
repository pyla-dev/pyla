//! Stato condiviso dell'applicazione, indipendente dal trasporto (Tauri o HTTP).
//!
//! Il database SQLite e' la fonte di verità di PYLA (vedi `db.rs`): in entrambe
//! le modalita' lo apriamo dallo stesso schema di percorso, cosi' i set creati a
//! desktop si ritrovano nella console web sullo stesso host.

use std::path::PathBuf;
use std::sync::Mutex;

use crate::db::Db;

pub type Res<T> = Result<T, String>;

pub struct AppState {
    pub db: Mutex<Db>,
    pub db_path: PathBuf,
    /// "desktop" o "web": finisce in `app_info` (e nel `/api/info` web).
    pub mode: &'static str,
}

impl AppState {
    pub fn new(db_path: PathBuf, mode: &'static str) -> Res<Self> {
        let db = Db::open(&db_path)?;
        Ok(Self {
            db: Mutex::new(db),
            db_path,
            mode,
        })
    }

    pub fn with_db<T>(&self, f: impl FnOnce(&mut Db) -> Res<T>) -> Res<T> {
        let mut db = self.db.lock().map_err(|_| "database bloccato".to_string())?;
        f(&mut db)
    }
}

/// Directory dati per la modalita' web. In desktop la risolve Tauri con
/// `app.path().app_data_dir()`, che usa l'identifier `space.pyla.app` di
/// `tauri.conf.json`: qui la risolviamo a mano con lo stesso schema.
///
/// Base, priorita': `--data-dir` > `$PYLA_DATA_DIR` > `$XDG_DATA_HOME` >
/// `$HOME/.local/share` (fallback `/var/lib` per un servizio di sistema senza
/// HOME). La directory finale e' sempre `<base>/space.pyla.app`, quindi
/// `--data-dir /var/lib/pyla` -> `/var/lib/pyla/space.pyla.app/pyla.db`.
pub fn web_data_dir(explicit: Option<PathBuf>) -> PathBuf {
    let env_dir = |k: &str| {
        std::env::var(k)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let base = match explicit {
        Some(p) => p,
        None => env_dir("PYLA_DATA_DIR")
            .or_else(|| env_dir("XDG_DATA_HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = env_dir("HOME").unwrap_or_else(|| "/var/lib".to_string());
                PathBuf::from(home).join(".local/share")
            }),
    };
    base.join("space.pyla.app")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_esplicita_vince() {
        let p = web_data_dir(Some(PathBuf::from("/var/lib/pyla")));
        assert_eq!(p, PathBuf::from("/var/lib/pyla/space.pyla.app"));
    }
}
