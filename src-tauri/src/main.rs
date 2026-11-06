#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod cve;
mod db;
mod helper;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use db::{Db, LogEntry, Rule, Ruleset, RulesetSummary};
use pyla_core::plan::{plan, Plan};
use pyla_core::ufw::{self, display_command, UfwStatus};
use pyla_core::{RuleSpec, HELPER_PATH};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, State};

struct AppState {
    db: Mutex<Db>,
    db_path: PathBuf,
}

type Res<T> = Result<T, String>;

fn with_db<T>(state: &State<AppState>, f: impl FnOnce(&mut Db) -> Res<T>) -> Res<T> {
    let mut db = state
        .db
        .lock()
        .map_err(|_| "database bloccato".to_string())?;
    f(&mut db)
}

#[derive(Serialize)]
struct AppInfo {
    helper_installed: bool,
    helper_path: &'static str,
    db_path: String,
}

#[tauri::command]
fn app_info(state: State<AppState>) -> AppInfo {
    AppInfo {
        helper_installed: helper::installed(),
        helper_path: HELPER_PATH,
        db_path: state.db_path.display().to_string(),
    }
}

/// Interruttore e policy di default: leggibili senza root.
#[tauri::command]
fn local_status() -> Res<UfwStatus> {
    ufw::read_conf(Path::new("/")).map_err(|e| format!("lettura configurazione UFW: {e}"))
}

#[tauri::command]
fn list_rulesets(state: State<AppState>) -> Res<Vec<RulesetSummary>> {
    with_db(&state, |db| db.list_rulesets())
}

#[tauri::command]
fn get_ruleset(state: State<AppState>, id: i64) -> Res<Ruleset> {
    with_db(&state, |db| db.get_ruleset(id))
}

#[tauri::command]
fn create_ruleset(
    state: State<AppState>,
    name: String,
    description: String,
    copy_from: Option<i64>,
) -> Res<i64> {
    with_db(&state, |db| match copy_from {
        Some(from) => db.copy_ruleset(from, &name, &description),
        None => db.create_ruleset(&name, &description, &[]),
    })
}

#[tauri::command]
fn update_ruleset(state: State<AppState>, id: i64, name: String, description: String) -> Res<()> {
    with_db(&state, |db| db.update_ruleset(id, &name, &description))
}

#[tauri::command]
fn delete_ruleset(state: State<AppState>, id: i64) -> Res<()> {
    with_db(&state, |db| db.delete_ruleset(id))
}

#[derive(Deserialize)]
struct RuleInput {
    id: Option<i64>,
    enabled: bool,
    #[serde(flatten)]
    spec: RuleSpec,
}

#[tauri::command]
fn save_rule(state: State<AppState>, ruleset_id: i64, rule: RuleInput) -> Res<i64> {
    let spec = rule.spec.normalized().map_err(|e| e.to_string())?;
    with_db(&state, |db| {
        db.save_rule(ruleset_id, rule.id, rule.enabled, &spec)
    })
}

#[tauri::command]
fn delete_rule(state: State<AppState>, id: i64) -> Res<()> {
    with_db(&state, |db| db.delete_rule(id))
}

#[tauri::command]
fn set_rule_enabled(state: State<AppState>, id: i64, enabled: bool) -> Res<()> {
    with_db(&state, |db| db.set_rule_enabled(id, enabled))
}

#[tauri::command]
fn move_rule(state: State<AppState>, id: i64, delta: i64) -> Res<()> {
    with_db(&state, |db| db.move_rule(id, delta))
}

#[tauri::command]
fn history(state: State<AppState>, limit: Option<i64>) -> Res<Vec<LogEntry>> {
    with_db(&state, |db| db.history(limit.unwrap_or(50)))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Res<T> + Send + 'static) -> Res<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("operazione interrotta: {e}"))?
}

/// Stato completo, regole incluse (chiede l'autenticazione).
#[tauri::command]
async fn live_status() -> Res<UfwStatus> {
    blocking(|| helper::call("status", None)).await
}

/// Crea un nuovo set con le regole presenti ora in UFW.
#[tauri::command]
async fn import_live(state: State<'_, AppState>, name: String) -> Res<i64> {
    let st: UfwStatus = blocking(|| helper::call("status", None)).await?;
    let skipped = st.unsupported().len();
    let id = with_db(&state, |db| {
        db.create_ruleset(
            &name,
            &if skipped > 0 {
                format!("Importato da UFW ({skipped} regole non gestite escluse)")
            } else {
                "Importato da UFW".into()
            },
            &st.specs(),
        )
    })?;
    // Se il set importato è esattamente ciò che c'è in UFW, è già quello attivo.
    if skipped == 0 {
        with_db(&state, |db| db.set_active_ruleset(id))?;
    }
    Ok(id)
}

#[derive(Serialize)]
struct Preview {
    status: UfwStatus,
    plan: Plan,
    commands: Vec<String>,
}

#[tauri::command]
async fn preview(state: State<'_, AppState>, ruleset_id: i64) -> Res<Preview> {
    let desired = with_db(&state, |db| db.enabled_specs(ruleset_id))?;
    let status: UfwStatus = blocking(|| helper::call("status", None)).await?;
    let plan = plan(&status, &desired).map_err(|e| e.to_string())?;
    let commands = plan.commands.iter().map(|a| display_command(a)).collect();
    Ok(Preview {
        status,
        plan,
        commands,
    })
}

#[tauri::command]
async fn apply(state: State<'_, AppState>, ruleset_id: i64) -> Res<serde_json::Value> {
    let (name, desired) = with_db(&state, |db| {
        let rs = db.get_ruleset(ruleset_id)?;
        let specs = rs
            .rules
            .into_iter()
            .filter(|r| r.enabled)
            .map(|r| r.spec)
            .collect::<Vec<_>>();
        Ok((rs.name, specs))
    })?;
    // Validazione anche qui, per dare l'errore prima di chiedere la password.
    pyla_core::plan::validate_all(&desired).map_err(|e| e.to_string())?;

    let input = serde_json::json!({ "rules": desired });
    let report: serde_json::Value = blocking(move || helper::call("apply", Some(&input))).await?;

    let ok = report.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let message = report
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    with_db(&state, |db| {
        db.log_apply(ruleset_id, &name, ok, &message, &report)?;
        if ok {
            db.set_active_ruleset(ruleset_id)?;
        }
        Ok(())
    })?;
    Ok(report)
}

#[tauri::command]
async fn set_firewall(enabled: bool) -> Res<UfwStatus> {
    let cmd = if enabled { "enable" } else { "disable" };
    blocking(move || helper::call(cmd, None)).await
}

#[derive(Deserialize)]
struct RulesetText {
    text: String,
}

#[derive(Serialize)]
struct FullRuleset {
    text: String,
    tables: Vec<pyla_core::nft::NftTable>,
}

/// Ruleset completo del kernel (nft), in sola lettura.
#[tauri::command]
async fn full_ruleset() -> Res<FullRuleset> {
    let r: RulesetText = blocking(|| helper::call("ruleset", None)).await?;
    let tables = pyla_core::nft::parse_ruleset(&r.text);
    Ok(FullRuleset {
        text: r.text,
        tables,
    })
}

/// Regole del set in forma di comandi `ufw`, per copiarle o controllarle.
#[tauri::command]
fn ruleset_commands(state: State<AppState>, id: i64) -> Res<Vec<String>> {
    let rules: Vec<Rule> = with_db(&state, |db| db.rules(id))?;
    Ok(rules
        .iter()
        .map(|r| {
            let cmd = display_command(&ufw::rule_args(&r.spec));
            if r.enabled {
                cmd
            } else {
                format!("# disabilitata: {cmd}")
            }
        })
        .collect())
}

#[derive(Serialize)]
struct CveWatch {
    system: cve::System,
    items: Vec<serde_json::Value>,
}

/// Rinfresco CVE in un thread dedicato (mai in foreground: ubuntu.com risponde lento).
/// I dati vecchi restano visibili; a fine fetch la UI riceve "cve-refreshed" e rilegge.
static CVE_REFRESHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn spawn_cve_refresh(app: tauri::AppHandle) {
    if CVE_REFRESHING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return; // già in corso
    }
    std::thread::spawn(move || {
        let ids = cve::cache()
            .and_then(|db| db.cve_watch())
            .unwrap_or_default();
        if let Err(e) = cve::refresh_watch(&ids) {
            eprintln!("refresh watch: {e}");
        }
        if let Err(e) = cve::refresh_kernel() {
            eprintln!("refresh kernel: {e}");
        }
        CVE_REFRESHING.store(false, std::sync::atomic::Ordering::SeqCst);
        let _ = app.emit("cve-refreshed", ());
    });
}

/// CVE seguite dalla cache (istantaneo). Se scadute, parte il rinfresco in background.
#[tauri::command]
async fn cve_watched(app: tauri::AppHandle) -> Res<CveWatch> {
    let (system, items) = blocking(cve::watched_snapshot).await?;
    if blocking(cve::watch_refresh_needed).await.unwrap_or(true) {
        spawn_cve_refresh(app);
    }
    let items = items
        .into_iter()
        .map(|i| serde_json::to_value(i).unwrap_or_default())
        .collect();
    Ok(CveWatch { system, items })
}

/// CVE del kernel aperte su questa release (high/critical), dalla cache; `limit` massimo 2000.
#[tauri::command]
async fn cve_kernel(app: tauri::AppHandle, limit: Option<usize>) -> Res<cve::CvePage> {
    let limit = limit.unwrap_or(500).clamp(1, 2000);
    let page = blocking(move || cve::kernel_snapshot(limit)).await?;
    if blocking(cve::kernel_refresh_needed).await.unwrap_or(true) {
        spawn_cve_refresh(app);
    }
    Ok(page)
}

#[tauri::command]
fn cve_watch_set(
    app: tauri::AppHandle,
    state: State<AppState>,
    id: String,
    watch: bool,
) -> Res<Vec<String>> {
    let id = id.trim().to_uppercase();
    if !cve::valid_id(&id) {
        return Err(format!(
            "identificativo non valido: {id:?} (formato CVE-AAAA-NNNNN)"
        ));
    }
    let ids = with_db(&state, |db| {
        let mut ids = db.cve_watch()?;
        ids.retain(|x| *x != id);
        if watch {
            ids.insert(0, id);
        }
        db.set_cve_watch(&ids)?;
        Ok(ids)
    })?;
    spawn_cve_refresh(app);
    Ok(ids)
}

#[derive(Serialize)]
struct MitigationStates {
    checks: Vec<pyla_core::mitigation::Check>,
    listeners: Vec<pyla_core::exposure::Listener>,
}

/// Stato di tutte le mitigazioni + listener TCP (senza root, senza rete).
#[tauri::command]
fn mitigation_states() -> MitigationStates {
    let root = Path::new("/");
    MitigationStates {
        checks: pyla_core::mitigation::ALL
            .iter()
            .map(|m| pyla_core::mitigation::check(m, root))
            .collect(),
        listeners: pyla_core::exposure::listeners(root),
    }
}

/// Exposure check v2: confronta i listener TCP con le catene input del ruleset
/// nftables live (chiede l'autenticazione: legge nft tramite l'helper).
#[tauri::command]
async fn exposure_check() -> Res<Vec<pyla_core::exposure::Exposure>> {
    let r: RulesetText = blocking(|| helper::call("ruleset", None)).await?;
    let ls = pyla_core::exposure::listeners(Path::new("/"));
    Ok(pyla_core::exposure::assess(&ls, &r.text))
}

/// Attiva o rimuove una mitigazione tramite l'helper (chiede l'autenticazione).
#[tauri::command]
async fn mitigate(id: String, on: bool) -> Res<serde_json::Value> {
    if pyla_core::mitigation::by_id(&id).is_none() {
        return Err(format!("mitigazione sconosciuta: {id}"));
    }
    let req = serde_json::json!({ "id": id, "on": on });
    blocking(move || helper::call("mitigate", Some(&req))).await
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let db_path = dir.join("pyla.db");
            let db = Db::open(&db_path)?;
            let _ = cve::DB_PATH.set(db_path.clone());
            app.manage(AppState {
                db: Mutex::new(db),
                db_path,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            local_status,
            list_rulesets,
            get_ruleset,
            create_ruleset,
            update_ruleset,
            delete_ruleset,
            save_rule,
            delete_rule,
            set_rule_enabled,
            move_rule,
            history,
            live_status,
            import_live,
            preview,
            apply,
            set_firewall,
            ruleset_commands,
            full_ruleset,
            cve_watched,
            cve_kernel,
            cve_watch_set,
            mitigation_states,
            exposure_check,
            mitigate,
        ])
        .run(tauri::generate_context!())
        .expect("avvio di Pyla");
}
