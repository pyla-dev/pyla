//! pyla-helper — l'unica parte di Pyla che gira come root.
//!
//! Avviato da pkexec (policy `space.pyla.app.helper`), parla JSON:
//!
//!   pyla-helper status            -> UfwStatus con le regole
//!   pyla-helper apply  < {rules}  -> ApplyReport
//!   pyla-helper enable | disable  -> UfwStatus
//!   pyla-helper ruleset           -> {"text": output di `nft list ruleset`}
//!   pyla-helper mitigate < {id,on} -> MitigateReport (mitigazioni CVE temporanee)
//!
//! Non usa mai una shell: `ufw` viene eseguito con argomenti già validati da
//! pyla-core. Prima di ogni modifica salva `user.rules`/`user6.rules` e, se un
//! comando fallisce o il risultato non coincide con il set, li ripristina.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use pyla_core::plan::{plan, Plan};
use pyla_core::ufw::{self, display_command, UfwStatus};
use pyla_core::{mitigation, RuleSpec};
use serde::{Deserialize, Serialize};

const UFW: &str = "/usr/sbin/ufw";
const NFT: &str = "/usr/sbin/nft";
const BACKUP_DIR: &str = "/var/lib/pyla/backups";
const KEEP_BACKUPS: usize = 30;
const MAX_INPUT: u64 = 1 << 20;
const MAX_RULES: usize = 500;

#[derive(Deserialize)]
struct ApplyRequest {
    rules: Vec<RuleSpec>,
}

#[derive(Serialize)]
struct CommandLog {
    command: String,
    ok: bool,
    output: String,
}

#[derive(Serialize)]
struct ApplyReport {
    ok: bool,
    message: String,
    plan: Plan,
    log: Vec<CommandLog>,
    rolled_back: bool,
    backup: Option<String>,
    before: UfwStatus,
    after: UfwStatus,
}

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let result = if !is_root() {
        Err("pyla-helper va avviato come root (tramite pkexec)".to_string())
    } else {
        match cmd.as_str() {
            "status" => status().and_then(to_json),
            "apply" => apply().and_then(to_json),
            "enable" => set_enabled(true).and_then(to_json),
            "disable" => set_enabled(false).and_then(to_json),
            "ruleset" => ruleset().and_then(to_json),
            "mitigate" => mitigate().and_then(to_json),
            _ => Err(format!(
                "comando sconosciuto: {cmd:?} (status|apply|enable|disable|ruleset|mitigate)"
            )),
        }
    };
    match result {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("{}", serde_json::json!({ "error": e }));
            ExitCode::FAILURE
        }
    }
}

fn to_json<T: Serialize>(v: T) -> Result<String, String> {
    serde_json::to_string(&v).map_err(|e| e.to_string())
}

fn is_root() -> bool {
    // Uid: reale effettivo salvato fs
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2).map(|euid| euid == "0"))
        })
        .unwrap_or(false)
}

fn status() -> Result<UfwStatus, String> {
    ufw::read_status(Path::new("/")).map_err(|e| format!("lettura stato UFW: {e}"))
}

fn run_ufw(args: &[String]) -> CommandLog {
    let out = Command::new(UFW)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .output();
    let command = display_command(args);
    match out {
        Ok(o) => {
            let mut output = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.trim().is_empty() {
                if !output.is_empty() {
                    output.push('\n');
                }
                output.push_str(err.trim());
            }
            CommandLog {
                command,
                ok: o.status.success(),
                output,
            }
        }
        Err(e) => CommandLog {
            command,
            ok: false,
            output: format!("avvio di {UFW}: {e}"),
        },
    }
}

fn read_request() -> Result<ApplyRequest, String> {
    let mut buf = String::new();
    std::io::stdin()
        .take(MAX_INPUT)
        .read_to_string(&mut buf)
        .map_err(|e| format!("lettura stdin: {e}"))?;
    let req: ApplyRequest =
        serde_json::from_str(&buf).map_err(|e| format!("richiesta non valida: {e}"))?;
    if req.rules.len() > MAX_RULES {
        return Err(format!("troppe regole (massimo {MAX_RULES})"));
    }
    Ok(req)
}

fn backup() -> Result<PathBuf, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let dir = Path::new(BACKUP_DIR).join(ts.to_string());
    std::fs::create_dir_all(&dir).map_err(|e| format!("creazione {}: {e}", dir.display()))?;
    for f in [ufw::USER_RULES, ufw::USER6_RULES] {
        let name = Path::new(f).file_name().unwrap();
        std::fs::copy(f, dir.join(name)).map_err(|e| format!("backup di {f}: {e}"))?;
    }
    prune_backups();
    Ok(dir)
}

fn prune_backups() {
    let Ok(entries) = std::fs::read_dir(BACKUP_DIR) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    dirs.sort();
    while dirs.len() > KEEP_BACKUPS {
        let _ = std::fs::remove_dir_all(dirs.remove(0));
    }
}

fn restore(dir: &Path, enabled: bool, log: &mut Vec<CommandLog>) -> Result<(), String> {
    for f in [ufw::USER_RULES, ufw::USER6_RULES] {
        let name = Path::new(f).file_name().unwrap();
        std::fs::copy(dir.join(name), f).map_err(|e| format!("ripristino di {f}: {e}"))?;
    }
    if enabled {
        let l = run_ufw(&["reload".into()]);
        let ok = l.ok;
        log.push(l);
        if !ok {
            return Err("ufw reload dopo il ripristino non riuscito".into());
        }
    }
    Ok(())
}

fn apply() -> Result<ApplyReport, String> {
    let req = read_request()?;
    let before = status()?;
    let plan = plan(&before, &req.rules).map_err(|e| e.to_string())?;

    if !plan.unsupported.is_empty() {
        return Err(format!(
            "in UFW ci sono regole che Pyla non gestisce, rimuovile prima con ufw o Gufw: {}",
            plan.unsupported.join(" | ")
        ));
    }
    if plan.in_sync {
        return Ok(ApplyReport {
            ok: true,
            message: "UFW è già allineato al set: nessuna modifica".into(),
            plan,
            log: Vec::new(),
            rolled_back: false,
            backup: None,
            after: before.clone(),
            before,
        });
    }

    let dir = backup()?;
    let mut log = Vec::new();
    let mut failure = None;
    for args in &plan.commands {
        let l = run_ufw(args);
        let ok = l.ok;
        log.push(l);
        if !ok {
            failure = Some("un comando ufw non è riuscito".to_string());
            break;
        }
    }
    let after = status()?;
    if failure.is_none() && after.specs() != plan.desired {
        failure = Some("dopo l'applicazione le regole in UFW non coincidono con il set".into());
    }

    let backup_s = Some(dir.display().to_string());
    match failure {
        None => Ok(ApplyReport {
            ok: true,
            message: format!("applicate {} regole", plan.desired.len()),
            plan,
            log,
            rolled_back: false,
            backup: backup_s,
            before,
            after,
        }),
        Some(why) => {
            let restored = restore(&dir, before.enabled, &mut log);
            let after = status()?;
            let message = match restored {
                Ok(()) => format!("{why}: ripristinate le regole precedenti"),
                Err(e) => format!(
                    "{why}; ripristino fallito ({e}), backup in {}",
                    dir.display()
                ),
            };
            Ok(ApplyReport {
                ok: false,
                message,
                plan,
                log,
                rolled_back: true,
                backup: backup_s,
                before,
                after,
            })
        }
    }
}

fn set_enabled(on: bool) -> Result<UfwStatus, String> {
    let args: Vec<String> = if on {
        vec!["--force".into(), "enable".into()]
    } else {
        vec!["disable".into()]
    };
    let l = run_ufw(&args);
    if !l.ok {
        return Err(format!("{}: {}", l.command, l.output));
    }
    status()
}

/// Ruleset completo del kernel, in sola lettura.
fn ruleset() -> Result<serde_json::Value, String> {
    let out = Command::new(NFT)
        .args(["list", "ruleset"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("avvio di {NFT}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "nft list ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(serde_json::json!({ "text": String::from_utf8_lossy(&out.stdout) }))
}

// ---------- mitigazioni CVE ----------

#[derive(Deserialize)]
struct MitigateRequest {
    id: String,
    on: bool,
}

#[derive(Serialize)]
struct MitigateReport {
    ok: bool,
    message: String,
    log: Vec<String>,
    check: mitigation::Check,
}

/// Scrive il file in modo atomico (tmp + rename), 0644 root.
fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("pyla-tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("scrittura {}: {e}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
}

fn mitigate() -> Result<MitigateReport, String> {
    let mut buf = String::new();
    std::io::stdin()
        .take(4096)
        .read_to_string(&mut buf)
        .map_err(|e| format!("lettura stdin: {e}"))?;
    let req: MitigateRequest =
        serde_json::from_str(&buf).map_err(|e| format!("richiesta non valida: {e}"))?;
    // solo id del registro: nessun nome di modulo o chiave sysctl arriva dall'esterno
    let m = mitigation::by_id(&req.id)
        .ok_or_else(|| format!("mitigazione sconosciuta: {:?}", req.id))?;
    if matches!(m.kind, mitigation::Kind::InUse { .. }) {
        return Err(format!("{} è solo una verifica", m.id));
    }
    let root = Path::new("/");
    let mut ids = mitigation::active_ids(root);
    ids.retain(|x| x != m.id);
    if req.on {
        ids.push(m.id.to_string());
    }
    let active: Vec<&mitigation::Mitigation> =
        ids.iter().filter_map(|i| mitigation::by_id(i)).collect();
    write_atomic(
        &root.join(mitigation::SYSCTL_FILE),
        &mitigation::render_sysctl(&active),
    )?;
    write_atomic(
        &root.join(mitigation::MODPROBE_FILE),
        &mitigation::render_modprobe(&active),
    )?;

    let mut log = vec![format!(
        "{} {}",
        if req.on { "attivata" } else { "rimossa" },
        m.id
    )];
    let mut ok = true;
    match m.kind {
        mitigation::Kind::Sysctl {
            key,
            value,
            default,
        } => {
            let v = if req.on { value } else { default };
            match std::fs::write(root.join(mitigation::sysctl_path(key)), v) {
                Ok(()) => log.push(format!("{key} = {v}")),
                Err(e) => {
                    ok = false;
                    log.push(format!("{key} = {v}: {e}"));
                }
            }
        }
        mitigation::Kind::Module { name }
            if req.on && root.join("sys/module").join(name).is_dir() =>
        {
            let out = Command::new("/usr/sbin/modprobe")
                .args(["-r", name])
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .output();
            match out {
                Ok(o) if o.status.success() => log.push(format!("modulo {name} scaricato")),
                Ok(o) => log.push(format!(
                    "modulo {name} in uso, non scaricato ({}): bloccato dal prossimo riavvio",
                    String::from_utf8_lossy(&o.stderr).trim()
                )),
                Err(e) => log.push(format!("modprobe -r {name}: {e}")),
            }
        }
        _ => {}
    }
    let check = mitigation::check(m, root);
    let message = if !ok {
        "mitigazione scritta ma non applicata subito: vedi dettagli".to_string()
    } else if req.on {
        match check.state {
            "al-riavvio" => format!("{}: effettiva al prossimo riavvio", m.label),
            _ => format!("{}: attiva", m.label),
        }
    } else {
        format!("{}: rimossa", m.label)
    };
    Ok(MitigateReport {
        ok,
        message,
        log,
        check,
    })
}
