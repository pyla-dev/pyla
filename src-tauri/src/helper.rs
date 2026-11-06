//! Chiamate all'helper privilegiato tramite pkexec.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use pyla_core::HELPER_PATH;
use serde::de::DeserializeOwned;

pub fn installed() -> bool {
    Path::new(HELPER_PATH).is_file()
}

/// Esegue `pkexec pyla-helper <cmd>` passando `input` su stdin e
/// interpreta la risposta JSON.
pub fn call<T: DeserializeOwned>(
    cmd: &str,
    input: Option<&serde_json::Value>,
) -> Result<T, String> {
    if !installed() {
        return Err(format!(
            "helper non installato in {HELPER_PATH}: esegui `sudo packaging/install-helper.sh`"
        ));
    }
    let mut child = Command::new("pkexec")
        .arg(HELPER_PATH)
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("avvio di pkexec: {e}"))?;
    {
        let mut stdin = child.stdin.take().expect("stdin piped");
        if let Some(v) = input {
            stdin
                .write_all(v.to_string().as_bytes())
                .map_err(|e| format!("invio all'helper: {e}"))?;
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("attesa dell'helper: {e}"))?;

    match out.status.code() {
        Some(126) => return Err("autenticazione annullata".into()),
        Some(127) => return Err("autenticazione negata o helper non autorizzato da polkit".into()),
        _ => {}
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).map_err(|_| {
        format!(
            "risposta non valida dall'helper (uscita {:?}): {} {}",
            out.status.code(),
            stdout.trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    })?;
    if let Some(err) = value.get("error").and_then(|v| v.as_str()) {
        if err.starts_with("comando sconosciuto") {
            return Err(format!(
                "l'helper installato in {HELPER_PATH} è più vecchio dell'app e non conosce `{cmd}`: \
                 ricompila (`cargo build --release`) e reinstalla con `sudo packaging/install-helper.sh`"
            ));
        }
        return Err(err.to_string());
    }
    serde_json::from_value(value).map_err(|e| format!("risposta dell'helper: {e}"))
}
