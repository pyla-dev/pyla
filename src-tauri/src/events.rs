//! Bus degli eventi in uscita verso l'interfaccia.
//!
//! Il desktop usa gli eventi Tauri (`app.emit`), la console web un canale
//! `tokio::sync::broadcast` consumato da SSE. Il produttore (il refresh CVE in
//! background) non deve sapere chi lo ascolta: da qui l'astrazione `Bus`.

use std::sync::Arc;

use serde_json::Value;

pub trait Emitter: Send + Sync {
    fn emit(&self, event: &str, payload: Value);
}

/// Clonabile: ogni thread di background ne tiene una copia.
#[derive(Clone)]
pub struct Bus(Arc<dyn Emitter>);

impl Bus {
    pub fn new(e: impl Emitter + 'static) -> Self {
        Self(Arc::new(e))
    }

    pub fn emit(&self, event: &str, payload: Value) {
        self.0.emit(event, payload);
    }
}

/// Trasporto desktop: eventi Tauri.
pub struct TauriEmitter(pub tauri::AppHandle);

impl Emitter for TauriEmitter {
    fn emit(&self, event: &str, payload: Value) {
        use tauri::Emitter;
        let _ = self.0.emit(event, payload);
    }
}

/// Bus muto: per i test e per le chiamate senza un'interfaccia collegata.
pub struct NullEmitter;

impl Emitter for NullEmitter {
    fn emit(&self, _event: &str, _payload: Value) {}
}
