//! Nucleo di PYLA: modello delle regole, validazione, traduzione in argomenti
//! `ufw`, lettura dello stato di UFW e confronto tra stato reale e desiderato.
//!
//! Non esegue nulla: lo usano sia l'app (senza privilegi) sia `pyla-helper`
//! (avviato come root tramite pkexec).

pub mod exposure;
pub mod mitigation;
pub mod model;
pub mod nft;
pub mod plan;
pub mod ufw;

pub use model::{Action, Direction, LogLevel, Proto, RuleSpec, ValidationError};
pub use plan::{plan, Plan};
pub use ufw::{LiveRule, UfwStatus};

/// Percorso fisso dell'helper privilegiato (deve coincidere con la policy polkit).
pub const HELPER_PATH: &str = "/usr/local/libexec/pyla/pyla-helper";
