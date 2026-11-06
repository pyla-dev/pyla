//! Confronto tra le regole presenti in UFW e quelle di un set, e piano dei
//! comandi per passare dalle une alle altre.
//!
//! In UFW l'ordine conta (vince la prima regola che corrisponde) e gli
//! inserimenti per posizione sono scomodi con IPv4/IPv6 misti, quindi quando
//! qualcosa cambia il piano è sempre: cancella tutte le regole utente, poi
//! aggiungile nell'ordine voluto. Le connessioni già aperte non cadono perché
//! UFW accetta `established,related` prima delle regole utente.

use serde::{Deserialize, Serialize};

use crate::model::{RuleSpec, ValidationError};
use crate::ufw::{delete_args, rule_args, UfwStatus};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    /// Regole desiderate, validate e normalizzate.
    pub desired: Vec<RuleSpec>,
    /// Già allineato: nessun comando da eseguire.
    pub in_sync: bool,
    /// Regole presenti in UFW che il set non contiene.
    pub removed: Vec<RuleSpec>,
    /// Regole del set che non sono in UFW.
    pub added: Vec<RuleSpec>,
    /// Stesse regole ma in ordine diverso.
    pub reordered: bool,
    /// Regole che PYLA non sa gestire: il piano non è applicabile finché ci sono.
    pub unsupported: Vec<String>,
    /// Argomenti `ufw`, nell'ordine di esecuzione.
    pub commands: Vec<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum PlanError {
    #[error("regola {index}: {source}")]
    Invalid {
        index: usize,
        source: ValidationError,
    },
    #[error("le regole {first} e {second} sono uguali (UFW salterebbe la seconda)")]
    Duplicate { first: usize, second: usize },
    #[error("lo stato reale non contiene le regole (serve root)")]
    NoLiveRules,
}

/// Valida le regole desiderate (numerate da 1 negli errori).
pub fn validate_all(desired: &[RuleSpec]) -> Result<Vec<RuleSpec>, PlanError> {
    let mut out: Vec<RuleSpec> = Vec::with_capacity(desired.len());
    for (i, r) in desired.iter().enumerate() {
        let n = r.normalized().map_err(|source| PlanError::Invalid {
            index: i + 1,
            source,
        })?;
        if let Some(j) = out.iter().position(|o| o.match_key() == n.match_key()) {
            return Err(PlanError::Duplicate {
                first: j + 1,
                second: i + 1,
            });
        }
        out.push(n);
    }
    Ok(out)
}

pub fn plan(live: &UfwStatus, desired: &[RuleSpec]) -> Result<Plan, PlanError> {
    if live.rules.is_none() {
        return Err(PlanError::NoLiveRules);
    }
    let desired = validate_all(desired)?;
    let current = live.specs();
    let unsupported: Vec<String> = live.unsupported().iter().map(|r| r.raw.clone()).collect();

    let removed: Vec<RuleSpec> = current
        .iter()
        .filter(|c| !desired.contains(c))
        .cloned()
        .collect();
    let added: Vec<RuleSpec> = desired
        .iter()
        .filter(|d| !current.contains(d))
        .cloned()
        .collect();
    let in_sync = current == desired && unsupported.is_empty();
    let reordered = !in_sync && removed.is_empty() && added.is_empty() && unsupported.is_empty();

    let commands = if in_sync {
        Vec::new()
    } else {
        current
            .iter()
            .map(delete_args)
            .chain(desired.iter().map(rule_args))
            .collect()
    };

    Ok(Plan {
        desired,
        in_sync,
        removed,
        added,
        reordered,
        unsupported,
        commands,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ufw::merge_rules;

    fn live(v4: &str) -> UfwStatus {
        UfwStatus {
            rules: Some(merge_rules(v4, "")),
            ..Default::default()
        }
    }

    const LIVE: &str = "\
### tuple ### allow tcp 22 0.0.0.0/0 any 192.0.2.9 in
### tuple ### allow any any 0.0.0.0/0 any 192.0.2.6 in
";

    #[test]
    fn in_sync_means_no_commands() {
        let st = live(LIVE);
        let p = plan(&st, &st.specs()).unwrap();
        assert!(p.in_sync);
        assert!(p.commands.is_empty());
    }

    #[test]
    fn change_rewrites_everything_in_order() {
        let st = live(LIVE);
        let mut want = st.specs();
        want.remove(1);
        want[0].comment = Some("workstation".into());
        let p = plan(&st, &want).unwrap();
        assert!(!p.in_sync);
        assert_eq!(p.removed.len(), 2); // il commento cambiato conta come regola diversa
        assert_eq!(p.added.len(), 1);
        assert_eq!(p.commands.len(), 3);
        assert_eq!(p.commands[0][0], "delete");
        assert_eq!(p.commands[2].last().unwrap(), "workstation");
    }

    #[test]
    fn detects_reorder_and_duplicates() {
        let st = live(LIVE);
        let mut want = st.specs();
        want.reverse();
        assert!(plan(&st, &want).unwrap().reordered);

        let dup = vec![
            want[0].clone(),
            RuleSpec {
                comment: Some("x".into()),
                ..want[0].clone()
            },
        ];
        assert!(matches!(
            plan(&st, &dup),
            Err(PlanError::Duplicate {
                first: 1,
                second: 2
            })
        ));
    }

    #[test]
    fn unsupported_rules_block_sync() {
        let st =
            live("### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1\n");
        let p = plan(&st, &[]).unwrap();
        assert!(!p.in_sync);
        assert_eq!(p.unsupported.len(), 1);
    }
}
