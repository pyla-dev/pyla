//! Profili pubblici di PYLA: il repository GitHub `pyla-dev/pyla-profiles`.
//!
//! Ogni profilo vive in `profiles/<id>/profile.jsonc` (con un README accanto). Qui si
//! elencano i profili e se ne scarica uno; il contenuto finisce nella textarea
//! dell'import, quindi l'utente lo vede (e lo puo' correggere) prima di importarlo.
//!
//! Il frontend passa solo l'`id` del profilo, mai un URL o un path: l'indirizzo lo
//! compone il backend, cosi' l'app scarica soltanto da questo repository.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cve::UA;

pub const REPO: &str = "pyla-dev/pyla-profiles";
const BRANCH: &str = "main";
const MAX_BYTES: u64 = 2 * 1024 * 1024; // stesso limite dell'import da file

#[derive(Serialize, Debug, PartialEq, Default)]
pub struct Profile {
    pub id: String,
    pub size: u64,
    /// Dal README del profilo (`# Titolo`, `**Target**:`, `**Risk level**:`); vuoti se
    /// il README non c'e' o non si legge: la riga resta comunque sceglibile per id.
    pub name: String,
    pub target: String,
    pub risk: String,
}

#[derive(Deserialize)]
struct Tree {
    tree: Vec<TreeItem>,
}

#[derive(Deserialize)]
struct TreeItem {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    size: u64,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .user_agent(UA)
        .build()
        .into()
}

/// Un id valido e' il nome di una cartella di `profiles/`: minuscole, cifre e trattini.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Dall'albero del repository tiene solo `profiles/<id>/profile.jsonc`, ordinati per id.
fn profiles_in(items: Vec<TreeItem>) -> Vec<Profile> {
    let mut out: Vec<Profile> = items
        .into_iter()
        .filter(|t| t.kind == "blob" && t.size <= MAX_BYTES)
        .filter_map(|t| {
            let id = t
                .path
                .strip_prefix("profiles/")?
                .strip_suffix("/profile.jsonc")?;
            valid_id(id).then(|| Profile {
                id: id.to_string(),
                size: t.size,
                ..Default::default()
            })
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Intestazione del README di un profilo:
///
/// ```text
/// # Silent stealth
///
/// **Target**: machines that should offer nothing ... (anche su piu' righe)
/// **PYLA tested**: 0.2.6 · **Risk level**: hard
/// ```
fn readme_header(md: &str) -> (String, String, String) {
    let name = md
        .lines()
        .find_map(|l| l.strip_prefix("# "))
        .unwrap_or_default()
        .trim()
        .to_string();
    // Target: dal marcatore fino alla prossima riga che apre un altro campo "**...**"
    // o a una riga vuota; le righe a capo del Markdown si ricompongono con uno spazio.
    let mut target = Vec::new();
    let mut inside = false;
    for l in md.lines() {
        let l = l.trim();
        if let Some(rest) = l.strip_prefix("**Target**:") {
            inside = true;
            target.push(rest.trim());
        } else if inside {
            if l.is_empty() || l.starts_with("**") || l.starts_with('#') {
                break;
            }
            target.push(l);
        }
    }
    let risk = md
        .lines()
        .find_map(|l| l.split_once("**Risk level**:").map(|(_, r)| r.trim()))
        .unwrap_or_default()
        .to_string();
    (name, target.join(" "), risk)
}

pub fn list() -> Result<Vec<Profile>, String> {
    let url = format!("https://api.github.com/repos/{REPO}/git/trees/{BRANCH}?recursive=1");
    let tree: Tree = agent()
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("github.com: {e}"))?
        .body_mut()
        .with_config()
        .limit(4 << 20)
        .read_json()
        .map_err(|e| format!("risposta di github.com non valida: {e}"))?;
    let mut profiles = profiles_in(tree.tree);
    // un README per profilo, in parallelo: sono pochi file piccoli e la UI aspetta
    let agent = agent();
    std::thread::scope(|sc| {
        for p in profiles.iter_mut() {
            let agent = &agent;
            sc.spawn(move || {
                let url = format!(
                    "https://raw.githubusercontent.com/{REPO}/{BRANCH}/profiles/{}/README.md",
                    p.id
                );
                if let Ok(md) = agent
                    .get(&url)
                    .call()
                    .and_then(|mut r| r.body_mut().with_config().limit(256 << 10).read_to_string())
                {
                    (p.name, p.target, p.risk) = readme_header(&md);
                }
            });
        }
    });
    Ok(profiles)
}

pub fn read(id: &str) -> Result<String, String> {
    if !valid_id(id) {
        return Err(format!("profilo non valido: {id}"));
    }
    let url =
        format!("https://raw.githubusercontent.com/{REPO}/{BRANCH}/profiles/{id}/profile.jsonc");
    agent()
        .get(&url)
        .call()
        .map_err(|e| format!("github.com: {e}"))?
        .body_mut()
        .with_config()
        .limit(MAX_BYTES)
        .read_to_string()
        .map_err(|e| format!("risposta di github.com non valida: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(path: &str, kind: &str, size: u64) -> TreeItem {
        TreeItem {
            path: path.into(),
            kind: kind.into(),
            size,
        }
    }

    #[test]
    fn only_profile_files_are_listed() {
        let got = profiles_in(vec![
            item("profiles/stealth/profile.jsonc", "blob", 6999),
            item("profiles/stealth/README.md", "blob", 10),
            item("profiles/home-server/profile.jsonc", "blob", 3540),
            item("profiles/home-server", "tree", 0),
            item("schema/profile.schema.json", "blob", 1),
            item("profiles/a/b/profile.jsonc", "blob", 1),
            item("profiles/../profile.jsonc", "blob", 1),
            item("profiles/huge/profile.jsonc", "blob", MAX_BYTES + 1),
        ]);
        let ids: Vec<&str> = got.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["home-server", "stealth"]);
    }

    #[test]
    fn ids_cannot_escape_the_repository() {
        for bad in ["", "../x", "a/b", "A", "-x", "x?y", "x y", "%2e%2e"] {
            assert!(!valid_id(bad), "{bad:?} non deve passare");
        }
        assert!(valid_id("workstation-laptop"));
        assert!(read("../../etc").is_err());
    }

    #[test]
    fn readme_header_is_parsed() {
        let md = "# Silent stealth\n\n**Target**: machines that offer nothing — laptops\non untrusted networks.\n**PYLA tested**: 0.2.6 · **Risk level**: hard\n\n## What it does\n";
        let (name, target, risk) = readme_header(md);
        assert_eq!(name, "Silent stealth");
        assert_eq!(
            target,
            "machines that offer nothing — laptops on untrusted networks."
        );
        assert_eq!(risk, "hard");
        assert_eq!(
            readme_header("niente"),
            (String::new(), String::new(), String::new())
        );
    }

    /// Rete reale: `cargo test -p pyla -- --ignored`.
    #[test]
    #[ignore]
    fn live_repository_has_profiles() {
        let got = list().unwrap();
        assert!(!got.is_empty());
        for p in &got {
            assert!(
                !p.name.is_empty() && !p.target.is_empty() && !p.risk.is_empty(),
                "{p:?}"
            );
            let text = read(&p.id).unwrap();
            let parsed = pyla_core::import::parse(&text, &p.id);
            assert!(parsed.is_ok(), "{}: {:?}", p.id, parsed.err());
        }
    }
}
