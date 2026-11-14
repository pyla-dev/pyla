//! Report dei servizi in ascolto — l'equivalente della scheda «Report» di Gufw.
//!
//! Elenca i socket TCP in stato LISTEN e i socket UDP non connessi (quelli che
//! ricevono datagrammi da chiunque) leggendo `/proc/net/{tcp,tcp6,udp,udp6}`,
//! poi risale al processo che li possiede seguendo i link `socket:[inode]` in
//! `/proc/<pid>/fd`. Non esegue `ss` né `netstat`: niente processi esterni.
//!
//! Senza privilegi `/proc/<pid>/fd` è leggibile solo per i propri processi, quindi
//! i servizi di sistema restano senza nome; letto dall'helper (root) l'elenco è
//! completo. In entrambi i casi l'utente proprietario del socket è noto, perché
//! l'uid sta già in `/proc/net/*`.

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;

use crate::exposure::parse_addr;

/// Un socket in ascolto con il processo che lo possiede, se visibile.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Socket {
    /// "tcp" | "udp"
    pub proto: &'static str,
    pub family: u8,
    pub addr: String,
    pub port: u16,
    /// "locale" | "tutte" | "link-local" | "indirizzo" (come in `exposure`)
    pub scope: &'static str,
    pub uid: u32,
    pub user: Option<String>,
    pub inode: u64,
    pub pid: Option<u32>,
    pub process: Option<String>,
    /// Riga di comando (argv separati da spazi), troncata a 300 caratteri.
    pub cmdline: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub sockets: Vec<Socket>,
    /// true se i processi sono stati cercati con privilegi di root (elenco completo).
    pub privileged: bool,
    /// Socket di cui non si è trovato il processo (altri utenti, senza root).
    pub unresolved: usize,
}

/// Legge i socket in ascolto e prova ad associarli ai processi.
pub fn report(root: &Path, privileged: bool) -> Report {
    let mut sockets = sockets(root);
    attach_processes(root, &mut sockets);
    let users = passwd(root);
    for s in &mut sockets {
        s.user = users.get(&s.uid).cloned();
    }
    let unresolved = sockets.iter().filter(|s| s.process.is_none()).count();
    Report {
        sockets,
        privileged,
        unresolved,
    }
}

/// Socket TCP in LISTEN e UDP non connessi, ordinati per protocollo, porta, indirizzo.
pub fn sockets(root: &Path) -> Vec<Socket> {
    let mut out = Vec::new();
    for (rel, proto, fam) in [
        ("proc/net/tcp", "tcp", 4u8),
        ("proc/net/tcp6", "tcp", 6),
        ("proc/net/udp", "udp", 4),
        ("proc/net/udp6", "udp", 6),
    ] {
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            continue;
        };
        for line in text.lines().skip(1) {
            if let Some(s) = parse_line(line, proto, fam) {
                out.push(s);
            }
        }
    }
    out.sort_by(|a, b| {
        (a.proto, a.port, a.family, &a.addr).cmp(&(b.proto, b.port, b.family, &b.addr))
    });
    // stessa porta e indirizzo con SO_REUSEPORT: una riga sola (vince l'inode più basso)
    out.dedup_by(|b, a| {
        a.proto == b.proto && a.family == b.family && a.addr == b.addr && a.port == b.port
    });
    out
}

fn parse_line(line: &str, proto: &'static str, fam: u8) -> Option<Socket> {
    // sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode ...
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 10 {
        return None;
    }
    let st = f[3];
    let listening = match proto {
        "tcp" => st == "0A",
        // UDP: 07 = TCP_CLOSE, cioè non connesso; il remoto tutto a zero lo conferma
        _ => st == "07" && f[2].split(':').all(|p| p.chars().all(|c| c == '0')),
    };
    if !listening {
        return None;
    }
    let (hex, p) = f[1].split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    if port == 0 {
        return None;
    }
    let (addr, scope) = parse_addr(hex, fam)?;
    Some(Socket {
        proto,
        family: fam,
        addr,
        port,
        scope,
        uid: f[7].parse().ok()?,
        user: None,
        inode: f[9].parse().ok()?,
        pid: None,
        process: None,
        cmdline: None,
    })
}

/// Associa gli inode ai processi tramite `/proc/<pid>/fd/*` -> `socket:[inode]`.
/// I processi non leggibili (altri utenti senza root) vengono saltati in silenzio.
pub fn attach_processes(root: &Path, sockets: &mut [Socket]) {
    if sockets.is_empty() {
        return;
    }
    let wanted: HashMap<u64, usize> = sockets
        .iter()
        .enumerate()
        .map(|(i, s)| (s.inode, i))
        .collect();
    let Ok(dir) = std::fs::read_dir(root.join("proc")) else {
        return;
    };
    let mut pids: Vec<u32> = dir
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable(); // il pid più basso è di solito il processo padre del servizio
    let mut left = wanted.len();
    for pid in pids {
        let fd_dir = root.join(format!("proc/{pid}/fd"));
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let Some(inode) = target
                .to_str()
                .and_then(|t| t.strip_prefix("socket:["))
                .and_then(|t| t.strip_suffix(']'))
                .and_then(|t| t.parse::<u64>().ok())
            else {
                continue;
            };
            let Some(&i) = wanted.get(&inode) else {
                continue;
            };
            let s = &mut sockets[i];
            if s.pid.is_some() {
                continue;
            }
            s.pid = Some(pid);
            s.process = std::fs::read_to_string(root.join(format!("proc/{pid}/comm")))
                .ok()
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty());
            s.cmdline = std::fs::read(root.join(format!("proc/{pid}/cmdline")))
                .ok()
                .map(|b| {
                    let s: String = String::from_utf8_lossy(&b)
                        .split('\0')
                        .filter(|a| !a.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ");
                    s.chars().take(300).collect()
                })
                .filter(|c: &String| !c.is_empty());
            left -= 1;
            if left == 0 {
                return;
            }
        }
    }
}

/// uid -> nome da `/etc/passwd` (solo utenti locali; LDAP/sssd restano senza nome).
fn passwd(root: &Path) -> HashMap<u32, String> {
    std::fs::read_to_string(root.join("etc/passwd"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let uid = f.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0 100 0 0 10 0
   2: 0F02000A:D3C2 0101A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1003 1 0 20 4 30 10 -1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1004 1 0 100 0 0 10 0
";
    const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  10: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   104        0 1005 2 0000000000000000 0
  11: 0F02000A:A1B2 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 1006 2 0000000000000000 0
  12: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 1007 2 0000000000000000 0
";

    fn fake_root(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("pyla-listening-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("proc/net")).unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("proc/net/tcp"), TCP).unwrap();
        fs::write(root.join("proc/net/tcp6"), TCP6).unwrap();
        fs::write(root.join("proc/net/udp"), UDP).unwrap();
        fs::write(
            root.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\navahi:x:104:110::/run/avahi:/usr/sbin/nologin\n",
        )
        .unwrap();
        // sshd (pid 800) possiede i due socket della 22, cupsd (pid 42) quello di 631;
        // il socket UDP di avahi resta senza processo (come senza root)
        for (pid, comm, cmd, inodes) in [
            (
                800u32,
                "sshd",
                "sshd: /usr/sbin/sshd -D",
                vec![1002u64, 1004],
            ),
            (42, "cupsd", "/usr/sbin/cupsd\0-l", vec![1001]),
            (900, "bash", "bash", vec![]),
        ] {
            let d = root.join(format!("proc/{pid}"));
            fs::create_dir_all(d.join("fd")).unwrap();
            fs::write(d.join("comm"), format!("{comm}\n")).unwrap();
            fs::write(d.join("cmdline"), format!("{cmd}\0")).unwrap();
            fs::write(d.join("fd/0"), "").unwrap(); // file normale, non un link
            for (n, ino) in inodes.iter().enumerate() {
                std::os::unix::fs::symlink(
                    format!("socket:[{ino}]"),
                    d.join(format!("fd/{}", n + 3)),
                )
                .unwrap();
            }
        }
        root
    }

    #[test]
    fn only_listening_tcp_and_unconnected_udp() {
        let root = fake_root("filter");
        let s = sockets(&root);
        let keys: Vec<_> = s
            .iter()
            .map(|s| (s.proto, s.family, s.addr.as_str(), s.port))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("tcp", 4, "0.0.0.0", 22),
                ("tcp", 6, "::", 22),
                ("tcp", 4, "127.0.0.1", 631),
                ("udp", 4, "0.0.0.0", 5353),
            ],
            "esclusi: tcp ESTABLISHED, udp connesso, udp con porta 0"
        );
        assert_eq!(s[2].scope, "locale");
        assert_eq!(s[0].scope, "tutte");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn processes_users_and_unresolved() {
        let root = fake_root("procs");
        let r = report(&root, false);
        let by_port = |p: u16, f: u8| {
            r.sockets
                .iter()
                .find(|s| s.port == p && s.family == f)
                .unwrap()
        };
        assert_eq!(by_port(22, 4).process.as_deref(), Some("sshd"));
        assert_eq!(by_port(22, 6).pid, Some(800));
        assert_eq!(by_port(631, 4).process.as_deref(), Some("cupsd"));
        assert_eq!(
            by_port(631, 4).cmdline.as_deref(),
            Some("/usr/sbin/cupsd -l")
        );
        assert_eq!(by_port(22, 4).user.as_deref(), Some("root"));
        let mdns = by_port(5353, 4);
        assert_eq!(
            (mdns.process.as_deref(), mdns.user.as_deref()),
            (None, Some("avahi"))
        );
        assert_eq!(r.unresolved, 1);
        assert!(!r.privileged);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn missing_proc_is_empty_not_error() {
        let r = report(Path::new("/nonexistent-pyla-root"), false);
        assert!(r.sockets.is_empty());
        assert_eq!(r.unresolved, 0);
    }

    #[test]
    fn live_proc_does_not_panic() {
        // sulla macchina vera: deve solo funzionare, il contenuto varia
        let r = report(Path::new("/"), false);
        assert!(r.sockets.iter().all(|s| s.port != 0));
    }
}
