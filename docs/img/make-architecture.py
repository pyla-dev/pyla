#!/usr/bin/env python3
"""Generate the README architecture diagram (light and dark SVG).

Usage: python3 docs/img/make-architecture.py   (writes architecture-light.svg / architecture-dark.svg
next to this script). Edit the layout or the palettes here, never the SVG files by hand.
"""
from pathlib import Path
from xml.sax.saxutils import escape

W, H = 1000, 600
FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

PALETTES = {
    "light": dict(
        bg="#ffffff", text="#1f2328", muted="#59636e", line="#59636e",
        zone="#f6f8fa", zone_stroke="#d1d9e0",
        box="#ffffff", box_stroke="#d1d9e0",
        app="#fff6e8", app_stroke="#d98a1c", accent="#b8690b",
        root="#fff5f4", root_stroke="#d1242f", root_text="#b3141f",
        net="#f2f7ff", net_stroke="#3b82c4", net_text="#1f5f99",
        badge="#0d1626", badge_text="#ffb95c",
    ),
    "dark": dict(
        bg="#0d1117", text="#e6edf3", muted="#9198a1", line="#9198a1",
        zone="#151b23", zone_stroke="#3d444d",
        box="#0d1117", box_stroke="#3d444d",
        app="#241a0c", app_stroke="#ffb95c", accent="#ffb95c",
        root="#1f1214", root_stroke="#f85149", root_text="#ff7b72",
        net="#0f1a2a", net_stroke="#4493f8", net_text="#79b8ff",
        badge="#ffb95c", badge_text="#0d1626",
    ),
}


def text(x, y, s, size=13, weight=400, fill="text", anchor="start", mono=False, p=None):
    fam = MONO if mono else FONT
    return (f'<text x="{x}" y="{y}" font-family="{fam}" font-size="{size}" font-weight="{weight}" '
            f'fill="{p[fill]}" text-anchor="{anchor}">{escape(s)}</text>')


def rect(x, y, w, h, fill, stroke, p, rx=10, dash=None, sw=1.2):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{p[fill]}" '
            f'stroke="{p[stroke]}" stroke-width="{sw}"{d}/>')


def zone(x, y, w, h, title, sub, fill, stroke, title_fill, p, dash=None):
    return "\n".join([
        rect(x, y, w, h, fill, stroke, p, rx=14, dash=dash, sw=1.4),
        text(x + 18, y + 28, title.upper(), 11.5, 700, title_fill, p=p),
        text(x + 18, y + 46, sub, 12, 400, "muted", p=p),
    ])


def box(x, y, w, h, title, lines, p, fill="box", stroke="box_stroke", title_fill="text", mono_lines=False):
    out = [rect(x, y, w, h, fill, stroke, p), text(x + 16, y + 28, title, 15, 650, title_fill, p=p)]
    for i, ln in enumerate(lines):
        out.append(text(x + 16, y + 50 + i * 19, ln, 12.5, 400, "muted", mono=mono_lines, p=p))
    return "\n".join(out)


def arrow(points, p, label=None, lx=0, ly=0, anchor="middle", dash=None):
    d = " ".join(f"{'M' if i == 0 else 'L'}{x},{y}" for i, (x, y) in enumerate(points))
    da = f' stroke-dasharray="{dash}"' if dash else ""
    out = [f'<path d="{d}" fill="none" stroke="{p["line"]}" stroke-width="1.6"{da} marker-end="url(#arr)"/>']
    if label:
        out.append(text(lx, ly, label, 12, 500, "muted", anchor, p=p))
    return "\n".join(out)


def render(p):
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
         f'role="img" aria-labelledby="t d">',
         '<title id="t">PYLA architecture</title>',
         '<desc id="d">The PYLA desktop app runs as the user with a local SQLite database, reads the Ubuntu '
         'Security API and the public profiles over HTTPS, and performs privileged actions only through '
         'pyla-helper, started via pkexec and authorised by polkit.</desc>',
         f'<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
         f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{p["line"]}"/></marker></defs>',
         f'<rect width="{W}" height="{H}" fill="{p["bg"]}"/>']

    # zones
    s.append(zone(24, 24, 452, 552, "User session", "runs as the logged-in user, no privileges",
                  "zone", "zone_stroke", "muted", p))
    s.append(zone(524, 24, 452, 170, "Internet", "HTTPS, read-only",
                  "net", "net_stroke", "net_text", p, dash="5 4"))
    s.append(zone(524, 226, 452, 350, "Root", "only through polkit (auth_admin_keep)",
                  "root", "root_stroke", "root_text", p, dash="5 4"))

    # user session
    s.append(box(52, 96, 396, 190, "PYLA desktop app", [
        "Tauri 2 shell, Rust backend",
        "UI: HTML, CSS, JavaScript (no framework, strict CSP)",
        "pyla-core: rule model, validation, apply planner,",
        "UFW and nftables parsers, JSONC import,",
        "CVE classifier, mitigation registry",
        "Italian and English interface",
    ], p, fill="app", stroke="app_stroke", title_fill="accent"))
    s.append(box(52, 376, 396, 170, "Local database (SQLite)", [
        "rule sets and per-rule state",
        "apply history with before/after snapshots",
        "settings, followed CVEs, CVE cache (6 h)",
        "~/.local/share/space.pyla.app/pyla.db",
    ], p))
    s.append(arrow([(250, 286), (250, 370)], p, "read / write", 262, 332, "start"))

    # internet
    s.append(box(546, 82, 200, 92, "Ubuntu Security API", ["ubuntu.com/security", "kernel CVEs, fixed versions"], p,
                 fill="box", stroke="net_stroke"))
    s.append(box(756, 82, 200, 92, "Public profiles", ["github.com/pyla-dev/", "pyla-profiles (fixed source)"], p,
                 fill="box", stroke="net_stroke"))
    s.append(arrow([(448, 140), (538, 140)], p, "HTTPS", 493, 130))

    # root
    s.append(box(546, 290, 410, 112, "pyla-helper", [
        "/usr/local/libexec/pyla/pyla-helper",
        "JSON in / JSON out, size-limited requests",
        "allow-listed commands, absolute paths, no shell",
    ], p, fill="box", stroke="root_stroke", title_fill="root_text"))
    targets = [
        (546, "UFW", ["/usr/sbin/ufw", "rules, backups"]),
        (686, "nftables", ["/usr/sbin/nft", "ruleset (read)"]),
        (826, "Kernel", ["sysctl, modprobe", "/proc sockets"]),
    ]
    for x, t, ln in targets:
        s.append(box(x, 456, 130, 92, t, ln, p))
        s.append(arrow([(x + 65, 402), (x + 65, 450)], p))

    # privileged call
    s.append(arrow([(448, 250), (500, 250), (500, 346), (540, 346)], p))
    s.append(f'<rect x="460" y="282" width="80" height="44" rx="8" fill="{p["badge"]}"/>')
    s.append(text(500, 300, "pkexec", 12.5, 700, "badge_text", "middle", p=p))
    s.append(text(500, 317, "polkit", 12, 500, "badge_text", "middle", p=p))

    s.append("</svg>")
    return "\n".join(s) + "\n"


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    for name, pal in PALETTES.items():
        (here / f"architecture-{name}.svg").write_text(render(pal), encoding="utf-8")
        print(f"architecture-{name}.svg")
