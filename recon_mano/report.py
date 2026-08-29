"""Génère un arbre HTML interactif (plan déroulant) depuis une liste d'URLs.

Groupe par hôte puis par hiérarchie de chemins, sépare pages / assets, et flague
les endpoints à fort intérêt (admin, api, .php, params…). Sortie autonome : un
seul fichier .html, sans dépendance externe, à ouvrir dans un navigateur.

Usage direct :  python -m recon_mano.report urls_200_final.txt [sortie.html]
"""

from __future__ import annotations

import html
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlsplit

# Extensions considérées comme du "bruit" statique (masquables d'un clic).
ASSET_EXT = {
    "css", "js", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp",
    "avif", "woff", "woff2", "ttf", "eot", "otf", "mp4", "webm", "mp3", "wav", "pdf",
}

# Mots-clés à fort signal en recon → badge "!".
HOT_KW = [
    "admin", "login", "logout", "signin", "/api", "api/", "graphql", "swagger",
    "actuator", "upload", "config", ".env", ".git", "backup", ".bak", ".sql",
    ".zip", ".tar", "debug", "phpinfo", "token", "oauth", "password", "passwd",
    "secret", "dashboard", "staging", "internal", "private", ".php", ".asp",
    ".aspx", ".jsp", ".do", ".action", ".yml", ".yaml", ".log", ".json",
]

Node = Dict[str, object]  # {"dirs": {name: Node}, "files": [(label, url, asset, hot)]}


def _new_node() -> Node:
    return {"dirs": {}, "files": []}


def _classify(url: str, path: str) -> Tuple[bool, bool]:
    segment = path.rsplit("/", 1)[-1]
    ext = segment.rsplit(".", 1)[1].lower() if "." in segment else ""
    asset = ext in ASSET_EXT
    low = url.lower()
    hot = (not asset) and any(kw in low for kw in HOT_KW)
    return asset, hot


def build_tree(urls: List[str]) -> Dict[str, Node]:
    tree: Dict[str, Node] = {}
    for url in urls:
        parts = urlsplit(url)
        host = parts.netloc or "(sans hôte)"
        node = tree.setdefault(host, _new_node())
        segments = [s for s in parts.path.split("/") if s]
        for seg in segments[:-1]:
            node = node["dirs"].setdefault(seg, _new_node())  # type: ignore[union-attr]
        leaf = segments[-1] if segments else "/"
        label = leaf + ("?" + parts.query if parts.query else "")
        asset, hot = _classify(url, parts.path)
        node["files"].append((label, url, asset, hot))  # type: ignore[union-attr]
    return tree


def _count(node: Node) -> int:
    return len(node["files"]) + sum(_count(c) for c in node["dirs"].values())  # type: ignore[union-attr,arg-type]


def _render(node: Node) -> str:
    out: List[str] = []
    for name in sorted(node["dirs"]):  # type: ignore[call-overload]
        child = node["dirs"][name]  # type: ignore[index]
        out.append(
            f'<details><summary>{html.escape(name)}'
            f'<span class="c">{_count(child)}</span></summary>'
        )
        out.append(_render(child))
        out.append("</details>")
    for label, url, asset, hot in sorted(node["files"], key=lambda x: x[0].lower()):  # type: ignore[union-attr]
        cls = "leaf" + (" asset" if asset else "") + (" hot" if hot else "")
        badges = ('<i class="bp">?</i>' if "?" in label else "") + ('<i class="bh">!</i>' if hot else "")
        out.append(
            f'<a class="{cls}" href="{html.escape(url)}" target="_blank" rel="noopener" '
            f'data-u="{html.escape(url.lower())}">{html.escape(label)}{badges}</a>'
        )
    return "".join(out)


def _extract_url(line: str) -> str:
    """1er token d'une ligne s'il ressemble à une URL — gère aussi les fichiers
    annotés `url [200] [titre]…` en plus des listes propres."""
    line = line.strip()
    if not line:
        return ""
    token = line.split()[0]
    return token if token.startswith(("http://", "https://")) else ""


def build_html(urls: List[str], title: str) -> str:
    urls = list(dict.fromkeys(u for u in (_extract_url(x) for x in urls) if u))
    tree = build_tree(urls)
    hosts = sorted(tree, key=lambda h: (-_count(tree[h]), h))
    body: List[str] = []
    for host in hosts:
        body.append(
            f'<details open class="host"><summary>{html.escape(host)}'
            f'<span class="c">{_count(tree[host])}</span></summary>'
        )
        body.append(_render(tree[host]))
        body.append("</details>")
    return (
        _PAGE.replace("%%TITLE%%", html.escape(title))
        .replace("%%TOTAL%%", str(len(urls)))
        .replace("%%HOSTS%%", str(len(hosts)))
        .replace("%%TREE%%", "".join(body))
    )


def write_report(url_file: Path, html_file: Path, title: str) -> int:
    urls = [l.strip() for l in url_file.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    html_file.write_text(build_html(urls, title), encoding="utf-8")
    return len(dict.fromkeys(urls))


_PAGE = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%%TITLE%% — arbre des URLs</title>
<style>
:root{
  --bg:#fbfbfc; --fg:#1c2024; --dim:#8b929b; --line:#e4e6ea; --panel:#fff;
  --link:#2563eb; --hot:#b45309; --hotbg:#fef3c7; --param:#7c3aed; --hover:#f1f3f5;
}
@media (prefers-color-scheme:dark){
  :root{--bg:#0e1116;--fg:#d7dbe0;--dim:#6b7280;--line:#232a33;--panel:#141920;
        --link:#6ea8fe;--hot:#f0b429;--hotbg:#3a2f12;--param:#c4a7ff;--hover:#1a2029;}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{position:sticky;top:0;z-index:5;background:var(--panel);border-bottom:1px solid var(--line);
  padding:12px 16px;display:flex;flex-wrap:wrap;gap:10px 14px;align-items:center}
h1{font-size:15px;margin:0;font-weight:600}
h1 small{color:var(--dim);font-weight:400;margin-left:8px}
#q{flex:1;min-width:180px;padding:7px 10px;border:1px solid var(--line);border-radius:8px;
  background:var(--bg);color:var(--fg);font-size:13px}
.btn{padding:6px 11px;border:1px solid var(--line);border-radius:8px;background:var(--bg);
  color:var(--fg);cursor:pointer;font-size:13px}
.btn:hover{background:var(--hover)}
label.tg{display:inline-flex;align-items:center;gap:6px;color:var(--dim);font-size:13px;cursor:pointer;user-select:none}
#count{color:var(--dim);font-size:12px;font-variant-numeric:tabular-nums}
main{padding:10px 16px 60px}
details{border-left:1px solid var(--line);margin-left:9px;padding-left:11px}
details.host{border-left:0;margin-left:0;padding-left:0;margin-top:8px}
summary{cursor:pointer;padding:3px 6px;border-radius:6px;list-style-position:inside}
summary:hover{background:var(--hover)}
.host>summary{font-weight:600;font-size:14px}
.c{color:var(--dim);font-size:11px;margin-left:8px;font-variant-numeric:tabular-nums}
a.leaf{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:12.5px;color:var(--link);text-decoration:none;padding:2px 6px 2px 22px;border-radius:5px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
a.leaf:hover{background:var(--hover);text-decoration:underline}
a.asset{color:var(--dim)}
a.hot{border-left:2px solid var(--hot);padding-left:20px}
i.bp,i.bh{font-style:normal;font-size:10px;font-weight:700;margin-left:6px;padding:0 5px;border-radius:6px;vertical-align:middle}
i.bp{color:var(--param);border:1px solid var(--param)}
i.bh{color:var(--hot);background:var(--hotbg);border:1px solid var(--hot)}
.hide-assets a.asset{display:none}
[hidden]{display:none !important}
</style>
</head>
<body>
<header>
  <h1>%%TITLE%%<small>%%TOTAL%% URLs · %%HOSTS%% hôtes</small></h1>
  <input id="q" type="search" placeholder="filtrer (ex: admin, .php, api, login)…" autocomplete="off">
  <label class="tg"><input type="checkbox" id="ha"> masquer les assets (css/js/img)</label>
  <button class="btn" id="ex">tout déplier</button>
  <button class="btn" id="co">tout replier</button>
  <span id="count"></span>
</header>
<main>%%TREE%%</main>
<script>
const q=document.getElementById('q'),ha=document.getElementById('ha'),cnt=document.getElementById('count');
const leaves=[...document.querySelectorAll('a.leaf')],dets=[...document.querySelectorAll('details')];
function refresh(){
  const s=q.value.trim().toLowerCase();
  document.body.classList.toggle('hide-assets',ha.checked);
  let shown=0;
  for(const a of leaves){
    let vis=!(ha.checked&&a.classList.contains('asset'));
    if(vis&&s&&!a.dataset.u.includes(s))vis=false;
    a.style.display=vis?'':'none';
    if(vis)shown++;
  }
  for(const d of dets){
    const any=[...d.querySelectorAll('a.leaf')].some(a=>a.style.display!=='none');
    d.hidden=!any;
    if(s&&any)d.open=true;
  }
  cnt.textContent=shown+' / '+leaves.length+' affichées';
}
q.addEventListener('input',refresh);
ha.addEventListener('change',refresh);
document.getElementById('ex').onclick=()=>dets.forEach(d=>d.open=true);
document.getElementById('co').onclick=()=>dets.forEach(d=>{if(!d.classList.contains('host'))d.open=false});
refresh();
</script>
</body>
</html>"""


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage : python -m recon_mano.report <fichier_urls> [sortie.html]")
        raise SystemExit(2)
    src = Path(sys.argv[1])
    dest = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_suffix(".html")
    n = write_report(src, dest, src.stem)
    print(f"{n} URLs -> {dest}")


if __name__ == "__main__":
    main()
