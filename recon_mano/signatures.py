"""Signatures d'URL : réduire des milliers d'URLs à quelques représentants.

nuclei (passe 2) travaille par URL, et le coût est (URLs × templates). Or un site
sert `/produit/1`, `/produit/2` … `/produit/9000` avec le même code : tester les
9000 n'apprend rien de plus que d'en tester deux. On regroupe donc les URLs par
**signature** (hôte[:port] + chemin « templaté » + noms de paramètres) et on n'en
garde que K par groupe.

Ce module est volontairement pur (aucun réseau). Seule l'intégration optionnelle de
`gf` lance un outil externe, via `runner.run_command`.

Choix de conception :

- **Le schéma est ignoré** : `http://h/x` et `https://h/x` sont la même appli
  (redirection ou miroir) — les tester deux fois double le trafic pour rien. Le
  **port est gardé** (un même hôte sur 8080 et 8443 peut être deux applis), sauf le
  port par défaut du schéma (`:443` en https, `:80` en http), retiré.
- **Seuls les noms de paramètres comptent**, jamais leurs valeurs : `?id=1` et
  `?id=2` sont la même surface ; `?id` et `?id&sort` sont deux surfaces.
- **Priorité par segment, pas par sous-chaîne** : « api » en sous-chaîne matcherait
  `/capital-markets` ou `/rapide`. On découpe le chemin en mots (`/`, `-`, `_`, `.`)
  et on compare mot à mot (voir `is_priority`).
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

from . import runner
from .io_utils import read_lines
from .report import ASSET_EXT

# Ressources statiques : rien à y trouver pour nuclei. On étend la liste de l'arbre
# HTML (images, CSS, JS, polices, médias, pdf) sans la modifier pour lui.
STATIC_EXT = frozenset(ASSET_EXT) | {
    "zip", "tar", "gz", "tgz", "bz2", "xz", "rar", "7z",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp",
    "tif", "tiff", "mov", "avi", "mkv", "ogg", "flac", "m4a",
}

DEFAULT_PORTS = {"http": 80, "https": 443}

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DATE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$")
_NUMBER = re.compile(r"^\d+$")
_HASH = re.compile(r"^[0-9a-fA-F]{16,}$")  # md5 (32), sha1 (40), sha256 (64)…
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{24,}$")

# Mots du chemin qui signalent une surface sensible (voir is_priority).
PRIORITY_KEYWORDS = (
    "admin", "api", "upload", "config", "debug",
    "graphql", "swagger", "actuator", "internal", "backup",
)

# Repli sans gf : paramètres dont le nom évoque une redirection, un fichier, une
# requête ou une commande — les classiques de XSS / SQLi / SSRF / LFI / open redirect.
SUSPICIOUS_PARAMS = frozenset({
    "id", "url", "uri", "redirect", "redirect_url", "redirect_uri", "redirecturl", "next",
    "file", "filename", "path", "page", "q", "search", "cmd", "command", "exec", "query",
    "callback", "return", "return_url", "returnurl", "dest", "destination", "template",
    "include", "src", "domain", "host", "dir", "folder", "doc", "document", "load",
    "view", "feed", "target", "goto", "continue", "data", "lang",
})

# Motifs gf interrogés quand l'outil est présent.
GF_PATTERNS = ("xss", "sqli", "ssrf", "redirect", "lfi", "rce", "idor")


# --------------------------------------------------------------------------- #
# Signature
# --------------------------------------------------------------------------- #


def host_port(url: str) -> str:
    """`hôte[:port]` en minuscules, port par défaut du schéma retiré. "" si inexploitable.

    Accepte aussi un `hôte` ou `hôte:port` sans schéma (champ `input` de httpx).
    """
    raw = url.strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw if "://" in raw else "//" + raw)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return ""
    if not host:
        return ""
    if port is not None and DEFAULT_PORTS.get(parts.scheme.lower()) == port:
        port = None
    if ":" in host:  # IPv6 littérale
        host = f"[{host}]"
    return f"{host}:{port}" if port is not None else host


def template_segment(segment: str) -> str:
    """Remplace un segment de chemin « variable » par un jeton stable.

    Ordre : uuid, date ISO, nombre, hash hexadécimal ≥ 16, puis jeton aléatoire
    (≥ 24 caractères mêlant lettres et chiffres). Un slug en minuscules
    (`mon-super-article-2024-edition`) n'est PAS un jeton : il porte du sens.
    """
    if _UUID.match(segment):
        return "{uuid}"
    if _DATE.match(segment):
        return "{date}"
    if _NUMBER.match(segment):
        return "{n}"
    if _HASH.match(segment):
        return "{hash}"
    if _TOKEN.match(segment):
        has_letter = any(c.isalpha() for c in segment)
        has_digit = any(c.isdigit() for c in segment)
        slug = segment == segment.lower() and ("-" in segment or "_" in segment)
        if has_letter and has_digit and not slug:
            return "{tok}"
    return segment


def _path_segments(path: str) -> List[str]:
    return [segment for segment in path.split("/") if segment]


def param_names(url: str) -> List[str]:
    """Noms de paramètres de requête, uniques et triés (valeurs ignorées)."""
    try:
        query = urlsplit(url.strip()).query
    except ValueError:
        return []
    return sorted({name for name, _ in parse_qsl(query, keep_blank_values=True) if name})


def signature(url: str) -> str:
    """`hôte[:port]/chemin/{n}/…[?a&b]` — deux URLs de même signature sont la même surface."""
    url = url.strip()
    host = host_port(url)
    if not host:
        return url.lower()
    try:
        path = urlsplit(url).path
    except ValueError:
        path = ""
    templated = "/".join(template_segment(s) for s in _path_segments(path))
    sig = f"{host}/{templated}"
    names = param_names(url)
    if names:
        sig += "?" + "&".join(names)
    return sig


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def is_static(url: str) -> bool:
    """Image, CSS, JS, police, média, archive, pdf/bureautique : à ne pas scanner."""
    try:
        path = urlsplit(url.strip()).path
    except ValueError:
        return False
    leaf = path.rsplit("/", 1)[-1]
    if "." not in leaf:
        return False
    return leaf.rsplit(".", 1)[1].lower() in STATIC_EXT


def representatives(urls: Iterable[str], k: int = 2) -> List[str]:
    """Les K premières URLs de chaque signature, ordre d'entrée conservé, statiques exclues."""
    k = max(int(k), 1)
    seen: Dict[str, int] = {}
    kept: List[str] = []
    for url in dict.fromkeys(u.strip() for u in urls if u.strip()):
        if is_static(url):
            continue
        sig = signature(url)
        if seen.get(sig, 0) < k:
            seen[sig] = seen.get(sig, 0) + 1
            kept.append(url)
    return kept


def has_params(url: str) -> bool:
    return bool(param_names(url))


def _keyword_hit(word: str, keyword: str) -> bool:
    if word == keyword or word == keyword + "s":
        return True
    if keyword == "api":
        return re.fullmatch(r"apiv?\d+", word) is not None  # api2, apiv2
    # Mots longs : `administrator`, `configuration`, `uploader`… — assez longs pour
    # que le préfixe ne soit pas ambigu. Les courts (« api ») restent exacts.
    return len(keyword) >= 5 and word.startswith(keyword)


def is_priority(url: str) -> bool:
    """Le chemin contient un mot sensible (admin, api, upload, config, debug, graphql,
    swagger, actuator, internal, backup).

    Le chemin est découpé en mots sur tout caractère non alphanumérique, et chaque
    mot est comparé au mot-clé (égalité, pluriel, ou préfixe pour les mots-clés de
    ≥ 5 lettres). Une simple sous-chaîne ferait matcher `/capital`, `/rapide` ou
    `/debugging-tips-blog` au même titre que `/api/` : trop de faux positifs, donc
    trop de requêtes inutiles. Seul le chemin est regardé (ni l'hôte, ni la requête).
    """
    try:
        path = urlsplit(url.strip()).path.lower()
    except ValueError:
        return False
    words = [w for w in re.split(r"[^a-z0-9]+", path) if w]
    return any(_keyword_hit(word, keyword) for word in words for keyword in PRIORITY_KEYWORDS)


def has_suspicious_param(url: str) -> bool:
    return any(name.lower() in SUSPICIOUS_PARAMS for name in param_names(url))


# --------------------------------------------------------------------------- #
# Liste prioritaire (gf optionnel)
# --------------------------------------------------------------------------- #

Log = Callable[[Optional[str]], None]


def gf_matches(
    candidate: Path,
    workdir: Path,
    log: Log = lambda message: None,
    timeout: int = 120,
) -> Optional[Dict[str, List[str]]]:
    """Passe `candidate` dans `gf <motif>` pour chaque motif de GF_PATTERNS.

    Retourne {motif: [urls]} ou None si gf est absent. Un motif non installé
    (~/.gf/<motif>.json manquant) est simplement ignoré : on interroge d'abord
    `gf -list` ; si la liste est vide on tente quand même tous les motifs.
    """
    binary = shutil.which("gf")
    if not binary:
        return None
    workdir.mkdir(parents=True, exist_ok=True)
    listing = workdir / ".gf_list.tmp"
    try:
        runner.run_command([binary, "-list"], "gf", stdout_to=listing, timeout=30, silent=False)
        installed = set(read_lines(listing))
    finally:
        listing.unlink(missing_ok=True)
    patterns = [p for p in GF_PATTERNS if p in installed] if installed else list(GF_PATTERNS)

    candidates = set(read_lines(candidate))
    found: Dict[str, List[str]] = {}
    for pattern in patterns:
        out = workdir / f".gf_{pattern}.tmp"
        try:
            runner.run_command(
                [binary, pattern], f"gf {pattern}", stdout_to=out, stdin_from=candidate,
                timeout=timeout, silent=False,
            )
            hits = [u for u in read_lines(out) if u in candidates]
        finally:
            out.unlink(missing_ok=True)
        if hits:
            found[pattern] = hits
    log(f"  [dim]gf : {', '.join(f'{p} {len(h)}' for p, h in found.items()) or 'aucun match'}[/dim]")
    return found


def select_priority(
    urls: Sequence[str],
    candidate: Path,
    workdir: Path,
    log: Log = lambda message: None,
) -> Tuple[List[str], str]:
    """URLs prioritaires parmi `urls` (déjà écrites dans `candidate`) + la méthode utilisée.

    - mots sensibles dans le chemin (`is_priority`), toujours ;
    - avec gf : les URLs que gf classe xss/sqli/ssrf/redirect/lfi/rce/idor ;
    - sans gf : repli sur une liste interne de noms de paramètres suspects.
    """
    gf = gf_matches(candidate, workdir, log)
    if gf is None:
        method = "mots sensibles + paramètres suspects (gf absent)"
        picked = [u for u in urls if is_priority(u) or has_suspicious_param(u)]
    else:
        method = "mots sensibles + gf"
        gf_hits = {u for hits in gf.values() for u in hits}
        picked = [u for u in urls if is_priority(u) or u in gf_hits]
    return picked, method
