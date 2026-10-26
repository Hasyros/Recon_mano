"""Phase 4b : helpers purs (aucun réseau, aucun outil) des modules jsluice, secrets,
takeover, naabu et arjun.

Tout ce qui se teste sans lancer de binaire est ici : lecture de l'index des réponses
stockées par katana, extraction du corps des JS, résolution des endpoints jsluice,
masquage des secrets, sélection des candidats takeover, analyse des sorties naabu /
subzy / arjun. Les appels d'outils et les modules eux-mêmes sont dans `modules.py`.

Formats vérifiés dans le code amont (pas supposés) :

- katana `-store-response -store-response-dir D` : un fichier par réponse,
  `D/<hôte, « : » remplacé par « _ »>/<sha1 de l'URL>.txt`, contenu = `URL`, trois sauts de
  ligne, la requête brute, deux sauts de ligne, la réponse brute (en-têtes + corps) ;
  `D/index.txt` = une ligne `<chemin du fichier> <URL> (<statut HTTP>)` par réponse
  (ouvert en ajout : on repart d'un dossier vide à chaque run).
- jsluice `urls|secrets` : un objet JSON par ligne, champ `filename` = chemin d'entrée ;
  les chemins d'entrée sont lus sur l'entrée standard (un par ligne) s'il n'y a pas d'argument.
- subzy `--output` : tableau JSON de {subdomain, status, engine, vulnerable, cname…}.
- arjun `-oJ` : objet JSON {url: {params: [...], method, headers}}.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from . import signatures

# --------------------------------------------------------------------------- #
# Réponses stockées par katana
# --------------------------------------------------------------------------- #

INDEX_NAME = "index.txt"
_INDEX_LINE = re.compile(r"^(?P<file>.+?) (?P<url>https?://\S+) \((?P<status>[^)]*)\)\s*$")
_RESPONSE_START = re.compile(r"(?m)^HTTP/\d(?:\.\d)?\s+\d{3}")
_HEADER_SPLIT = re.compile(r"\r?\n\r?\n")
JS_EXT = (".js", ".mjs", ".cjs")


@dataclass(frozen=True)
class StoredResponse:
    file: Path
    url: str
    status: str


def _resolve_stored(store_dir: Path, token: str) -> Optional[Path]:
    """Chemin du fichier tel qu'écrit dans l'index (relatif au dossier de lancement de katana,
    ou absolu), sinon reconstruit depuis `store_dir/<hôte>/<nom>`."""
    path = Path(token)
    for candidate in (path, store_dir / path.parent.name / path.name):
        if candidate.is_file():
            return candidate
    return None


def read_katana_index(store_dir: Path) -> List[StoredResponse]:
    """Réponses listées dans `index.txt` dont le fichier existe, une par URL (la 1re l'emporte)."""
    index = store_dir / INDEX_NAME
    if not index.is_file():
        return []
    seen: set = set()
    found: List[StoredResponse] = []
    for line in index.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _INDEX_LINE.match(line.strip())
        if not match or match["url"] in seen:
            continue
        path = _resolve_stored(store_dir, match["file"])
        if path is None:
            continue
        seen.add(match["url"])
        found.append(StoredResponse(path, match["url"], match["status"]))
    return found


def split_response(text: str) -> Tuple[str, str]:
    """(en-têtes, corps) de la réponse HTTP brute contenue dans un fichier stocké par katana.

    La réponse commence à la 1re ligne `HTTP/x.y NNN`. Sans elle, tout le texte est le corps."""
    start = _RESPONSE_START.search(text)
    if not start:
        return "", text
    response = text[start.start():]
    parts = _HEADER_SPLIT.split(response, maxsplit=1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def header_value(headers: str, name: str) -> str:
    prefix = name.lower() + ":"
    for line in headers.splitlines():
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


def is_javascript(url: str, status: str, headers: str) -> bool:
    """Un JS exploitable : réponse 2xx, URL en .js/.mjs/.cjs ou content-type javascript/ecmascript
    (jamais du HTML, même sous une URL en .js)."""
    if not status.strip().startswith("2"):
        return False
    content_type = header_value(headers, "content-type").lower()
    if "html" in content_type:
        return False
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return False
    return path.endswith(JS_EXT) or "javascript" in content_type or "ecmascript" in content_type


def extract_js_bodies(
    responses: Iterable[StoredResponse], destination: Path, max_bytes: int
) -> Tuple[List[Tuple[Path, str]], int]:
    """Écrit le corps de chaque JS stocké dans `destination/<sha1>.js` (jsluice n'a pas à
    lire les en-têtes ni la requête). Retourne ([(fichier JS, URL source)], nombre ignorés
    car trop gros). Les fichiers dépassant `max_bytes` sont écartés (bundles énormes)."""
    destination.mkdir(parents=True, exist_ok=True)
    extracted: List[Tuple[Path, str]] = []
    too_big = 0
    for response in responses:
        try:
            text = response.file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        headers, body = split_response(text)
        if not body.strip() or not is_javascript(response.url, response.status, headers):
            continue
        if len(body.encode("utf-8", errors="replace")) > max_bytes:
            too_big += 1
            continue
        target = destination / (response.file.stem + ".js")
        target.write_text(body, encoding="utf-8")
        extracted.append((target, response.url))
    return extracted, too_big


def dir_size(path: Path) -> Tuple[int, int]:
    """(nombre de fichiers, octets) sous `path`."""
    files = size = 0
    if path.is_dir():
        for item in path.rglob("*"):
            if item.is_file():
                files += 1
                try:
                    size += item.stat().st_size
                except OSError:
                    pass
    return files, size


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("o", "Ko", "Mo", "Go"):
        if value < 1024 or unit == "Go":
            return f"{value:.0f} {unit}" if unit == "o" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} o"


# --------------------------------------------------------------------------- #
# jsluice
# --------------------------------------------------------------------------- #

PLACEHOLDER = "EXPR"
_BAD_URL_CHARS = re.compile(r"[\s<>{}\\^`|]")


def iter_json_objects(lines: Iterable[str]) -> Iterable[Dict[str, Any]]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            yield row


def resolve_endpoint(raw: str, base: str, placeholder: str = PLACEHOLDER) -> Optional[str]:
    """Endpoint vu dans un JS → URL absolue http(s), ou None si inexploitable.

    Résolu contre l'URL du JS qui le contient (`urljoin` : relatif, absolu, `//cdn…`, `../x`).
    jsluice remplace les expressions dynamiques par `placeholder` : dans l'hôte ou le chemin
    l'URL est inutilisable (écartée) ; dans la requête on met `1`. Fragment retiré."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        full = urljoin(base, raw)
        parts = urlsplit(full)
        hostname = parts.hostname
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not hostname:
        return None
    if placeholder in parts.netloc or placeholder in parts.path or _BAD_URL_CHARS.search(full):
        return None
    query = parts.query.replace(placeholder, "1")
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))


def source_lookup(extracted: Iterable[Tuple[Path, str]]) -> Dict[str, str]:
    """Chemin d'entrée jsluice → URL source (clé = chemin complet et nom de fichier)."""
    lookup: Dict[str, str] = {}
    for path, url in extracted:
        lookup[str(path)] = url
        lookup.setdefault(path.name, url)
    return lookup


def find_source(lookup: Dict[str, str], filename: str) -> str:
    return lookup.get(filename) or lookup.get(Path(filename).name, "")


def parse_jsluice_urls(lines: Iterable[str], lookup: Dict[str, str]) -> List[str]:
    """Sortie `jsluice urls` → endpoints absolus, sans statiques, dédoublonnés (ordre conservé).

    Le périmètre est appliqué par l'appelant (`apply_scope`, étape « jsluice »)."""
    urls: List[str] = []
    for row in iter_json_objects(lines):
        raw = row.get("url")
        if not isinstance(raw, str):
            continue
        base = find_source(lookup, str(row.get("filename") or ""))
        resolved = resolve_endpoint(raw, base)
        if resolved and not signatures.is_static(resolved):
            urls.append(resolved)
    return list(dict.fromkeys(urls))


# --------------------------------------------------------------------------- #
# Secrets : masquage et normalisation
# --------------------------------------------------------------------------- #


def redact(secret: str) -> str:
    """Début du secret + « … » : 4 caractères, moins pour un secret court (jamais le secret entier)."""
    secret = str(secret)
    keep = 4 if len(secret) >= 12 else len(secret) // 4
    return secret[:keep] + "…"


def redact_value(value: Any) -> str:
    """Masque une valeur de secret : chaîne, ou structure jsluice (`{"key": …, "secret": …}`)."""
    if isinstance(value, dict):
        return ", ".join(f"{key}={redact_value(item)}" for key, item in value.items() if item not in (None, ""))
    if isinstance(value, (list, tuple)):
        return ", ".join(redact_value(item) for item in value)
    return redact(str(value))


@dataclass
class SecretFinding:
    detector: str
    source: str            # trufflehog | gitleaks | jsluice
    file: str              # fichier local analysé
    url: str               # URL d'origine (index katana), vide si inconnue
    redacted: str          # jamais le secret entier
    line: Optional[int]
    raw: str               # ligne JSON brute de l'outil (écrite dans 10_secrets.jsonl uniquement)


def url_lookup(responses: Iterable[StoredResponse]) -> Dict[str, str]:
    """Fichier stocké → URL d'origine, sous plusieurs clés (chemin complet, `hôte/nom`, nom sans extension)."""
    lookup: Dict[str, str] = {}
    for response in responses:
        file = response.file
        for key in (str(file), f"{file.parent.name}/{file.name}", file.stem):
            lookup.setdefault(key, response.url)
    return lookup


def find_url(lookup: Dict[str, str], filename: str) -> str:
    if not filename:
        return ""
    path = Path(filename)
    for key in (filename, f"{path.parent.name}/{path.name}", path.stem):
        if key in lookup:
            return lookup[key]
    return ""


def _find_key(node: Any, key: str) -> Any:
    if isinstance(node, dict):
        if key in node:
            return node[key]
        for child in node.values():
            found = _find_key(child, key)
            if found is not None:
                return found
    elif isinstance(node, list):
        for child in node:
            found = _find_key(child, key)
            if found is not None:
                return found
    return None


def parse_trufflehog(lines: Iterable[str], lookup: Dict[str, str]) -> List[SecretFinding]:
    findings: List[SecretFinding] = []
    for line in lines:
        for row in iter_json_objects([line]):
            detector = row.get("DetectorName")
            if not detector:
                continue
            meta = row.get("SourceMetadata") or {}
            filesystem = _find_key(meta, "Filesystem") or meta
            file = str(_find_key(filesystem, "file") or "")
            line_no = _find_key(filesystem, "line")
            secret = row.get("Raw") or row.get("RawV2") or ""
            findings.append(SecretFinding(
                str(detector), "trufflehog", file, find_url(lookup, file), redact(secret),
                line_no if isinstance(line_no, int) else None, json.dumps(row, ensure_ascii=False),
            ))
    return findings


def parse_gitleaks(report: str, lookup: Dict[str, str]) -> List[SecretFinding]:
    """Rapport JSON de gitleaks (`--report-format json` : un tableau)."""
    try:
        rows = json.loads(report) if report.strip() else []
    except json.JSONDecodeError:
        return []
    if not isinstance(rows, list):
        return []
    findings: List[SecretFinding] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        file = str(row.get("File") or "")
        line_no = row.get("StartLine")
        findings.append(SecretFinding(
            str(row.get("RuleID") or row.get("Description") or "gitleaks"), "gitleaks", file,
            find_url(lookup, file), redact(row.get("Secret") or ""),
            line_no if isinstance(line_no, int) else None, json.dumps(row, ensure_ascii=False),
        ))
    return findings


def parse_jsluice_secrets(lines: Iterable[str], lookup: Dict[str, str]) -> List[SecretFinding]:
    findings: List[SecretFinding] = []
    for row in iter_json_objects(lines):
        kind = row.get("kind")
        if not kind:
            continue
        file = str(row.get("filename") or "")
        findings.append(SecretFinding(
            str(kind), "jsluice", file, find_url(lookup, file), redact_value(row.get("data")), None,
            json.dumps(row, ensure_ascii=False),
        ))
    return findings


def summary_line(finding: SecretFinding) -> str:
    """`[détecteur] URL (outil, fichier:ligne) secret masqué` — pas de secret entier."""
    where = Path(finding.file).name if finding.file else "?"
    if finding.line:
        where += f":{finding.line}"
    origin = finding.url or finding.file or "?"
    return f"[{finding.detector}] {origin}  ({finding.source}, {where})  {finding.redacted}"


# --------------------------------------------------------------------------- #
# takeover : CNAME hors périmètre
# --------------------------------------------------------------------------- #


def _clean_name(name: str) -> str:
    return name.strip().strip(".").lower()


def parse_cname_rows(lines: Iterable[str]) -> Dict[str, List[str]]:
    """Sortie `dnsx -cname -resp -json` → {hôte: [CNAME…]} (minuscules, sans point final).

    `cname` est une liste (ou une chaîne selon la version) ; les hôtes sans CNAME sont ignorés."""
    result: Dict[str, List[str]] = {}
    for row in iter_json_objects(lines):
        host = _clean_name(str(row.get("host") or ""))
        raw = row.get("cname")
        names = [raw] if isinstance(raw, str) else [n for n in (raw or []) if isinstance(n, str)]
        cleaned = [c for c in (_clean_name(n) for n in names) if c]
        if host and cleaned:
            result.setdefault(host, [])
            result[host].extend(c for c in cleaned if c not in result[host])
    return result


def _under(host: str, domains: Sequence[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def takeover_candidates(
    cnames: Dict[str, List[str]], apexes: Sequence[str], excludes: Sequence[str] = ()
) -> Dict[str, List[str]]:
    """Hôtes dont au moins un CNAME pointe HORS du périmètre (service tiers : Heroku, S3, GitHub
    Pages…). Un CNAME interne (même apex) n'est pas un candidat ; un CNAME vers une exclusion
    non plus (on ne touche pas à ce qui est exclu). Retourne {hôte: [CNAME externes]}."""
    candidates: Dict[str, List[str]] = {}
    for host, targets in cnames.items():
        external = [t for t in targets if not _under(t, apexes) and not _under(t, excludes)]
        if external:
            candidates[host] = external
    return candidates


def parse_subzy(text: str) -> List[Dict[str, Any]]:
    """Fichier `--output` de subzy : tableau JSON (repli : un objet JSON par ligne)."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return list(iter_json_objects(text.splitlines()))
    if isinstance(data, dict):
        data = [data]
    return [row for row in data if isinstance(row, dict)] if isinstance(data, list) else []


def is_vulnerable(row: Dict[str, Any]) -> bool:
    status = str(row.get("status") or "").strip().lower()
    if status.startswith(("not ", "no ")):
        return False
    return row.get("vulnerable") is True or status == "vulnerable"


def takeover_line(row: Dict[str, Any]) -> str:
    cname = row.get("cname") or []
    target = ", ".join(cname) if isinstance(cname, list) else str(cname)
    engine = row.get("engine") or row.get("service") or "?"
    return f"[{str(row.get('status') or 'vulnerable').upper()}] {row.get('subdomain', '?')} → {target or '?'} ({engine})"


# --------------------------------------------------------------------------- #
# naabu
# --------------------------------------------------------------------------- #

_PORT_LIST = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
MAX_EXPLICIT_PORTS = 5000     # au-delà, c'est un scan complet déguisé
WEB_DEFAULT_PORTS = (80, 443)


def port_flags(spec: str, allow_full: bool = False) -> List[str]:
    """Option `--ports` → arguments naabu. Accepte `top-100`, `top-1000` ou une liste explicite
    (`80,443,8080-8090`). `full` (65535 ports) et les listes équivalentes exigent `allow_full`.
    Lève ValueError sur toute autre valeur."""
    value = spec.strip().lower().replace(" ", "")
    if value in ("top-100", "top-1000"):
        return ["-top-ports", value.split("-")[1]]
    if value in ("full", "-", "all"):
        if not allow_full:
            raise ValueError("--ports full est refusé par défaut (65535 ports par hôte) : ajouter --naabu-allow-full")
        return ["-top-ports", "full"]
    if not _PORT_LIST.match(value):
        raise ValueError("--ports : top-100, top-1000 ou une liste (80,443,8080-8090)")
    total = 0
    for chunk in value.split(","):
        low, _, high = chunk.partition("-")
        first, last = int(low), int(high or low)
        if not (1 <= first <= 65535 and 1 <= last <= 65535 and first <= last):
            raise ValueError(f"--ports : plage invalide « {chunk} » (1-65535)")
        total += last - first + 1
    if total > MAX_EXPLICIT_PORTS and not allow_full:
        raise ValueError(f"--ports : {total} ports ≈ scan complet, refusé par défaut (--naabu-allow-full)")
    return ["-p", value]


def port_count(flags: Sequence[str]) -> int:
    """Nombre de ports par hôte pour des arguments issus de `port_flags` (estimation de durée)."""
    value = flags[1] if len(flags) > 1 else ""
    if flags[:1] == ["-top-ports"]:
        return 65535 if value == "full" else int(value)
    total = 0
    for chunk in value.split(","):
        low, _, high = chunk.partition("-")
        total += int(high or low) - int(low) + 1 if low.isdigit() else 0
    return total


def parse_naabu(lines: Iterable[str]) -> List[Tuple[str, int, str]]:
    """Sortie `naabu -json` → [(hôte, port, ligne JSON)] dédoublonnée. Hôte = `host` (le nom
    scanné), à défaut `ip`. Les lignes sans port valide sont ignorées."""
    seen: set = set()
    found: List[Tuple[str, int, str]] = []
    for line in lines:
        for row in iter_json_objects([line]):
            host = _clean_name(str(row.get("host") or row.get("ip") or ""))
            port = row.get("port")
            if isinstance(port, dict):               # anciennes versions : {"Port": 8080, …}
                port = port.get("Port") or port.get("port")
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            if not host or not 1 <= port <= 65535 or (host, port) in seen:
                continue
            seen.add((host, port))
            found.append((host, port, line.strip()))
    return found


def web_candidates(entries: Iterable[str]) -> List[str]:
    """`host:port` hors 80/443 (déjà couverts par httpx #1), ordre conservé."""
    kept: List[str] = []
    for entry in entries:
        host, _, port = entry.strip().rpartition(":")
        if host and port.isdigit() and int(port) not in WEB_DEFAULT_PORTS:
            kept.append(entry.strip())
    return list(dict.fromkeys(kept))


# --------------------------------------------------------------------------- #
# arjun
# --------------------------------------------------------------------------- #


def pick_arjun_targets(urls: Iterable[str], cap: int) -> List[str]:
    """URLs à confier à arjun : une représentante par signature (statiques exclues), les URLs
    prioritaires (admin, api, upload…) d'abord, plafonnées à `cap` (arjun envoie des centaines
    de requêtes par URL)."""
    reps = signatures.representatives(urls, 1)
    ordered = sorted(reps, key=lambda url: not signatures.is_priority(url))   # tri stable
    return ordered[: max(int(cap), 0)]


def parse_arjun(text: str) -> Dict[str, List[str]]:
    """Fichier `-oJ` d'arjun → {url: [paramètres trouvés]} (URLs sans paramètre omises)."""
    try:
        data = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    found: Dict[str, List[str]] = {}
    for url, info in data.items():
        params = info.get("params") if isinstance(info, dict) else None
        if isinstance(params, dict):                  # variantes : {nom: valeur}
            params = list(params)
        names = [str(p) for p in (params or []) if str(p).strip()]
        if names:
            found[str(url)] = list(dict.fromkeys(names))
    return found


def param_url(url: str, params: Sequence[str], value: str = "1") -> Optional[str]:
    """`https://h/p?a=1` + [b, c] → `https://h/p?a=1&b=1&c=1` : paramètres existants conservés
    tels quels, nouveaux avec une valeur factice ; un paramètre déjà présent n'est pas dupliqué."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    known = {name for name, _ in pairs}
    for name in params:
        if name not in known:
            known.add(name)
            pairs.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(pairs, safe="[]"), ""))


def arjun_param_urls(found: Dict[str, List[str]]) -> List[str]:
    """Une URL par jeu de paramètres découvert (valeurs factices), dédoublonnée."""
    urls = [u for u in (param_url(url, names) for url, names in found.items()) if u]
    return list(dict.fromkeys(urls))
