"""Filtre de « vivacité » : quelles URLs méritent katana / nuclei.

`--match-codes` (httpx -mc) reste large (500/502/503 compris) pour le triage
manuel. Mais un 404 ou un 502 n'est pas une cible : katana n'a rien à crawler,
nuclei y perdrait des requêtes. On extrait donc de la sortie httpx une liste
« live » restreinte à `--live-codes`.

httpx n'écrit jamais les timeouts / connexions refusées : ils sont absents de la
sortie, donc forcément absents de la liste live.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from .io_utils import count_lines, read_lines, write_lines
from .signatures import host_port

# Codes qui prouvent qu'un endpoint répond pour de bon : 200, redirections, et
# 401/403 (protégé = existe). 404 et 5xx en sont volontairement exclus.
DEFAULT_LIVE_CODES = "200,301,302,307,308,401,403"


def parse_codes(spec: str) -> Set[int]:
    """`"200, 301 403"` → {200, 301, 403}. Lève ValueError sur un token non numérique."""
    codes: Set[int] = set()
    for token in spec.replace(",", " ").split():
        codes.add(int(token))
    return codes


def iter_httpx_rows(lines: Iterable[str]) -> Iterator[Dict[str, Any]]:
    """Lignes JSONL httpx → dicts. Les lignes cassées ou non-objets sont ignorées."""
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            yield row


def filter_live(rows: Iterable[Dict[str, Any]], live_codes: Set[int]) -> List[str]:
    """URLs nues (dédupliquées, ordre conservé) dont le code HTTP est dans `live_codes`."""
    live: List[str] = []
    for row in rows:
        url = row.get("url") or row.get("input")
        if url and row.get("status_code") in live_codes:
            live.append(url)
    return list(dict.fromkeys(live))


def protected_hosts(jsonl_file: Path) -> Dict[str, str]:
    """Hôtes derrière un WAF / CDN d'après la sortie httpx lancée avec `-cdn`.

    httpx ajoute `cdn` (bool), `cdn_name` et `cdn_type` (« cdn », « waf », « cloud »…) à
    chaque ligne. Un simple hébergement cloud (`cdn_type: cloud`) n'est pas un filtre
    en frontal : on ne le compte pas. `cdn: true` sans `cdn_type` (ancien httpx) est
    traité comme protégé — dans le doute on ralentit. Clé = `hôte[:port]` normalisé
    (`signatures.host_port`), valeur = libellé lisible (« cloudflare (waf) »).
    """
    protected: Dict[str, str] = {}
    for row in iter_httpx_rows(read_lines(jsonl_file)):
        if not row.get("cdn"):
            continue
        kind = str(row.get("cdn_type") or "").lower()
        if kind == "cloud":
            continue
        key = host_port(str(row.get("url") or row.get("input") or ""))
        if not key:
            continue
        name = str(row.get("cdn_name") or "cdn")
        protected.setdefault(key, f"{name} ({kind})" if kind else name)
    return protected


def row_keys(row: Dict[str, Any]) -> List[str]:
    """Les clés sous lesquelles une ligne httpx « connaît » une URL : `url` et `input`."""
    return [str(value) for value in (row.get("url"), row.get("input")) if value]


def seen_urls(rows: Iterable[Dict[str, Any]]) -> Set[str]:
    """Toutes les URLs (champs `url` et `input`) déjà passées par httpx."""
    seen: Set[str] = set()
    for row in rows:
        seen.update(row_keys(row))
    return seen


def union_rows(
    first: Iterable[Dict[str, Any]],
    second: Iterable[Dict[str, Any]],
    only: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Lignes httpx #1 puis #2 fusionnées, une par URL (la plus récente l'emporte).

    `only` restreint les lignes de la passe #1 à celles qui concernent une URL de cet
    ensemble (la carte) : httpx #1 a aussi testé des hôtes morts ou hors carte, qui ne
    doivent pas apparaître dans les listes finales. Les lignes de #2 sont toutes gardées
    (elles ne portent que ce qui a été envoyé à httpx #2). L'ordre est celui de première
    apparition.
    """
    merged: Dict[str, Dict[str, Any]] = {}
    for row in first:
        if only is not None and not any(key in only for key in row_keys(row)):
            continue
        url = row.get("url") or row.get("input")
        if url:
            merged[str(url)] = row
    for row in second:
        url = row.get("url") or row.get("input")
        if url:
            merged[str(url)] = row
    return list(merged.values())


def split_httpx_rows(
    rows: List[Dict[str, Any]],
    all_file: Path,
    ok_file: Path,
    live_file: Optional[Path] = None,
    live_codes: Optional[Set[int]] = None,
) -> Tuple[int, int, int]:
    """Éclate des lignes httpx déjà lues. Retourne (total, alive_200, live).

    - all_file  : une ligne annotée par résultat (`url [code] [taille] [titre] [tech]`)
    - ok_file   : URLs nues en 200 uniquement
    - live_file : URLs nues dont le code est dans `live_codes` (défaut DEFAULT_LIVE_CODES)
    """
    if live_codes is None:
        live_codes = parse_codes(DEFAULT_LIVE_CODES)

    annotated: List[str] = []
    alive: List[str] = []
    for row in rows:
        url = row.get("url") or row.get("input")
        if not url:
            continue
        status = row.get("status_code")
        parts = [url, f"[{status if status is not None else '-'}]"]
        if row.get("content_length") is not None:
            parts.append(f"[{row['content_length']}]")
        title = (row.get("title") or "").replace("\n", " ").strip()
        if title:
            parts.append(f"[{title}]")
        tech = row.get("tech") or []
        if tech:
            parts.append(f"[{','.join(tech)}]")
        annotated.append(" ".join(parts))
        if status == 200:
            alive.append(url)

    live = filter_live(rows, live_codes)
    live_count = write_lines(live_file, live) if live_file is not None else len(live)
    return write_lines(all_file, annotated), write_lines(ok_file, alive), live_count


def split_httpx_output(
    jsonl_file: Path,
    all_file: Path,
    ok_file: Path,
    live_file: Optional[Path] = None,
    live_codes: Optional[Set[int]] = None,
) -> Tuple[int, int, int]:
    """Éclate la sortie JSONL de httpx (voir `split_httpx_rows`)."""
    rows = list(iter_httpx_rows(read_lines(jsonl_file)))
    return split_httpx_rows(rows, all_file, ok_file, live_file, live_codes)


def clean_live_urls(urls_all_file: Path, fallback_file: Path) -> List[str]:
    """URLs vivantes propres. urls_all.txt est annoté (`url [code] [titre]…`) :
    on ne garde que le 1er token (l'URL). Repli sur la carte finale si absent."""
    if urls_all_file.exists() and count_lines(urls_all_file):
        raw = [line.split()[0] for line in read_lines(urls_all_file)]
    else:
        raw = read_lines(fallback_file)
    return [u for u in raw if u.startswith(("http://", "https://"))]
