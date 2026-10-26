"""Périmètre strict (scope) : une seule fonction fait foi, `in_scope`.

Règle : l'hôte doit être égal à un apex ou en être un sous-domaine (suffixe
`.apex`), et ne pas être égal à / sous-domaine d'une exclusion. Jamais de
`contains` : `evilexample.com` et `example.com.evil.net` ne matchent PAS
`example.com`.

`ScopeFilter` applique cette règle aux sorties de chaque étape et journalise
les rejets dans un TSV (`rejected_scope.tsv`) pour garder la trace de ce qui a
été écarté.
"""

from __future__ import annotations

import re
import threading
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse

from .io_utils import read_lines, write_lines

# Séparateurs de chemin/requête/fragment pour un `host[:port]/chemin` sans schéma.
_PATH_SPLIT = re.compile(r"[/?#]")
# Hôte plausible : lettres, chiffres, `_`, `.`, `-` (et `:` pour l'IPv6). Écarte les
# astuces du type `evil.com\@example.com` que les navigateurs lisent autrement.
_HOST_OK = re.compile(r"^[\w.\-:]+$")

Domains = Union[str, Sequence[str]]


# --------------------------------------------------------------------------- #
# Extraction / normalisation
# --------------------------------------------------------------------------- #


def host_of(url: str) -> str:
    """Hostname d'une URL ou d'un `host[:port]`, sans port ni userinfo, en minuscules.

    Seul le 1er token (séparé par des espaces) compte : une ligne annotée
    `url [200] [titre]` marche donc telle quelle. Chaîne vide si rien d'exploitable.
    """
    tokens = url.split()
    if not tokens:
        return ""
    raw = tokens[0]
    if "://" in raw:
        try:
            netloc = urlparse(raw).netloc
        except ValueError:  # ex. IPv6 mal fermée
            return ""
    else:
        netloc = _PATH_SPLIT.split(raw, 1)[0]
    if "\\" in netloc:  # ambigu (les navigateurs lisent \ comme /) → on refuse
        return ""
    netloc = netloc.rsplit("@", 1)[-1]  # retire un éventuel user:pass@
    if netloc.startswith("["):          # IPv6 littérale [::1]:8080
        host = netloc[1:].split("]", 1)[0]
    else:
        host = netloc.split(":", 1)[0]  # retire le port
    host = host.strip().strip(".").lower()
    return host if _HOST_OK.match(host) else ""


def _normalize_domain(domain: str) -> str:
    """`*.Exemple.COM.` → `exemple.com` (accepte aussi une URL complète)."""
    domain = domain.strip().lower()
    if "://" in domain:
        domain = host_of(domain)
    while domain.startswith("*."):
        domain = domain[2:]
    return domain.strip(".")


def parse_domains(spec: str) -> List[str]:
    """Liste de domaines séparés par des virgules/espaces → liste propre.

    Retire `*.` et les points de bord, met en minuscules, dédoublonne en gardant l'ordre.
    """
    domains = (_normalize_domain(part) for part in re.split(r"[,\s]+", spec or ""))
    return list(dict.fromkeys(d for d in domains if d))


def _as_domains(value: Domains) -> List[str]:
    """Accepte une chaîne (éventuellement virgulée) ou une séquence de domaines."""
    if isinstance(value, str):
        return parse_domains(value)
    return list(dict.fromkeys(d for d in (_normalize_domain(v) for v in value) if d))


# --------------------------------------------------------------------------- #
# Règle de périmètre
# --------------------------------------------------------------------------- #


def _is_or_under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _host_in_scope(host: str, apexes: Sequence[str], excludes: Sequence[str]) -> bool:
    """Cœur de la règle, sur des listes DÉJÀ normalisées (évite de renormaliser par ligne)."""
    if not host:
        return False
    if not any(_is_or_under(host, apex) for apex in apexes):
        return False
    return not any(_is_or_under(host, ex) for ex in excludes)


def in_scope(host_or_url: str, apexes: Domains, excludes: Domains = ()) -> bool:
    """True si l'hôte est un apex (ou son sous-domaine) et n'est pas exclu."""
    return _host_in_scope(host_of(host_or_url), _as_domains(apexes), _as_domains(excludes))


def scope_urls(lines: Sequence[str], apexes: Domains, excludes: Domains = ()) -> List[str]:
    apex_list, exclude_list = _as_domains(apexes), _as_domains(excludes)
    return [line for line in lines if _host_in_scope(host_of(line), apex_list, exclude_list)]


# --------------------------------------------------------------------------- #
# Filtre appliqué après chaque étape
# --------------------------------------------------------------------------- #


class ScopeFilter:
    """Écarte tout ce qui sort du périmètre et en garde la trace.

    - `filter(lines, stage)` : lignes en scope (hôtes nus, URLs, ou lignes annotées
      `url [200] …` dont seul le 1er token décide ; la ligne est gardée entière).
    - `filter_file(path, stage)` : idem, en réécrivant le fichier sur place.
    - Les rejets sont ajoutés au TSV `stage<TAB>hôte<TAB>ligne` et comptés par étape
      dans `self.rejected`.
    - `enabled=False` (--no-scope-filter) : rien n'est filtré ni journalisé.

    Le journal est remis à zéro à la création (un run = un journal) ; en mode
    désactivé, un journal périmé d'un run précédent est supprimé. `reset_log=False`
    (rejeu `merge`) conserve le journal existant et y ajoute.

    Utilisable depuis plusieurs threads (modules en parallèle) : comptage et
    journal sont protégés par un verrou.
    """

    def __init__(
        self,
        apexes: Domains,
        excludes: Domains = (),
        reject_log: Optional[Path] = None,
        enabled: bool = True,
        reset_log: bool = True,
    ) -> None:
        self.apexes = _as_domains(apexes)
        self.excludes = _as_domains(excludes)
        self.reject_log = reject_log
        self.enabled = enabled
        self.rejected: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        if reset_log:
            self._reset_log()

    def _reset_log(self) -> None:
        if self.reject_log is None:
            return
        try:
            if self.enabled:
                self.reject_log.write_text("", encoding="utf-8")
            else:
                self.reject_log.unlink(missing_ok=True)
        except OSError:
            pass

    @property
    def total_rejected(self) -> int:
        return sum(self.rejected.values())

    def _log(self, stage: str, rejects: Iterable[Tuple[str, str]]) -> None:
        if self.reject_log is None:
            return
        rows = [
            f"{stage}\t{host}\t{line.strip().replace(chr(9), ' ')}\n"
            for host, line in rejects
        ]
        if not rows:
            return
        try:
            with self.reject_log.open("a", encoding="utf-8") as handle:
                handle.writelines(rows)
        except OSError:
            pass

    def filter(self, lines: Iterable[str], stage: str) -> List[str]:
        if not self.enabled:
            return list(lines)
        kept: List[str] = []
        rejects: List[Tuple[str, str]] = []
        for line in lines:
            if not line.strip():
                continue  # ligne vide : ni gardée, ni comptée comme rejet
            host = host_of(line)
            if _host_in_scope(host, self.apexes, self.excludes):
                kept.append(line)
            else:
                rejects.append((host, line))
        if rejects:
            with self._lock:
                self.rejected[stage] += len(rejects)
                self._log(stage, rejects)
        return kept

    def filter_file(self, path: Path, stage: str) -> Tuple[int, int]:
        """Réécrit `path` avec les seules lignes en scope. Retourne (gardées, rejetées)."""
        if not path.exists():
            return 0, 0
        lines = read_lines(path)
        if not self.enabled:
            return len(lines), 0
        kept = self.filter(lines, stage)
        rejected = len(lines) - len(kept)
        return write_lines(path, kept), rejected
