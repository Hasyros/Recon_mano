"""`recon_mano merge <dossier>` : rejoue la fusion finale depuis les fichiers déjà
sur disque, sans lancer aucun outil.

Utile après avoir ajouté une exclusion au périmètre, édité une liste à la main ou
relancé un seul module : on reconstruit la carte (`all_urls.txt`), les listes
`*_final` (depuis le JSONL httpx) et l'arbre HTML avec le périmètre voulu.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Tuple

from .io_utils import count_lines
from .liveness import DEFAULT_LIVE_CODES, parse_codes, split_httpx_output
from .modules import Log, apply_scope, merge_files
from .pipeline import build_paths, load_run_config
from .report import write_report as write_tree_report
from .scope import ScopeFilter, host_of, parse_domains
from .ui import console

MERGE_STAGE = "merge"  # nom d'étape dans rejected_scope.tsv


@dataclass
class MergeResult:
    target: str
    scope_apexes: List[str]
    scope_excludes: List[str]
    scope_enabled: bool
    live_codes: Set[int]
    rebuilt: List[Tuple[str, int]] = field(default_factory=list)  # (fichier, nombre de lignes)
    notes: List[str] = field(default_factory=list)
    from_config: bool = False


def _live_codes(raw: object) -> Set[int]:
    try:
        if isinstance(raw, str):
            return parse_codes(raw)
        if isinstance(raw, (list, tuple)):
            return {int(code) for code in raw}
    except (TypeError, ValueError):
        pass
    return parse_codes(DEFAULT_LIVE_CODES)


def _forget_previous_merge(log_file: Path) -> None:
    """Retire du journal les rejets d'un `merge` précédent (les autres étapes restent)."""
    if not log_file.exists():
        return
    kept = [
        line for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        if not line.startswith(MERGE_STAGE + "\t")
    ]
    log_file.write_text("".join(kept), encoding="utf-8")


def merge_folder(folder: Path, log: Log = console.print) -> MergeResult:
    paths = build_paths(folder)
    config = load_run_config(folder)
    notes: List[str] = []

    if config:
        target = str(config.get("target") or folder.resolve().name)
        scope_cfg = config.get("scope") if isinstance(config.get("scope"), dict) else {}
        apexes = parse_domains(",".join(scope_cfg.get("apexes") or [])) or [host_of(target) or target]
        excludes = parse_domains(",".join(scope_cfg.get("excludes") or []))
        scope_enabled = bool(scope_cfg.get("enabled", True))
        live_codes = _live_codes(config.get("live_codes"))
    else:
        # Pas de run_config.json (ancien scan) : le dossier porte en général le nom de la cible.
        target = folder.resolve().name
        apexes = parse_domains(target)
        excludes = []
        scope_enabled = bool(apexes) and "." in apexes[0]
        live_codes = parse_codes(DEFAULT_LIVE_CODES)
        notes.append(
            f"run_config.json absent — périmètre déduit du nom du dossier ({', '.join(apexes)})"
            if scope_enabled
            else "run_config.json absent et nom de dossier sans domaine — filtre de périmètre désactivé"
        )

    result = MergeResult(target, apexes, excludes, scope_enabled, live_codes, notes=notes, from_config=bool(config))

    if scope_enabled:
        _forget_previous_merge(paths["rejected_scope"])
    scope_filter = ScopeFilter(apexes, excludes, paths["rejected_scope"], enabled=scope_enabled, reset_log=False)

    # 1. Carte : seeds vivantes + crawl katana (repli historique : entrées brutes
    #    fusionnées si httpx n'a jamais tourné), puis périmètre strict.
    seeds: Optional[Path] = paths["urls_live"] if paths["urls_live"].exists() else None
    if seeds is None and not paths["httpx_jsonl"].exists() and paths["httpx_input"].exists():
        seeds = paths["httpx_input"]
    sources = [p for p in (seeds, paths["katana"]) if p is not None and p.exists()]
    if sources:
        merge_files(sources, paths["all_urls"])
        total = apply_scope(scope_filter, paths["all_urls"], MERGE_STAGE, log)
        result.rebuilt.append((paths["all_urls"].name, total))
    else:
        notes.append(f"aucune entrée pour {paths['all_urls'].name} ({paths['urls_live'].name} / {paths['katana'].name} absents)")

    # 2. Listes finales depuis le JSONL httpx le plus à jour.
    jsonl = next((p for p in (paths["httpx2_jsonl"], paths["httpx_jsonl"]) if p.exists()), None)
    if jsonl is None:
        notes.append("aucun JSONL httpx — listes *_final non reconstruites")
    else:
        if jsonl is paths["httpx_jsonl"]:
            notes.append(f"{paths['httpx2_jsonl'].name} absent — listes *_final reconstruites depuis {jsonl.name}")
        split_httpx_output(
            jsonl, paths["urls_all_final"], paths["urls_200_final"], paths["urls_live_final"], live_codes
        )
        for key in ("urls_all_final", "urls_200_final", "urls_live_final"):
            kept = apply_scope(scope_filter, paths[key], MERGE_STAGE, log)
            result.rebuilt.append((paths[key].name, kept))

    # 3. Arbre HTML des 200.
    live_200 = paths["urls_200_final"]
    if live_200.exists() and count_lines(live_200):
        count = write_tree_report(live_200, paths["tree_html"], f"{target} · 200")
        result.rebuilt.append((paths["tree_html"].name, count))
    else:
        notes.append("pas de liste de 200 — arbre HTML non reconstruit")

    if scope_filter.total_rejected:
        notes.append(f"{scope_filter.total_rejected} entrées hors périmètre écartées → {paths['rejected_scope'].name}")
    return result
