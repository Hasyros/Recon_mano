"""Résultats nuclei : JSONL des deux passes → vue lisible `nuclei.txt` + décompte.

Chaque passe écrit son JSONL (`nuclei_pass1.jsonl`, `nuclei_pass2.jsonl`) ; c'est la
source de vérité. `nuclei.txt` n'en est qu'une vue pour l'œil : une ligne par
finding, `[sévérité] template-id URL`, triée de la plus grave à la moins grave.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from .io_utils import read_lines, write_lines

# Du plus grave au moins grave ; toute autre valeur est rangée en « unknown ».
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")

Finding = Tuple[str, str, str]  # (sévérité, template-id, cible touchée)


def part_path(destination: Path, index: int) -> Path:
    """Fichier temporaire d'un lot (`nuclei_pass1.jsonl.1.part`), fusionné puis supprimé."""
    return destination.with_name(f"{destination.name}.{index}.part")


def valid_json_lines(path: Path) -> List[str]:
    """Lignes du fichier qui sont des objets JSON complets (une sortie tuée en plein
    écriture peut finir sur une ligne tronquée : on l'écarte)."""
    lines: List[str] = []
    for line in read_lines(path):
        try:
            if isinstance(json.loads(line), dict):
                lines.append(line)
        except json.JSONDecodeError:
            continue
    return lines


def merge_jsonl(parts: Sequence[Path], destination: Path) -> int:
    """Concatène les lots JSONL valides dans `destination` (dédupliqué, ordre conservé),
    supprime les lots, retourne le nombre de findings."""
    merged: List[str] = []
    try:
        for part in parts:
            merged.extend(valid_json_lines(part))
    finally:
        for part in parts:
            part.unlink(missing_ok=True)
    return write_lines(destination, merged)


def parse_findings(path: Path) -> List[Finding]:
    findings: List[Finding] = []
    for line in valid_json_lines(path):
        row = json.loads(line)
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        severity = str(info.get("severity") or row.get("severity") or "unknown").lower()
        if severity not in SEVERITIES:
            severity = "unknown"
        template = str(row.get("template-id") or row.get("templateID") or row.get("template") or "?")
        target = str(row.get("matched-at") or row.get("matched") or row.get("url") or row.get("host") or "?")
        findings.append((severity, template, target))
    return findings


def sort_findings(findings: Iterable[Finding]) -> List[Finding]:
    """Dédupliqué (un même finding peut sortir des deux passes), du plus grave au moins grave."""
    return sorted(set(findings), key=lambda f: (SEVERITIES.index(f[0]), f[1], f[2]))


def count_by_severity(findings: Iterable[Finding]) -> Dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for severity, _, _ in findings:
        counts[severity] += 1
    return {severity: n for severity, n in counts.items() if n}


def write_view(jsonl_files: Sequence[Path], destination: Path) -> Dict[str, int]:
    """Génère `nuclei.txt` depuis les JSONL donnés. Retourne les comptes par sévérité."""
    findings: List[Finding] = []
    for path in jsonl_files:
        findings.extend(parse_findings(path))
    ordered = sort_findings(findings)
    write_lines(destination, [f"[{sev}] {template} {target}" for sev, template, target in ordered])
    return count_by_severity(ordered)


def severity_line(counts: Dict[str, int]) -> str:
    """`2 critical · 1 high` (markup Rich) ou « aucun finding »."""
    if not counts:
        return "aucun finding"
    colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim", "unknown": "dim"}
    return " · ".join(f"[{colors[sev]}]{n} {sev}[/{colors[sev]}]" for sev, n in counts.items())
