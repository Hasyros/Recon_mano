"""Petits utilitaires fichiers partagés (cli, scope, liveness).

Isolés ici pour éviter les imports circulaires : `scope.py` et `liveness.py`
lisent/écrivent des listes mais ne doivent pas dépendre de `cli.py`.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Sequence


def count_lines(path: Path) -> int:
    """Compte les lignes en binaire — rapide même sur des fichiers volumineux."""
    try:
        with path.open("rb") as handle:
            return sum(chunk.count(b"\n") for chunk in iter(lambda: handle.read(1 << 20), b""))
    except OSError:
        return 0


def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def write_lines(path: Path, lines: Sequence[str]) -> int:
    deduped = list(dict.fromkeys(line for line in lines if line.strip()))
    path.write_text("\n".join(deduped) + ("\n" if deduped else ""), encoding="utf-8")
    return len(deduped)
