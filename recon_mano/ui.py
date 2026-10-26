"""Habillage Rich partagé : console unique, bannière, board live, tableau final.

Rich n'autorise qu'un seul affichage `Live` à la fois : avec des modules en
parallèle, c'est l'ordonnanceur qui possède le board (`Board`) ; les outils ne
font que publier leur progression dans `PROGRESS` (registre thread-safe).
"""

from __future__ import annotations

import sys
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

# La console Windows est en cp1252 par défaut : accents et flèches du rendu Rich
# y lèvent un UnicodeEncodeError. On bascule en UTF-8 tolérant avant tout.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, OSError, ValueError):
        pass

console = Console()


# --------------------------------------------------------------------------- #
# Formatage / mesures
# --------------------------------------------------------------------------- #


def human_duration(seconds: float) -> str:
    total = int(seconds)
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def format_eta(count: int, per_second: float) -> Optional[str]:
    if count <= 0 or per_second <= 0:
        return None
    return human_duration(count / per_second)


def eta_line(count: int, per_second: float, note: str) -> Optional[str]:
    """Ligne d'estimation (markup Rich) ou None ; le module la journalise lui-même."""
    eta = format_eta(count, per_second)
    if eta:
        return f"  [dim]≈ {eta} estimé · {count} {note}[/dim]"
    return None


# --------------------------------------------------------------------------- #
# Habillage visuel
# --------------------------------------------------------------------------- #

_BANNER = [
    r"    ____                          __  ___",
    r"   / __ \___  _________  ____    /  |/  /___ _____  ____",
    r"  / /_/ / _ \/ ___/ __ \/ __ \  / /|_/ / __ `/ __ \/ __ \ ",
    r" / _, _/  __/ /__/ /_/ / / / / / /  / / /_/ / / / / /_/ /",
    r"/_/ |_|\___/\___/\____/_/ /_/ /_/  /_/\__,_/_/ /_/\____/",
]
# Dégradé cyan → indigo, ligne par ligne.
_BANNER_GRAD = ["#22d3ee", "#38bdf8", "#3b82f6", "#6366f1", "#818cf8"]

# Icône par étape (rendu terminal Kali OK).
# Emojis à largeur fixe (sans sélecteur de variante) → alignement propre en table.
STAGE_ICONS = {
    "subfinder": "🔍", "dnsx": "🧬", "urlfinder": "📜", "httpx": "📡",
    "httpx #2": "🔁", "httpx2": "🔁", "katana": "🧭", "nuclei": "💥", "report": "🌳",
    "nuclei1": "💥", "nuclei2": "💥", "merge_map": "🧩", "tree": "🌳",
}

# statut → (glyphe, style Rich, libellé)
STATUS_VIEW = {
    "pending": ("…", "dim", "attente"),
    "running": ("▶", "cyan", "en cours"),
    "done": ("✓", "green", "terminé"),
    "failed": ("✗", "red", "échec"),
    "timeout": ("⏱", "yellow", "timeout"),
    "skipped": ("–", "dim", "ignoré"),
    "disabled": ("⊘", "yellow", "désactivé"),
}


def print_banner(rows: Sequence[tuple[str, str]]) -> None:
    """Bannière ASCII en dégradé + panneau récapitulatif du scan."""
    console.print()
    for line, color in zip(_BANNER, _BANNER_GRAD):
        console.print(f"[bold {color}]{line}[/]")
    console.print("[dim italic]   reconnaissance passive → active · pipeline ProjectDiscovery[/]\n")
    body = Text()
    for index, (label, value) in enumerate(rows):
        if index:
            body.append("\n")
        body.append(f"{label}  ", style="dim")
        body.append(value, style="bold")
    console.print(Panel(body, border_style="#38bdf8", box=box.ROUNDED, expand=False, padding=(0, 2)))


def stage_header(step: str, name: str, desc: str) -> None:
    icon = STAGE_ICONS.get(name, "•")
    console.print()
    console.rule(f"[bold #38bdf8]{step}[/]  {icon} [bold]{name}[/]  [dim]· {desc}[/]", align="left", style="#1f2d3d")


def report(count: int, path, elapsed: float) -> str:
    """Ligne `→ N entrées · durée · fichier` (markup Rich), à journaliser par le module."""
    color = "green" if count else "yellow"
    return f"  [{color}]→ {count} entrées[/{color}] · {human_duration(elapsed)} · {path.name}"


# --------------------------------------------------------------------------- #
# Progression des outils (écrite par run_command, lue par le board)
# --------------------------------------------------------------------------- #


class ProgressRegistry:
    """Compteur de lignes par module, partagé entre threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._lines: Dict[str, int] = {}

    def update(self, key: str, lines: int) -> None:
        with self._lock:
            self._lines[key] = lines

    def get(self, key: str) -> int:
        with self._lock:
            return self._lines.get(key, 0)

    def clear(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._lines.clear()
            else:
                self._lines.pop(key, None)


PROGRESS = ProgressRegistry()

# Module « courant » du thread : run_command y rattache sa progression sans que
# les modules aient à passer leur nom à chaque appel.
_local = threading.local()


def bind_module(name: Optional[str]) -> None:
    _local.module = name


def current_module() -> Optional[str]:
    return getattr(_local, "module", None)


# --------------------------------------------------------------------------- #
# Board live + tableau final
# --------------------------------------------------------------------------- #


@dataclass
class ModuleRow:
    """Vue d'un module pour l'affichage (board et récapitulatif)."""

    name: str
    label: str
    icon: str
    status: str
    count: int = 0
    elapsed: float = 0.0
    rate: int = 0
    note: str = ""
    start: Optional[float] = None   # décalage (s) depuis le début du run


class Board:
    """Tableau compact rendu en continu par `rich.live.Live` (une ligne par module)."""

    def __init__(self, rows: Callable[[], List[ModuleRow]]) -> None:
        self._rows = rows

    def __rich__(self) -> Table:
        table = Table(
            box=box.ROUNDED, border_style="#38bdf8", header_style="bold #38bdf8",
            expand=False, padding=(0, 1),
        )
        table.add_column("module")
        table.add_column("état")
        table.add_column("lignes", justify="right")
        table.add_column("temps", justify="right", style="dim")
        table.add_column("débit", justify="right", style="dim")
        for row in self._rows():
            glyph, style, label = STATUS_VIEW.get(row.status, ("•", "", row.status))
            name = f"{row.icon} {row.label}"
            if row.status == "running":
                state = Spinner("dots", text=Text(label, style=style), style=style)
            else:
                text = f"{glyph} {label}"
                if row.status == "pending" and row.note:
                    text = f"{glyph} {row.note}"
                state = Text(text, style=style)
            shown = row.count if row.status in ("running", "done", "timeout", "failed") else 0
            lines = f"{shown:,}".replace(",", " ") if shown else ""
            elapsed = human_duration(row.elapsed) if row.status not in ("pending", "skipped", "disabled") else ""
            rate = f"{row.rate}/s" if row.rate else ""
            table.add_row(Text(name, style="dim" if row.status == "pending" else ""), state, lines, elapsed, rate)
        return table


def _short(text: str, width: int) -> str:
    """Note tronquée pour le tableau (le détail complet est dans run_stats.json)."""
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 1] + "…"


def print_summary(
    rows: Sequence[ModuleRow], total_elapsed: float, cumulated: float, failed: bool = False
) -> None:
    """Récapitulatif final : une ligne par module (dans l'ordre de démarrage)."""
    color = "yellow" if failed else "green"
    title_glyph = "!" if failed else "✓"
    gain = cumulated - total_elapsed
    table = Table(
        title=f"[bold {color}]{title_glyph} Terminé en {human_duration(total_elapsed)}[/]",
        caption=(
            f"durée réelle {human_duration(total_elapsed)} · cumul des modules "
            f"{human_duration(cumulated)} · gain parallèle {human_duration(max(gain, 0))}"
        ),
        caption_justify="left",
        box=box.ROUNDED, border_style=color, header_style="bold #38bdf8",
        title_justify="left", expand=False, padding=(0, 1),
    )
    table.add_column("étape", no_wrap=True)
    table.add_column("début", justify="right", style="dim", no_wrap=True)
    table.add_column("statut", no_wrap=True)
    table.add_column("résultat", justify="right", style="bold", no_wrap=True)
    table.add_column("temps", justify="right", style="dim", no_wrap=True)
    table.add_column("note", style="dim", no_wrap=True, overflow="ellipsis")
    # Les colonnes fixes (~66 car. avec bordures) gardent leur largeur ; la note prend le reste.
    note_width = min(max(console.width - 68, 16), 70)
    for row in rows:
        glyph, style, label = STATUS_VIEW.get(row.status, ("•", "", row.status))
        has_result = row.status in ("done", "timeout", "failed")
        result = f"{row.count:,}".replace(",", " ") if has_result and row.status != "failed" else "–"
        ran = row.status not in ("skipped", "disabled") and row.start is not None
        table.add_row(
            f"{row.icon} {row.label}",
            f"+{human_duration(row.start)}" if ran else "",
            Text(f"{glyph} {label}", style=style),
            result,
            human_duration(row.elapsed) if row.status not in ("skipped", "disabled") else "",
            _short(row.note, note_width),
        )
    console.print()
    console.print(table)
