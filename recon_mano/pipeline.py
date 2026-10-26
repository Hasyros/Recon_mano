"""Modèle de modules + ordonnanceur sensible aux dépendances.

Chaque étape du pipeline est un `Module` indépendant. L'`Scheduler` démarre tout
module dont les dépendances sont *terminées* (réussies, en échec, en timeout,
ignorées ou désactivées — peu importe : c'est la fonction `run` du module qui
gère les entrées manquantes et les replis), dans la limite de `--workers` modules
simultanés et d'un **budget de débit global** (`--max-rps`) partagé par tous les
modules qui envoient du trafic à la cible.

États : pending → running → done | failed | timeout ; ou skipped (désactivé par une
option, ou rien à faire) / disabled (binaire introuvable).
"""

from __future__ import annotations

import copy
import json
import platform
import shutil
import threading
import time
import traceback
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from rich.live import Live
from rich.markup import escape

from . import __version__, runner, ui
from .scope import ScopeFilter
from .ui import console, human_duration

# Budget de débit : sous ce plancher (ou le débit demandé s'il est plus petit), un
# module réseau attend qu'un autre libère du budget plutôt que de démarrer étranglé.
MIN_START_RATE = 10

# Fichiers produits par le pipeline (clé interne → nom, à la racine du dossier de sortie
# pour la compatibilité). Sert aussi au nettoyage (--clean) et à `merge`.
ARTIFACTS: Dict[str, str] = {
    "subfinder": "01_subfinder.txt",
    "dnsx": "02_dnsx.txt",
    "urlfinder": "03_urlfinder.txt",
    "httpx_input": "04_httpx_input.txt",
    "httpx_jsonl": "05_httpx.jsonl",
    "urls_all": "urls_all.txt",
    "urls_200": "urls_200.txt",
    "urls_live": "urls_live.txt",
    "katana": "06_katana.txt",
    "all_urls": "all_urls.txt",
    "httpx2_jsonl": "08_httpx2.jsonl",
    "urls_all_final": "urls_all_final.txt",
    "urls_200_final": "urls_200_final.txt",
    "urls_live_final": "urls_live_final.txt",
    "rejected_scope": "rejected_scope.tsv",
    "nuclei_input": "07_nuclei_input.txt",
    "nuclei": "nuclei.txt",
    "tree_html": "urls_tree.html",
    "run_config": "run_config.json",
    "run_stats": "run_stats.json",
}


def build_paths(output: Path) -> Dict[str, Path]:
    return {key: output / name for key, name in ARTIFACTS.items()}


class Status(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    DISABLED = "disabled"


# Un module « terminé » débloque ses dépendants, quelle que soit l'issue.
FINISHED = {Status.DONE, Status.FAILED, Status.TIMEOUT, Status.SKIPPED, Status.DISABLED}


class ModuleSkipped(Exception):
    """Levée par un module qui n'a rien à faire (entrée absente…) : statut `skipped`."""


class ModuleError(Exception):
    """Échec attendu (message clair, pas de traceback) : statut `failed`."""


@dataclass
class ModuleResult:
    count: int
    note: str = ""


@dataclass
class Module:
    name: str
    deps: List[str]
    run: Callable[["Context"], ModuleResult]
    binaries: List[str] = field(default_factory=list)
    enabled: bool = True
    timeout: Optional[int] = None  # secondes ; None = illimité
    network: bool = False          # envoie du trafic à la cible → consomme le budget de débit
    rate: int = 0                  # req/s demandées (si network)
    icon: str = "•"
    desc: str = ""
    label: str = ""                # nom affiché (défaut : name)

    @property
    def display(self) -> str:
        return self.label or self.name


@dataclass
class ModuleRecord:
    name: str
    label: str
    icon: str
    desc: str
    deps: List[str]
    network: bool
    status: Status = Status.PENDING
    start: Optional[float] = None   # décalage (s) depuis le début du run
    end: Optional[float] = None
    count: int = 0
    rate: int = 0                   # débit accordé
    requested_rate: int = 0
    note: str = ""

    @property
    def duration(self) -> float:
        if self.start is None or self.end is None:
            return 0.0
        return max(self.end - self.start, 0.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "start": _round(self.start),
            "end": _round(self.end),
            "duration": round(self.duration, 3),
            "count": self.count,
            "rate": self.rate,
            "requested_rate": self.requested_rate,
            "network": self.network,
            "deps": list(self.deps),
            "note": self.note,
        }


def _round(value: Optional[float]) -> Optional[float]:
    return None if value is None else round(value, 3)


# --------------------------------------------------------------------------- #
# Contexte partagé
# --------------------------------------------------------------------------- #


@dataclass
class Context:
    """Ce que voient les modules. Un exemplaire par module (`for_module`), mais
    paths / state / scope / lock / records sont partagés entre tous."""

    target: str
    output: Path
    paths: Dict[str, Path]
    options: Any
    scope: ScopeFilter
    state: Dict[str, Any] = field(default_factory=dict)
    lock: Any = field(default_factory=threading.RLock)
    records: Dict[str, ModuleRecord] = field(default_factory=dict)
    # Propres au module courant :
    module: str = ""
    rate: int = 0                       # débit accordé (req/s), 0 si non réseau
    deadline: Optional[float] = None    # échéance (time.monotonic) ou None
    lines: List[str] = field(default_factory=list)

    def for_module(self, module: Module, rate: int, deadline: Optional[float]) -> "Context":
        view = copy.copy(self)
        view.module, view.rate, view.deadline, view.lines = module.name, rate, deadline, []
        return view

    def status(self, name: str) -> Status:
        record = self.records.get(name)
        return record.status if record else Status.PENDING

    def remaining(self) -> Optional[int]:
        """Secondes restantes avant l'échéance du module (pour `run_command(timeout=…)`)."""
        if self.deadline is None:
            return None
        return max(int(self.deadline - time.monotonic()) + 1, 1)

    def log(self, message: Optional[str], now: bool = False) -> None:
        """Journalise une ligne de détail du module.

        Par défaut elle est mise de côté et imprimée d'un bloc à la fin du module
        (sinon les lignes de modules parallèles s'entremêlent) ; `now=True` l'imprime
        tout de suite avec le nom du module en préfixe (attentes, nouveaux essais).
        """
        if not message:
            return
        if now:
            console.print(f"[dim]{self.module} ·[/dim] {message.strip()}")
        else:
            self.lines.append(message)


# --------------------------------------------------------------------------- #
# Budget de débit global
# --------------------------------------------------------------------------- #


class RateBudget:
    """Budget global de requêtes/seconde partagé par les modules réseau.

    `acquire` ne bloque pas : l'ordonnanceur réessaie à chaque tour tant qu'il
    retourne None. Somme des débits accordés ≤ `max_rps`, toujours.
    """

    def __init__(self, max_rps: int) -> None:
        self.max_rps = max(int(max_rps), 1)
        self._used = 0
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    def acquire(self, wanted: int) -> Optional[int]:
        wanted = max(int(wanted), 1)
        # Plancher de démarrage : jamais plus que le budget total (sinon un
        # --max-rps bas ne démarrerait aucun module).
        minimum = min(wanted, MIN_START_RATE, self.max_rps)
        with self._lock:
            remaining = self.max_rps - self._used
            if remaining < minimum:
                return None
            granted = min(wanted, remaining)
            self._used += granted
            return granted

    def release(self, granted: int) -> None:
        with self._lock:
            self._used = max(self._used - granted, 0)


# --------------------------------------------------------------------------- #
# Ordonnanceur
# --------------------------------------------------------------------------- #


def validate_modules(modules: List[Module]) -> None:
    """Noms uniques, dépendances connues, pas de cycle (sinon ValueError)."""
    names = [m.name for m in modules]
    if len(set(names)) != len(names):
        raise ValueError("noms de modules en double")
    for module in modules:
        for dep in module.deps:
            if dep not in names:
                raise ValueError(f"module {module.name!r} : dépendance inconnue {dep!r}")
    resolved: set = set()
    remaining = list(modules)
    while remaining:
        ready = [m for m in remaining if all(d in resolved for d in m.deps)]
        if not ready:
            raise ValueError("cycle dans les dépendances : " + ", ".join(m.name for m in remaining))
        resolved.update(m.name for m in ready)
        remaining = [m for m in remaining if m.name not in resolved]


class Scheduler:
    def __init__(
        self,
        modules: List[Module],
        ctx: Context,
        max_workers: int = 4,
        max_rps: int = 150,
        live: bool = True,
        verbose: bool = False,
        poll: float = 0.1,
    ) -> None:
        validate_modules(modules)
        self.modules = modules
        self.ctx = ctx
        self.max_workers = max(int(max_workers), 1)
        self.max_rps = max(int(max_rps), 1)
        self.budget = RateBudget(self.max_rps)
        self.live = live
        self.verbose = verbose
        self.poll = poll
        self.records: Dict[str, ModuleRecord] = {
            m.name: ModuleRecord(m.name, m.display, m.icon, m.desc, list(m.deps), m.network, requested_rate=m.rate if m.network else 0)
            for m in modules
        }
        ctx.records = self.records
        self.wall_clock = 0.0
        self._t0 = time.monotonic()
        self._lock = threading.Lock()
        self._which: Dict[str, Optional[str]] = {}

    # -- utilitaires ---------------------------------------------------------- #

    def _now(self) -> float:
        return time.monotonic() - self._t0

    def _find_binary(self, name: str) -> Optional[str]:
        if name not in self._which:
            if name == "httpx":
                # Le `httpx` du PATH peut être le client HTTP Python : résolution dédiée.
                if "httpx_path" not in self.ctx.state:
                    self.ctx.state["httpx_path"] = runner.resolve_httpx(getattr(self.ctx.options, "httpx_bin", None))
                self._which[name] = self.ctx.state["httpx_path"]
            else:
                self._which[name] = shutil.which(name)
        return self._which[name]

    def rows(self) -> List[ui.ModuleRow]:
        """Instantané pour le board (appelé par le thread de rafraîchissement de Live)."""
        now = self._now()
        with self._lock:
            rows = []
            for module in self.modules:
                rec = self.records[module.name]
                running = rec.status is Status.RUNNING
                rows.append(ui.ModuleRow(
                    name=rec.name, label=rec.label, icon=rec.icon, status=rec.status.value,
                    count=ui.PROGRESS.get(rec.name) if running else rec.count,
                    elapsed=(now - rec.start) if running and rec.start is not None else rec.duration,
                    rate=rec.rate, note=rec.note if rec.status is Status.PENDING else "",
                ))
            return rows

    def summary_rows(self) -> List[ui.ModuleRow]:
        """Une ligne par module, dans l'ordre de démarrage."""
        order = {m.name: i for i, m in enumerate(self.modules)}
        recs = sorted(
            self.records.values(),
            key=lambda r: (r.start is None, r.start if r.start is not None else 0.0, order[r.name]),
        )
        return [
            ui.ModuleRow(r.name, r.label, r.icon, r.status.value, r.count, r.duration, r.rate, r.note)
            for r in recs
        ]

    @property
    def sum_of_durations(self) -> float:
        return sum(r.duration for r in self.records.values())

    @property
    def failed(self) -> bool:
        return any(r.status is Status.FAILED for r in self.records.values())

    def stats(self) -> Dict[str, Any]:
        order = {m.name: i for i, m in enumerate(self.modules)}
        recs = sorted(
            self.records.values(),
            key=lambda r: (r.start is None, r.start if r.start is not None else 0.0, order[r.name]),
        )
        total = self.sum_of_durations
        return {
            "target": self.ctx.target,
            "workers": self.max_workers,
            "max_rps": self.max_rps,
            "wall_clock": round(self.wall_clock, 3),
            "sum_of_durations": round(total, 3),
            "parallel_gain": round(total - self.wall_clock, 3),
            "modules": [r.to_dict() for r in recs],
        }

    def write_stats(self, path: Path) -> None:
        try:
            path.write_text(json.dumps(self.stats(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        except OSError as exc:
            console.print(f"[yellow]run_stats.json non écrit : {exc}[/yellow]")

    # -- cycle de vie d'un module -------------------------------------------- #

    def _finish_instant(self, rec: ModuleRecord, status: Status, note: str) -> None:
        """Module qui n'a jamais tourné (désactivé / ignoré) : terminé tout de suite."""
        with self._lock:
            rec.status, rec.note = status, note
            rec.start = rec.end = self._now()
        glyph, style, _ = ui.STATUS_VIEW[status.value]
        console.print(f"  [{style}]{glyph}[/] {rec.icon} [bold]{rec.label}[/] [dim]— {note}[/dim]")

    def _launch(self, module: Module, rec: ModuleRecord, granted: int, executor: ThreadPoolExecutor, futures: Dict[Future, tuple]) -> None:
        deadline = time.monotonic() + module.timeout if module.timeout else None
        mctx = self.ctx.for_module(module, granted, deadline)
        with self._lock:
            rec.status, rec.start, rec.rate, rec.note = Status.RUNNING, self._now(), granted, ""
        ui.PROGRESS.clear(module.name)
        rate_txt = ""
        if module.network:
            rate_txt = f" · {granted}/s"
            if granted < module.rate:
                rate_txt += f" (demandé {module.rate}, plafonné par --max-rps)"
        console.print(f"[dim]▶ {module.icon} {module.display} · {module.desc}{rate_txt}[/dim]")
        futures[executor.submit(self._execute, module, mctx)] = (module, mctx)

    @staticmethod
    def _execute(module: Module, mctx: Context) -> ModuleResult:
        ui.bind_module(module.name)
        try:
            return module.run(mctx)
        finally:
            ui.bind_module(None)

    def _collect(self, future: Future, module: Module, mctx: Context) -> None:
        rec = self.records[module.name]
        status, note, count = Status.DONE, "", 0
        detail: List[str] = []  # lignes après la note (origine de l'exception, traceback en -v)
        try:
            result = future.result()
            count, note = result.count, result.note
        except ModuleSkipped as exc:
            status, note = Status.SKIPPED, str(exc)
        except ModuleError as exc:
            status, note = Status.FAILED, str(exc)
        except Exception as exc:  # noqa: BLE001 — un module ne doit jamais tuer le pipeline
            status, note = Status.FAILED, f"{type(exc).__name__}: {exc}"
            frame = traceback.extract_tb(exc.__traceback__)[-1]
            detail.append(f"  [dim]{Path(frame.filename).name}:{frame.lineno} dans {frame.name}[/dim]")
            if self.verbose:
                detail.append(escape("".join(traceback.format_exception(type(exc), exc, exc.__traceback__))))
        end = self._now()
        with self._lock:
            started = rec.start if rec.start is not None else end
            if status is Status.DONE and module.timeout is not None and end - started > module.timeout:
                status = Status.TIMEOUT
                note = note or f"délai de {human_duration(module.timeout)} dépassé"
            rec.status, rec.end, rec.count, rec.note = status, end, count, note
        if module.network:
            self.budget.release(rec.rate)
        self._print_finish(rec, mctx, detail)

    def _print_finish(self, rec: ModuleRecord, mctx: Context, detail: List[str]) -> None:
        glyph, style, label = ui.STATUS_VIEW[rec.status.value]
        if rec.status in (Status.DONE, Status.TIMEOUT):
            result = f"{rec.count:,} entrées".replace(",", " ")
        else:
            result = label
        console.print()
        console.rule(
            f"[bold {style}]{glyph}[/] {rec.icon} [bold]{rec.label}[/]  "
            f"[dim]· {result} · {human_duration(rec.duration)}[/]",
            align="left", style="#1f2d3d",
        )
        for line in mctx.lines:
            console.print(line)
        if rec.note and rec.status is not Status.DONE:
            console.print(f"  [{style}]{escape(rec.note)}[/{style}]")
        elif rec.note:
            console.print(f"  [dim]{escape(rec.note)}[/dim]")
        for line in detail:
            console.print(line)

    # -- boucle principale ---------------------------------------------------- #

    def _step(self, executor: ThreadPoolExecutor, futures: Dict[Future, tuple]) -> bool:
        """Démarre/résout tout ce qui peut l'être. Retourne True s'il y a eu du progrès."""
        progressed = False
        for module in self.modules:
            rec = self.records[module.name]
            if rec.status is not Status.PENDING:
                continue
            if not all(self.records[d].status in FINISHED for d in module.deps):
                continue
            if not module.enabled:
                self._finish_instant(rec, Status.SKIPPED, "désactivé (option)")
                progressed = True
                continue
            missing = [b for b in module.binaries if not self._find_binary(b)]
            if missing:
                self._finish_instant(rec, Status.DISABLED, f"binaire {', '.join(missing)} introuvable — module désactivé")
                progressed = True
                continue
            if len(futures) >= self.max_workers:
                continue
            granted = 0
            if module.network:
                acquired = self.budget.acquire(module.rate)
                if acquired is None:
                    rec.note = "attend le budget de débit"
                    continue
                granted = acquired
            self._launch(module, rec, granted, executor, futures)
            progressed = True
        return progressed

    def _all_finished(self) -> bool:
        return all(r.status in FINISHED for r in self.records.values())

    def run(self) -> List[ModuleRecord]:
        self._t0 = time.monotonic()
        board = Live(
            ui.Board(self.rows), console=console, refresh_per_second=8, transient=True,
        ) if (self.live and not self.verbose and console.is_terminal) else nullcontext()
        executor = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="module")
        futures: Dict[Future, tuple] = {}
        interrupted = False
        try:
            with board:
                while True:
                    progressed = self._step(executor, futures)
                    if self._all_finished():
                        break
                    if futures:
                        done, _ = wait(list(futures), timeout=self.poll, return_when=FIRST_COMPLETED)
                        for future in done:
                            module, mctx = futures.pop(future)
                            self._collect(future, module, mctx)
                    elif not progressed:
                        # Rien en cours ni démarrable : sécurité contre une boucle infinie.
                        raise RuntimeError("ordonnanceur bloqué : " + ", ".join(
                            n for n, r in self.records.items() if r.status is Status.PENDING))
        except KeyboardInterrupt:
            interrupted = True
            runner.kill_all()
            with self._lock:
                for rec in self.records.values():
                    if rec.status in (Status.RUNNING, Status.PENDING):
                        was_running = rec.status is Status.RUNNING
                        rec.status = Status.FAILED if was_running else Status.SKIPPED
                        rec.note = "interrompu (Ctrl+C)"
                        rec.end = self._now()
                        if rec.start is None:
                            rec.start = rec.end
            console.print("\n[bold yellow]Interrompu — outils arrêtés.[/bold yellow]")
        finally:
            executor.shutdown(wait=not interrupted, cancel_futures=True)
            self.wall_clock = self._now()
            self.write_stats(self.ctx.paths["run_stats"])
        if interrupted:
            raise KeyboardInterrupt
        return list(self.records.values())


# --------------------------------------------------------------------------- #
# run_config.json
# --------------------------------------------------------------------------- #


def write_run_config(path: Path, data: Dict[str, Any]) -> None:
    """Config du run (périmètre, codes…), relue par `recon_mano merge`."""
    payload = {
        "version": __version__,
        "python": platform.python_version(),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        **data,
    }
    try:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        console.print(f"[yellow]run_config.json non écrit : {exc}[/yellow]")


def load_run_config(folder: Path) -> Dict[str, Any]:
    """Config d'un run précédent, {} si absente ou illisible."""
    try:
        data = json.loads((folder / ARTIFACTS["run_config"]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}
