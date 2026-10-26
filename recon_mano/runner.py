"""Exécution des outils externes (subprocess) et résolution des binaires.

`run_command` est appelé depuis plusieurs threads (un par module en parallèle) :
il n'ouvre aucun affichage Rich qui lui soit propre, il publie seulement son
compteur de lignes dans `ui.PROGRESS` ; c'est le board de l'ordonnanceur qui l'affiche.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import ui
from .io_utils import count_lines
from .ui import console, human_duration

# Le client HTTP Python s'installe aussi comme `httpx` dans le PATH avec des
# flags totalement différents : on doit distinguer les deux.
HTTPX_MARKERS = ("projectdiscovery", "httpx version")

# Mode -v : intervalle du « heartbeat » de progression quand l'outil est muet
# sur stderr mais écrit dans son -o (httpx traversant des URLs mortes…).
VERBOSE_HEARTBEAT_SEC = 5

_VERBOSE = False

# Processus en cours : permet de tout tuer proprement sur Ctrl+C (jamais d'orphelin).
_PROCS: set = set()
_PROCS_LOCK = threading.Lock()


def set_verbose(value: bool) -> None:
    global _VERBOSE
    _VERBOSE = value


def is_verbose() -> bool:
    return _VERBOSE


def kill_all() -> None:
    """Tue tous les outils encore actifs (Ctrl+C, arrêt de l'ordonnanceur)."""
    with _PROCS_LOCK:
        procs = list(_PROCS)
    for proc in procs:
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass


def run_command(
    command: Sequence[str],
    label: str,
    watch: Optional[Path] = None,
    timeout: Optional[int] = None,
    stdout_to: Optional[Path] = None,
    silent: bool = True,
    stdin_from: Optional[Path] = None,
) -> tuple[int, float, str]:
    """Lance un outil sans tuer le pipeline sur un exit code non nul.

    Mode normal : la progression (lignes écrites dans `watch`) est publiée dans le
    registre partagé `ui.PROGRESS` ; le board de l'ordonnanceur l'affiche, pour
    qu'un scan long (httpx sur 8000 hôtes…) montre en permanence qu'il tourne.
    Mode --verbose : flux stderr de l'outil en direct (préfixe `label │`) + heartbeat.

    `stdout_to` redirige la sortie standard vers un fichier (au lieu de la jeter) :
    on capture ainsi directement ce que l'outil imprime, sans dépendre de son -o.

    `stdin_from` alimente l'entrée standard depuis un fichier (outils de filtre type
    `gf`) ; sans lui l'outil hérite de l'entrée du pipeline, comme avant.

    `timeout` (secondes) : l'outil est tué au-delà, code retour 124.

    Retourne (code_retour, secondes, stderr_capturé).
    """
    full = list(command)
    if silent and not _VERBOSE and "-silent" not in full:
        full.append("-silent")

    key = ui.current_module() or label
    start = time.monotonic()
    out_handle = open(stdout_to, "w", encoding="utf-8") if stdout_to is not None else None
    out_target = out_handle if out_handle is not None else subprocess.DEVNULL
    in_handle = open(stdin_from, "rb") if stdin_from is not None else None
    proc: Optional[subprocess.Popen] = None

    try:
        if _VERBOSE:
            console.print(f"[dim cyan]$ {' '.join(full)}[/dim cyan]")
        try:
            proc = subprocess.Popen(
                full, stderr=subprocess.PIPE, stdout=out_target, stdin=in_handle,
                text=True, encoding="utf-8", errors="replace", bufsize=1 if _VERBOSE else -1,
            )
        except FileNotFoundError:
            console.print(f"[bold red]Binaire introuvable :[/bold red] {full[0]}")
            return 127, 0.0, ""
        with _PROCS_LOCK:
            _PROCS.add(proc)
        assert proc.stderr is not None

        # stderr lu par un thread : en verbose il est streamé en direct, sinon capturé
        # (urlfinder -v y écrit son diagnostic par source).
        stderr_tail: List[str] = []

        def _drain() -> None:
            for line in proc.stderr:  # type: ignore[union-attr]
                if _VERBOSE:
                    console.print(f"[dim]  {label} │ {line.rstrip()}[/dim]")
                else:
                    stderr_tail.append(line)

        drainer = threading.Thread(target=_drain, daemon=True)
        drainer.start()

        last_beat = 0.0
        last_size = -1
        count = 0
        killed = False
        while proc.poll() is None:
            elapsed = time.monotonic() - start
            if timeout and elapsed > timeout:
                proc.kill()
                killed = True
                break
            if watch is not None and watch.exists():
                size = watch.stat().st_size
                if size != last_size:
                    count = count_lines(watch)
                    last_size = size
                    ui.PROGRESS.update(key, count)
            if _VERBOSE and elapsed - last_beat >= VERBOSE_HEARTBEAT_SEC:
                console.print(f"[dim]  {label} · {count} lignes · {human_duration(elapsed)}…[/dim]")
                last_beat = elapsed
            time.sleep(0.4)

        try:
            proc.wait(timeout=5)  # récolte le processus tué (pas de zombie)
        except subprocess.TimeoutExpired:
            pass
        drainer.join(timeout=1)
        if watch is not None and watch.exists():
            ui.PROGRESS.update(key, count_lines(watch))
    finally:
        # Quoi qu'il arrive (exception, Ctrl+C) : aucun outil ne reste en arrière-plan.
        if proc is not None:
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            with _PROCS_LOCK:
                _PROCS.discard(proc)
        if out_handle is not None:
            out_handle.close()
        if in_handle is not None:
            in_handle.close()

    elapsed = time.monotonic() - start
    stderr_text = "".join(stderr_tail)
    if killed:
        console.print(f"[bold yellow]Timeout[/bold yellow] sur {label} après {human_duration(elapsed)}")
        return 124, elapsed, stderr_text

    rc = proc.returncode
    if rc != 0 and stderr_tail:
        console.print(f"[yellow]{label} exit {rc}[/yellow] : {stderr_text.strip()[:400]}")
    return rc, elapsed, stderr_text


# --------------------------------------------------------------------------- #
# Résolution des binaires
# --------------------------------------------------------------------------- #


def is_projectdiscovery_httpx(path: str) -> bool:
    try:
        result = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    blob = f"{result.stdout}{result.stderr}".lower()
    return any(marker in blob for marker in HTTPX_MARKERS)


def resolve_httpx(explicit: Optional[str] = None) -> Optional[str]:
    """Trouve le httpx de ProjectDiscovery, pas le client HTTP Python."""
    candidates: List[str] = []
    if explicit:
        candidates.append(explicit)
    found = shutil.which("httpx")
    if found:
        candidates.append(found)
    go_bin = Path.home() / "go" / "bin"
    candidates += [str(go_bin / "httpx.exe"), str(go_bin / "httpx")]

    for candidate in candidates:
        if candidate and Path(candidate).exists() and is_projectdiscovery_httpx(candidate):
            return candidate
    return None
