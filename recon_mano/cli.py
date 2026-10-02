"""Recon Mano - orchestration de la chaîne de reconnaissance ProjectDiscovery.

Pipeline::

    cible ─┬─ subfinder → dnsx (-wd) ── hôtes ──┐
           │                                     ├─ merge → httpx ─┬─ urls_all.txt
           └─ urlfinder (-d apex) ──── URLs ────┘                  └─ urls_200.txt → katana
                                                                                        │
                                                            merge final ────────────────┘
                                                                  └─ [--nuclei] (opt-in)

Invocation minimale::

    recon_mano cible.com nom_sortie [--nuclei ...]
    python -m recon_mano cible.com nom_sortie [--nuclei ...]
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional, Sequence
from urllib.parse import urlparse

try:
    import typer
except ModuleNotFoundError:
    print(
        "Module 'typer' introuvable. Installez-le avec :\n"
        "python -m pip install -r requirements.txt --break-system-packages"
    )
    raise

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .report import write_report as write_tree_report

# La console Windows est en cp1252 par défaut : accents et flèches du rendu Rich
# y lèvent un UnicodeEncodeError. On bascule en UTF-8 tolérant avant tout.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, OSError, ValueError):
        pass

console = Console()

REQUIRED_TOOLS = ["subfinder", "dnsx", "httpx", "urlfinder", "katana"]

# Le client HTTP Python s'installe aussi comme `httpx` dans le PATH avec des
# flags totalement différents : on doit distinguer les deux.
HTTPX_MARKERS = ("projectdiscovery", "httpx version")

# Large volontairement : 401/403 = endpoints protégés, 500 = crash. Les filtrer
# reviendrait à jeter les meilleures pistes.
DEFAULT_MATCH_CODES = "200,204,301,302,307,308,401,403,405,500,502,503"

# Débit nominal grossier pour les estimations de durée (ordre de grandeur, pas
# une promesse) : dnsx résout vite, httpx est plafonné par --rate-limit.
DNSX_NOMINAL_PER_SEC = 1200

# Mode -v : intervalle du « heartbeat » de progression quand l'outil est muet
# sur stderr mais écrit dans son -o (httpx traversant des URLs mortes…).
VERBOSE_HEARTBEAT_SEC = 5

# Fichiers produits par le pipeline — sert aussi au nettoyage (--clean).
ARTIFACT_NAMES = [
    "01_subfinder.txt",
    "02_dnsx.txt",
    "03_urlfinder.txt",
    "04_httpx_input.txt",
    "05_httpx.jsonl",
    "urls_all.txt",
    "urls_200.txt",
    "06_katana.txt",
    "all_urls.txt",
    "08_httpx2.jsonl",
    "urls_all_final.txt",
    "urls_200_final.txt",
    "07_nuclei_input.txt",
    "nuclei.txt",
    "urls_tree.html",
]

_VERBOSE = False


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


def count_lines(path: Path) -> int:
    """Compte les lignes en binaire — rapide même sur des fichiers volumineux."""
    try:
        with path.open("rb") as handle:
            return sum(chunk.count(b"\n") for chunk in iter(lambda: handle.read(1 << 20), b""))
    except OSError:
        return 0


def format_eta(count: int, per_second: float) -> Optional[str]:
    if count <= 0 or per_second <= 0:
        return None
    return human_duration(count / per_second)


def announce_eta(label: str, count: int, per_second: float, note: str) -> None:
    eta = format_eta(count, per_second)
    if eta:
        console.print(f"  [dim]≈ {eta} estimé · {count} {note}[/dim]")


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
    "httpx #2": "🔁", "katana": "🧭", "nuclei": "💥", "report": "🌳",
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


def print_summary(rows: Sequence[tuple[str, int, float]], total_elapsed: float) -> None:
    table = Table(
        title=f"[bold green]✓ Terminé en {human_duration(total_elapsed)}[/]",
        box=box.ROUNDED, border_style="green", header_style="bold #38bdf8",
        title_justify="left", expand=False, padding=(0, 2),
    )
    table.add_column("étape")
    table.add_column("résultat", justify="right", style="bold")
    table.add_column("temps", justify="right", style="dim")
    for name, count, elapsed in rows:
        icon = STAGE_ICONS.get(name, "•")
        table.add_row(f"{icon} {name}", f"{count:,}".replace(",", " "), human_duration(elapsed))
    console.print()
    console.print(table)


# --------------------------------------------------------------------------- #
# Exécution des outils
# --------------------------------------------------------------------------- #


def run_command(
    command: Sequence[str],
    label: str,
    watch: Optional[Path] = None,
    timeout: Optional[int] = None,
    stdout_to: Optional[Path] = None,
    silent: bool = True,
) -> tuple[int, float, str]:
    """Lance un outil sans tuer le pipeline sur un exit code non nul.

    Mode normal : spinner Rich avec compteur de lignes live + temps écoulé, pour
    qu'un scan long (httpx sur 8000 hôtes…) montre en permanence qu'il tourne.
    Mode --verbose : flux stderr de l'outil en direct, sans spinner.

    `stdout_to` redirige la sortie standard vers un fichier (au lieu de la jeter) :
    on capture ainsi directement ce que l'outil imprime, sans dépendre de son -o.

    Retourne (code_retour, secondes, stderr_capturé).
    """
    full = list(command)
    if silent and not _VERBOSE and "-silent" not in full:
        full.append("-silent")

    start = time.monotonic()
    out_handle = open(stdout_to, "w", encoding="utf-8") if stdout_to is not None else None
    out_target = out_handle if out_handle is not None else subprocess.DEVNULL

    try:
        if _VERBOSE:
            console.print(f"[dim cyan]$ {' '.join(full)}[/dim cyan]")
            try:
                proc = subprocess.Popen(full, stderr=subprocess.PIPE, stdout=out_target, text=True, encoding="utf-8", errors="replace", bufsize=1)
            except FileNotFoundError:
                console.print(f"[bold red]Binaire introuvable :[/bold red] {full[0]}")
                return 127, 0.0, ""
            assert proc.stderr is not None
            # stderr streamé en direct par un thread ; en parallèle un heartbeat
            # de progression, sinon un outil muet sur stderr (httpx écrivant dans
            # -o) paraît figé pendant des minutes.
            def _drain() -> None:
                for line in proc.stderr:  # type: ignore[union-attr]
                    console.print(f"[dim]  {label} │ {line.rstrip()}[/dim]")

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
                if elapsed - last_beat >= VERBOSE_HEARTBEAT_SEC:
                    console.print(f"[dim]  {label} · {count} lignes · {human_duration(elapsed)}…[/dim]")
                    last_beat = elapsed
                time.sleep(0.5)
            drainer.join(timeout=1)
            elapsed = time.monotonic() - start
            if killed:
                console.print(f"[bold yellow]Timeout[/bold yellow] sur {label} après {human_duration(elapsed)}")
                return 124, elapsed, ""
            return proc.returncode, elapsed, ""

        try:
            proc = subprocess.Popen(full, stderr=subprocess.PIPE, stdout=out_target, text=True, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            console.print(f"[bold red]Binaire introuvable :[/bold red] {full[0]}")
            return 127, 0.0, ""

        stderr_tail: List[str] = []
        assert proc.stderr is not None
        drainer = threading.Thread(target=lambda: stderr_tail.extend(proc.stderr.readlines()), daemon=True)
        drainer.start()

        last_size = -1
        count = 0
        killed = False
        with console.status(f"[cyan]{label}[/cyan] démarrage…", spinner="dots") as status:
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
                status.update(
                    f"[cyan]{label}[/cyan] · [bold]{count}[/bold] lignes · {human_duration(elapsed)}"
                )
                time.sleep(0.4)

        drainer.join(timeout=1)
    finally:
        if out_handle is not None:
            out_handle.close()

    elapsed = time.monotonic() - start
    stderr_text = "".join(stderr_tail)
    if killed:
        console.print(f"[bold yellow]Timeout[/bold yellow] sur {label} après {human_duration(elapsed)}")
        return 124, elapsed, stderr_text

    rc = proc.returncode
    if rc != 0 and stderr_tail:
        console.print(f"[yellow]{label} exit {rc}[/yellow] : {stderr_text.strip()[:400]}")
    return rc, elapsed, stderr_text


def report(count: int, path: Path, elapsed: float) -> None:
    color = "green" if count else "yellow"
    console.print(f"  [{color}]→ {count} entrées[/{color}] · {human_duration(elapsed)} · {path.name}")


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


# --------------------------------------------------------------------------- #
# Fichiers
# --------------------------------------------------------------------------- #


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


def merge_files(sources: Sequence[Path], destination: Path) -> int:
    combined: List[str] = []
    for source in sources:
        combined.extend(read_lines(source))
    return write_lines(destination, combined)


def host_of(url: str) -> str:
    """Hostname d'une URL ou d'un `host[:port]`, sans port ni userinfo, en minuscules."""
    netloc = urlparse(url).netloc if "://" in url else url.split("/", 1)[0]
    netloc = netloc.rsplit("@", 1)[-1]  # retire un éventuel user:pass@
    host = netloc.split(":", 1)[0]      # retire le port
    return host.strip().strip(".").lower()


def in_scope(url: str, apexes: Sequence[str]) -> bool:
    """True si l'hôte de `url` est l'un des `apexes` ou un de leurs sous-domaines."""
    host = host_of(url)
    return bool(host) and any(host == a or host.endswith("." + a) for a in apexes)


def scope_urls(lines: Sequence[str], apexes: Sequence[str]) -> List[str]:
    return [line for line in lines if in_scope(line, apexes)]


def clean_live_urls(urls_all_file: Path, fallback_file: Path) -> List[str]:
    """URLs vivantes propres. urls_all.txt est annoté (`url [code] [titre]…`) :
    on ne garde que le 1er token (l'URL). Repli sur la carte finale si absent."""
    if urls_all_file.exists() and count_lines(urls_all_file):
        raw = [line.split()[0] for line in read_lines(urls_all_file)]
    else:
        raw = read_lines(fallback_file)
    return [u for u in raw if u.startswith(("http://", "https://"))]


def dedupe_hosts(urls: Sequence[str]) -> List[str]:
    """Réduit une liste d'URLs à des racines `scheme://host[:port]` uniques."""
    seen: set = set()
    roots: List[str] = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.netloc:
            continue
        key = parsed.netloc.lower()
        if key not in seen:
            seen.add(key)
            roots.append(f"{parsed.scheme}://{parsed.netloc}")
    return roots


def clean_artifacts(output: Path) -> None:
    removed = 0
    for name in ARTIFACT_NAMES:
        target = output / name
        if target.exists():
            try:
                target.unlink()
                removed += 1
            except OSError as exc:
                console.print(f"[yellow]Impossible de supprimer {target.name} : {exc}[/yellow]")
    console.print(f"[dim]Nettoyage : {removed} ancien(s) fichier(s) supprimé(s).[/dim]\n")


# --------------------------------------------------------------------------- #
# Étapes
# --------------------------------------------------------------------------- #


def stage_subfinder(target: str, destination: Path, all_sources: bool) -> tuple[int, float]:
    command = ["subfinder", "-d", target, "-o", str(destination)]
    if all_sources:
        command.append("-all")
    _, elapsed, _ = run_command(command, "subfinder", watch=destination)
    return write_lines(destination, read_lines(destination)), elapsed


def load_provided_subdomains(spec: str) -> List[str]:
    """Parse --subdomains : chemin de fichier (un hôte par ligne) ou liste
    séparée par des virgules/espaces. Un hôte peut aussi être une URL complète
    (http(s)://...) — seul le nom d'hôte sera gardé par les étapes suivantes."""
    spec = spec.strip()
    if not spec:
        return []
    candidate = Path(spec)
    if candidate.is_file():
        return read_lines(candidate)
    return [h.strip() for h in spec.replace("\n", ",").replace(" ", ",").split(",") if h.strip()]


def stage_dnsx(source: Path, destination: Path, target: str, wildcard: bool) -> tuple[int, float]:
    command = ["dnsx", "-l", str(source), "-o", str(destination)]
    if wildcard:
        # Sans -wd, un *.cible.com fait passer tous les faux sous-domaines.
        command += ["-wd", target]
    _, elapsed, _ = run_command(command, "dnsx", watch=destination)
    return write_lines(destination, read_lines(destination)), elapsed


def stage_urlfinder(
    target: str, destination: Path, retries: int, retry_wait: int, all_sources: bool
) -> tuple[int, float, str]:
    """urlfinder tape des archives publiques (Wayback…) souvent rate-limitées :
    un run peut rendre 0 — ou une fraction — alors qu'un autre en rend des milliers.

    Choix importants :

    - `-all` par défaut : sans lui urlfinder n'interroge qu'un sous-ensemble curé
      de sources, ce qui explique un « 79 au lieu de 19000 ». On veut le maximum.
    - **pas de `-silent`, mais `-v`** : c'est le seul moyen de voir la sortie par
      source ([INF] Found N, [WRN] rate limited…) et donc de savoir *pourquoi*
      un run est maigre. Les URLs propres passent par `-o`, indépendant du silent.
    - Aucun timeout : urlfinder tourne autant qu'il veut (un run sain prend 2+ min).
    - Retry sur résultat vide, délai progressif (`retry_wait` × n°), on garde le
      meilleur essai pour ne jamais régresser.
    """
    attempt_file = destination.with_name(destination.name + ".attempt")
    best_urls: List[str] = []
    total_elapsed = 0.0
    last_stderr = ""

    for attempt in range(retries + 1):
        if attempt:
            wait = retry_wait * attempt
            console.print(
                f"  [yellow]urlfinder vide — nouvel essai {attempt}/{retries} dans {human_duration(wait)}…[/yellow]"
            )
            time.sleep(wait)
        command = ["urlfinder", "-d", target, "-v", "-o", str(attempt_file)]
        if all_sources:
            command.append("-all")
        # -v sur stderr (diagnostic par source), URLs propres dans -o.
        _, elapsed, stderr = run_command(command, "urlfinder", watch=attempt_file, silent=False)
        total_elapsed += elapsed
        last_stderr = stderr or last_stderr
        urls = [line for line in read_lines(attempt_file) if line.startswith(("http://", "https://"))]
        if len(urls) > len(best_urls):
            best_urls = urls
        if best_urls:
            break

    count = write_lines(destination, best_urls)
    try:
        attempt_file.unlink()
    except OSError:
        pass

    return count, total_elapsed, last_stderr


def stage_httpx(
    binary: str,
    source: Path,
    jsonl_file: Path,
    all_file: Path,
    ok_file: Path,
    match_codes: str,
    threads: int,
    rate_limit: int,
) -> tuple[int, int, float]:
    _, elapsed, _ = run_command(
        [
            binary,
            "-l",
            str(source),
            "-json",
            "-status-code",
            "-title",
            "-content-length",
            "-tech-detect",
            "-match-code",
            match_codes,
            "-threads",
            str(threads),
            "-rate-limit",
            str(rate_limit),
            "-o",
            str(jsonl_file),
        ],
        "httpx",
        watch=jsonl_file,
    )
    total, alive = split_httpx_output(jsonl_file, all_file, ok_file)
    return total, alive, elapsed


def split_httpx_output(jsonl_file: Path, all_file: Path, ok_file: Path) -> tuple[int, int]:
    annotated: List[str] = []
    alive: List[str] = []
    for line in read_lines(jsonl_file):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
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
    return write_lines(all_file, annotated), write_lines(ok_file, alive)


def stage_katana(
    source: Path,
    destination: Path,
    depth: int,
    scope: str,
    js_crawl: bool,
    rate_limit: int,
    concurrency: int,
    max_pages: int,
    duration: str,
    ignore_query: bool,
    filter_similar: bool,
) -> tuple[int, float]:
    command = [
        "katana",
        "-list",
        str(source),
        "-depth",
        str(depth),
        # Les archives ramènent des hôtes tiers : sans périmètre on sort du scope.
        "-field-scope",
        scope,
        "-rate-limit",
        str(rate_limit),
        "-concurrency",
        str(concurrency),
    ]
    # Garde-fous anti-explosion : sans eux, les variantes de query params et les
    # chemins numérotés (/evenement/1..900) font grimper à 100k+ lignes.
    if filter_similar:
        command.append("-filter-similar")  # collapse /x/1 /x/2 … en un motif
    if ignore_query:
        command.append("-ignore-query-params")  # collapse ?page=1,2,3…
    if max_pages > 0:
        command += ["-max-domain-pages", str(max_pages)]  # plafond dur par domaine
    if duration.strip():
        command += ["-crawl-duration", duration.strip()]  # coupe après la durée
    if js_crawl:
        command.append("-jc")
    command += ["-o", str(destination)]
    _, elapsed, _ = run_command(command, "katana", watch=destination)
    return write_lines(destination, read_lines(destination)), elapsed


def stage_nuclei(
    source: Path,
    destination: Path,
    mode: str,
    severity: str,
    rate_limit: int,
    max_host_error: int,
    timeout: int,
    concurrency: int,
    retries: int,
) -> tuple[int, float]:
    """Trois façons de piloter le coût (cibles × templates × requêtes) :

    - auto    : `-as` (Wappalyzer → tags) ne lance que les templates matchant la
                stack détectée. Rapide, précis, peu de bruit. Défaut.
    - curated : un set choisi (cve/exposure/misconfig…), sans les catégories qui
                explosent le compteur (fuzz/dos/intrusive).
    - full    : tout ce que couvre --nuclei-severity. Lent, réservé à peu d'hôtes.

    `-timeout`/`-retries`/`-mhe` bornent le temps perdu sur les hôtes lents ou
    morts ; `-c` parallélise les templates.
    """
    command = ["nuclei", "-l", str(source)]
    if mode == "auto":
        command += ["-as", "-severity", severity]
    elif mode == "curated":
        command += [
            "-tags", "cve,exposure,misconfig,takeover,default-login",
            "-exclude-tags", "fuzz,dos,intrusive",
            "-severity", severity,
        ]
    else:  # full
        command += ["-severity", severity]
    command += [
        "-rate-limit", str(rate_limit),
        "-concurrency", str(concurrency),
        "-timeout", str(timeout),
        "-retries", str(retries),
        # -mhe : abandonne un hôte après N erreurs (défaut nuclei = 30, trop sur
        # des cibles d'archive souvent mortes).
        "-max-host-error", str(max_host_error),
        "-o", str(destination),
    ]
    _, elapsed, _ = run_command(command, "nuclei", watch=destination)
    return len(read_lines(destination)), elapsed


# --------------------------------------------------------------------------- #
# Vérification des outils
# --------------------------------------------------------------------------- #


def check_tools() -> List[str]:
    missing: List[str] = []
    for tool in REQUIRED_TOOLS:
        if tool == "httpx":
            path = resolve_httpx()
            if path:
                console.print(f"[green]httpx[/green] (ProjectDiscovery) : {path}")
            else:
                shadow = shutil.which("httpx")
                if shadow:
                    console.print(
                        f"[red]httpx[/red] : {shadow} n'est [bold]pas[/bold] celui de "
                        "ProjectDiscovery (probablement le client HTTP Python)"
                    )
                else:
                    console.print("[red]httpx[/red] introuvable")
                missing.append(tool)
            continue
        path = shutil.which(tool)
        if path:
            console.print(f"[green]{tool}[/green] : {path}")
        else:
            console.print(f"[red]{tool}[/red] introuvable")
            missing.append(tool)

    nuclei_path = shutil.which("nuclei")
    console.print(
        f"[green]nuclei[/green] (optionnel) : {nuclei_path}"
        if nuclei_path
        else "[dim]nuclei (optionnel) introuvable — nécessaire seulement avec --nuclei[/dim]"
    )
    return missing


# --------------------------------------------------------------------------- #
# Sous-commande report
# --------------------------------------------------------------------------- #


def run_report_command(path_arg: Optional[Path]) -> None:
    """`recon_mano report <dossier|fichier>` — (re)génère l'arbre HTML.

    Sur un dossier : cherche la meilleure liste de 200 dedans → urls_tree.html.
    Sur un fichier : le transforme directement en <fichier>.html.
    """
    if path_arg is None:
        console.print("[bold]Usage :[/bold] recon_mano report [cyan]<dossier|fichier_urls>[/cyan]")
        raise typer.Exit(code=2)

    path = Path(path_arg)
    if path.is_dir():
        candidates = ["urls_200_final.txt", "urls_200.txt", "urls_all_final.txt", "all_urls.txt", "06_katana.txt"]
        source = next((path / name for name in candidates if (path / name).exists() and count_lines(path / name)), None)
        if source is None:
            console.print(f"[bold red]Aucune liste d'URLs dans {path}[/bold red] (urls_200_final.txt attendu).")
            raise typer.Exit(code=1)
        dest = path / "urls_tree.html"
        title = path.name or "urls"
    elif path.is_file():
        source = path
        dest = path.with_suffix(".html")
        title = path.parent.name or path.stem
    else:
        console.print(f"[bold red]Introuvable :[/bold red] {path}")
        raise typer.Exit(code=1)

    count = write_tree_report(source, dest, f"{title} · {source.stem}")
    console.print(f"[green]{count} URLs[/green] → [bold]{dest}[/bold] [dim](source : {source.name})[/dim]")
    raise typer.Exit()


# --------------------------------------------------------------------------- #
# Commande principale
# --------------------------------------------------------------------------- #


def main(
    target: Optional[str] = typer.Argument(None, help="Domaine apex, ou 'report' pour (re)générer l'arbre HTML"),
    output: Optional[Path] = typer.Argument(None, help="Dossier de sortie (ou dossier/fichier si target=report)"),
    check: bool = typer.Option(False, "--check", help="Vérifie la présence des outils puis quitte"),
    clean: bool = typer.Option(False, "--clean", help="Supprime les anciens fichiers de sortie avant de lancer"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Affiche les commandes et le flux des outils"),
    all_sources: bool = typer.Option(False, "--all-sources", help="subfinder -all (plus lent)"),
    subdomains: str = typer.Option(
        "", "--subdomains",
        help="Sous-domaines déjà connus (ex: trouvés via ffuf) : fichier (un par ligne) ou liste "
             "séparée par des virgules. Si fourni, l'étape subfinder est ignorée et le scan part "
             "directement de cette liste.",
    ),
    wildcard_filter: bool = typer.Option(
        True, "--wildcard-filter/--no-wildcard-filter", help="dnsx -wd (filtrage wildcard)"
    ),
    match_codes: str = typer.Option(DEFAULT_MATCH_CODES, "--match-codes", help="httpx -mc"),
    depth: int = typer.Option(2, "--depth", help="Profondeur katana (seeds déjà profondes)"),
    scope: str = typer.Option("rdn", "--scope", help="katana -fs : rdn, fqdn, dn ou regex"),
    js_crawl: bool = typer.Option(False, "--js-crawl", help="katana -jc (endpoints JS, non validés)"),
    katana_max_pages: int = typer.Option(3000, "--katana-max-pages", help="Plafond pages/domaine katana (-mdp). 0 = illimité"),
    katana_duration: str = typer.Option("10m", "--katana-duration", help="Durée max du crawl katana (-ct, ex: 10m). Vide = illimité"),
    katana_ignore_query: bool = typer.Option(False, "--katana-ignore-query", help="katana -iqp : collapse les variantes de query params"),
    katana_filter_similar: bool = typer.Option(
        True, "--katana-filter-similar/--no-katana-filter-similar", help="katana -fsu : collapse les chemins similaires (/x/1../x/900)"
    ),
    urlfinder_all: bool = typer.Option(True, "--urlfinder-all/--urlfinder-curated", help="urlfinder -all : toutes les sources (défaut) vs sous-ensemble curé"),
    urlfinder_retries: int = typer.Option(1, "--urlfinder-retries", help="Réessais si urlfinder rend 0 (sources rate-limitées)"),
    urlfinder_retry_wait: int = typer.Option(30, "--urlfinder-retry-wait", help="Base du délai entre essais urlfinder, en s (progressif ×n)"),
    threads: int = typer.Option(50, "--threads", help="Threads httpx"),
    rate_limit: int = typer.Option(150, "--rate-limit", help="Requêtes/seconde"),
    concurrency: int = typer.Option(10, "--concurrency", help="Concurrence katana"),
    httpx_bin: Optional[str] = typer.Option(None, "--httpx-bin", help="Chemin du httpx ProjectDiscovery"),
    revalidate: bool = typer.Option(
        True, "--revalidate/--no-revalidate",
        help="Passe httpx #2 sur la sortie katana : codes réels + liste complète des 200",
    ),
    tree_report: bool = typer.Option(
        True, "--tree/--no-tree", help="Génère urls_tree.html : arbre interactif repliable des 200"
    ),
    in_scope_domains: str = typer.Option(
        "", "--in-scope",
        help="Restreindre à ces domaines (séparés par des virgules, ex: devinci.fr,esilv.fr,emlv.fr). "
             "Vide = tout garder. Fortement recommandé avec --nuclei.",
    ),
    nuclei: bool = typer.Option(False, "--nuclei", help="Lance nuclei sur les hôtes/URLs vivants"),
    nuclei_mode: str = typer.Option(
        "auto", "--nuclei-mode",
        help="auto (-as tech-aware, défaut) | curated (tags CVE/expo/misconfig, sans fuzz) | full (tout selon --nuclei-severity)",
    ),
    nuclei_targets: Optional[str] = typer.Option(
        None, "--nuclei-targets",
        help="hosts (hôtes vivants dédupliqués, défaut) | urls (toutes les URLs vivantes). Absent + terminal → demandé.",
    ),
    nuclei_severity: str = typer.Option("medium,high,critical", "--nuclei-severity"),
    nuclei_rate_limit: int = typer.Option(150, "--nuclei-rate-limit", help="nuclei -rate-limit"),
    nuclei_max_host_error: int = typer.Option(
        10, "--nuclei-max-host-error", help="nuclei -mhe : abandonne un hôte après N erreurs (nuclei=30)"
    ),
    nuclei_timeout: int = typer.Option(5, "--nuclei-timeout", help="nuclei -timeout (s) : ne pas s'attarder sur un hôte lent"),
    nuclei_concurrency: int = typer.Option(25, "--nuclei-concurrency", help="nuclei -c : templates en parallèle"),
    nuclei_retries: int = typer.Option(1, "--nuclei-retries", help="nuclei -retries"),
    skip_dnsx: bool = typer.Option(False, "--skip-dnsx"),
    skip_urlfinder: bool = typer.Option(False, "--skip-urlfinder"),
    skip_httpx: bool = typer.Option(False, "--skip-httpx"),
    skip_katana: bool = typer.Option(False, "--skip-katana"),
):
    """Recon Mano — subfinder → dnsx → urlfinder → httpx → katana → [nuclei].

    Exemple : recon_mano exemple.com sortie --nuclei
    """
    global _VERBOSE
    _VERBOSE = verbose

    # Pseudo-sous-commande : `recon_mano report <dossier|fichier>`. On la détecte
    # ici car le CLI est mono-commande (positionnels libres, pas de vraies
    # sous-commandes). 'report' n'est pas un domaine valide → aucune collision.
    if target == "report":
        run_report_command(output)

    if check:
        missing = check_tools()
        if missing:
            console.print(f"\n[bold red]Manquant : {', '.join(missing)}[/bold red]")
            raise typer.Exit(code=1)
        console.print("\n[bold green]Tous les outils requis sont disponibles.[/bold green]")
        raise typer.Exit()

    if not target:
        console.print(
            "[bold]Usage :[/bold] recon_mano [cyan]cible.com[/cyan] [cyan]nom_sortie[/cyan] [dim][options][/dim]\n"
            "Exemples :\n"
            "  recon_mano exemple.com sortie\n"
            "  recon_mano exemple.com sortie --nuclei --clean\n"
            "  recon_mano report exemple.com   [dim](re)génère l'arbre HTML[/dim]\n"
            "  recon_mano --check\n"
            "Aide complète : recon_mano --help"
        )
        raise typer.Exit(code=1)

    if nuclei_mode not in {"auto", "curated", "full"}:
        console.print("[bold red]--nuclei-mode :[/bold red] auto | curated | full")
        raise typer.Exit(code=2)
    if nuclei_targets is not None and nuclei_targets not in {"hosts", "urls"}:
        console.print("[bold red]--nuclei-targets :[/bold red] hosts | urls")
        raise typer.Exit(code=2)

    # Sortie par défaut = nom de la cible assaini.
    if output is None:
        output = Path(target.replace("/", "_").replace(":", "_"))
    output.mkdir(parents=True, exist_ok=True)

    pipeline_start = time.monotonic()

    subfinder_file = output / "01_subfinder.txt"
    dnsx_file = output / "02_dnsx.txt"
    urlfinder_file = output / "03_urlfinder.txt"
    httpx_input_file = output / "04_httpx_input.txt"
    httpx_jsonl_file = output / "05_httpx.jsonl"
    urls_all_file = output / "urls_all.txt"
    urls_200_file = output / "urls_200.txt"
    katana_file = output / "06_katana.txt"
    final_file = output / "all_urls.txt"
    httpx2_jsonl_file = output / "08_httpx2.jsonl"
    urls_all_final_file = output / "urls_all_final.txt"
    urls_200_final_file = output / "urls_200_final.txt"
    nuclei_input_file = output / "07_nuclei_input.txt"
    nuclei_file = output / "nuclei.txt"
    tree_html_file = output / "urls_tree.html"

    scan_bits = []
    if nuclei:
        scan_bits.append(f"nuclei {nuclei_mode}·{nuclei_targets or 'demandé'}")
    scan_bits.append(f"revalidate {'on' if revalidate else 'off'}")
    if in_scope_domains.strip():
        scan_bits.append(f"scope {in_scope_domains}")
    print_banner([("🎯 cible ", target), ("📁 sortie", str(output)), ("⚙️  config", " · ".join(scan_bits))])

    summary: List[tuple[str, int, float]] = []
    if clean:
        clean_artifacts(output)

    httpx_path: Optional[str] = None
    if not skip_httpx:
        httpx_path = resolve_httpx(httpx_bin)
        if not httpx_path:
            console.print(
                "[bold red]httpx (ProjectDiscovery) introuvable.[/bold red] "
                "Un `httpx` du PATH peut être le client HTTP Python.\n"
                "Installe : [cyan]go install github.com/projectdiscovery/httpx/cmd/httpx@latest[/cyan] "
                "ou passe [cyan]--httpx-bin[/cyan]."
            )
            raise typer.Exit(code=1)

    # --- Branche 1 : hôtes -------------------------------------------------- #
    provided_hosts = load_provided_subdomains(subdomains)
    if provided_hosts:
        stage_header("1/6", "subfinder", "sous-domaines fournis (--subdomains)")
        count = write_lines(subfinder_file, provided_hosts)
        elapsed = 0.0
        report(count, subfinder_file, elapsed)
        console.print("  [dim]Liste fournie — étape subfinder ignorée.[/dim]")
    else:
        stage_header("1/6", "subfinder", "sous-domaines théoriques")
        count, elapsed = stage_subfinder(target, subfinder_file, all_sources)
        report(count, subfinder_file, elapsed)
    summary.append(("subfinder", count, elapsed))
    if not count:
        console.print("[bold red]Aucun sous-domaine trouvé, arrêt.[/bold red]")
        raise typer.Exit(code=1)

    hosts_file = subfinder_file
    if skip_dnsx:
        console.print("[dim]2 · dnsx ignoré — on repart de subfinder[/dim]")
    else:
        stage_header("2/6", "dnsx", "validation DNS + filtrage wildcard")
        announce_eta("dnsx", count, DNSX_NOMINAL_PER_SEC, "hôtes à résoudre")
        n, elapsed = stage_dnsx(subfinder_file, dnsx_file, target, wildcard_filter)
        report(n, dnsx_file, elapsed)
        summary.append(("dnsx", n, elapsed))
        if n:
            hosts_file = dnsx_file
        else:
            console.print("[yellow]dnsx sans résultat — on garde la liste subfinder[/yellow]")

    # --- Branche 2 : archives ----------------------------------------------- #
    if skip_urlfinder:
        console.print("[dim]3 · urlfinder ignoré[/dim]")
    else:
        mode = "toutes sources (-all)" if urlfinder_all else "sources curées"
        stage_header("3/6", "urlfinder", f"chemins historiques (apex) · {mode}")
        n, elapsed, uf_stderr = stage_urlfinder(
            target, urlfinder_file, urlfinder_retries, urlfinder_retry_wait, urlfinder_all
        )
        report(n, urlfinder_file, elapsed)
        summary.append(("urlfinder", n, elapsed))
        lines = [line.strip() for line in uf_stderr.splitlines() if line.strip()]
        # Le récap propre de l'outil ("Found N urls … in T") : toujours affiché.
        for line in [l for l in lines if "found" in l.lower() and "url" in l.lower()][-1:]:
            console.print(f"  [dim]urlfinder : {line}[/dim]")
        # Erreurs explicites de sources (429, timeouts…).
        problems = [
            line for line in lines
            if any(tag in line for tag in ("[WRN]", "[ERR]", "[FTL]"))
            or "rate" in line.lower() or "limit" in line.lower()
        ]
        if problems:
            console.print("  [yellow]urlfinder — sources en échec/limitées :[/yellow]")
            for line in problems[:8]:
                console.print(f"    [dim]{line}[/dim]")
        elif n < 500:
            # Peu d'URLs SANS erreur = throttling silencieux (réponses vides en 200),
            # le cas le plus fréquent sur les archives une fois le quota IP épuisé.
            console.print(
                "  [yellow]Peu d'URLs sans erreur signalée[/yellow] — throttling silencieux probable "
                "(réponses vides en 200)."
            )
        if n < 500 or problems:
            if not urlfinder_all:
                console.print("  [dim]Garder --urlfinder-all (défaut) pour toutes les sources.[/dim]")
            console.print(
                "  [dim]Pour du volume : laisser la fenêtre de quota se reposer, ou ajouter des clés "
                "d'API dans ~/.config/urlfinder/provider-config.yaml.[/dim]"
            )

    # --- Fusion puis passe httpx unique ------------------------------------- #
    merged = merge_files([hosts_file, urlfinder_file], httpx_input_file)
    console.print(f"\n[bold]Fusion des deux branches[/bold] → {merged} entrées\n")

    katana_seeds = httpx_input_file
    if skip_httpx:
        console.print("[dim]4 · httpx ignoré — katana partira des entrées brutes[/dim]")
    else:
        stage_header("4/6", "httpx", "validation + annotation (une seule passe)")
        announce_eta("httpx", merged, rate_limit, f"requêtes @ {rate_limit}/s (plancher)")
        total, alive, elapsed = stage_httpx(
            httpx_path,  # type: ignore[arg-type]
            httpx_input_file,
            httpx_jsonl_file,
            urls_all_file,
            urls_200_file,
            match_codes,
            threads,
            rate_limit,
        )
        report(total, urls_all_file, elapsed)
        console.print(f"  [green]→ {alive} en 200[/green] · {urls_200_file.name}")
        summary.append(("httpx", total, elapsed))
        if alive:
            katana_seeds = urls_200_file
        elif total:
            console.print("[yellow]Aucun 200 — katana repart des entrées fusionnées[/yellow]")

    # --- Crawl actif --------------------------------------------------------- #
    if skip_katana:
        console.print("[dim]5 · katana ignoré[/dim]")
    else:
        stage_header("5/6", "katana", "crawl actif depuis les seeds vivantes")
        n, elapsed = stage_katana(
            katana_seeds, katana_file, depth, scope, js_crawl, rate_limit, concurrency,
            katana_max_pages, katana_duration, katana_ignore_query, katana_filter_similar,
        )
        report(n, katana_file, elapsed)
        summary.append(("katana", n, elapsed))
        if js_crawl:
            console.print("[dim]  -jc actif : endpoints extraits du JS non requêtés, donc non validés.[/dim]")

    # --- Cartographie finale ------------------------------------------------- #
    total = merge_files([katana_seeds, katana_file], final_file)

    # Restriction de périmètre optionnelle (vide = tout gardé). Les archives font
    # entrer des hôtes tiers ; --in-scope permet de garder le groupe voulu
    # (devinci.fr,esilv.fr,emlv.fr…) et d'écarter le reste — surtout avant nuclei.
    scope_apexes = [d.strip().strip(".").lower() for d in in_scope_domains.split(",") if d.strip()]
    if scope_apexes:
        kept = scope_urls(read_lines(final_file), scope_apexes)
        dropped = total - len(kept)
        total = write_lines(final_file, kept)
        console.print(f"[dim]--in-scope {','.join(scope_apexes)} : {dropped} URLs hors périmètre écartées[/dim]")

    # --- Passe httpx #2 : valider la carte crawlée --------------------------- #
    # katana découvre des URLs par crawl mais ne connaît PAS leur code HTTP.
    # On re-teste la carte pour obtenir les statuts réels + la liste complète des
    # 200 (archives ET découvertes katana), et une surface vivante propre.
    live_all_file, live_200_file = urls_all_file, urls_200_file
    if revalidate and not skip_katana and not skip_httpx and httpx_path and total:
        stage_header("5b", "httpx #2", "validation de la carte crawlée (codes réels)")
        announce_eta("httpx", total, rate_limit, f"requêtes @ {rate_limit}/s (plancher)")
        total_v, alive_v, elapsed = stage_httpx(
            httpx_path, final_file, httpx2_jsonl_file,
            urls_all_final_file, urls_200_final_file,
            match_codes, threads, rate_limit,
        )
        report(total_v, urls_all_final_file, elapsed)
        console.print(f"  [green]→ {alive_v} en 200[/green] · {urls_200_final_file.name}")
        summary.append(("httpx #2", total_v, elapsed))
        live_all_file, live_200_file = urls_all_final_file, urls_200_final_file

    if tree_report and live_200_file.exists() and count_lines(live_200_file):
        write_tree_report(live_200_file, tree_html_file, f"{target} · 200")

    console.print()
    console.rule("[bold green]livrables[/]", align="left", style="green")
    console.print(f"  🗺️  [dim]carte[/dim]            [bold]{final_file}[/bold] [dim]({total} URLs)[/dim]")
    console.print(f"  📊 [dim]surface vivante[/dim]  [bold]{live_all_file}[/bold]")
    console.print(f"  🎯 [dim]endpoints 200[/dim]    [bold]{live_200_file}[/bold]")
    if tree_html_file.exists():
        console.print(f"  🌳 [dim]arbre HTML[/dim]       [bold]{tree_html_file}[/bold]")

    if nuclei:
        if not shutil.which("nuclei"):
            console.print("[bold red]nuclei introuvable dans le PATH.[/bold red]")
            raise typer.Exit(code=1)

        # Cibles = surface VIVANTE validée (après httpx #2 si disponible), jamais
        # le dump urlfinder brut : les URLs mortes rendaient nuclei interminable.
        live_urls = clean_live_urls(live_all_file, final_file)
        if scope_apexes:
            live_urls = scope_urls(live_urls, scope_apexes)
        hosts = dedupe_hosts(live_urls)

        # hosts (défaut) vs urls : flag au départ, sinon demandé ici si terminal.
        targets_mode = nuclei_targets
        if targets_mode is None:
            if sys.stdin.isatty():
                choice = typer.prompt(
                    f"nuclei — cibles ? [1] hôtes vivants ({len(hosts)}) · [2] toutes les URLs vivantes ({len(live_urls)})",
                    default="1",
                )
                targets_mode = "urls" if str(choice).strip() == "2" else "hosts"
            else:
                targets_mode = "hosts"

        chosen = hosts if targets_mode == "hosts" else live_urls
        count_in = write_lines(nuclei_input_file, chosen)
        if not count_in:
            console.print("[yellow]Aucune cible vivante pour nuclei — étape ignorée.[/yellow]")
        else:
            if not scope_apexes:
                console.print(
                    "[yellow]Rappel :[/yellow] payloads actifs sur [bold]"
                    f"{count_in}[/bold] cibles, domaines tiers d'archive possibles. "
                    "Restreins avec [cyan]--in-scope[/cyan]."
                )
            stage_header("6/6", "nuclei", f"mode {nuclei_mode} · {targets_mode} ({count_in} cibles)")
            console.print(f"  [dim]sévérité {nuclei_severity} · -mhe {nuclei_max_host_error} · -timeout {nuclei_timeout}s[/dim]")
            n, elapsed = stage_nuclei(
                nuclei_input_file, nuclei_file, nuclei_mode,
                nuclei_severity, nuclei_rate_limit, nuclei_max_host_error,
                nuclei_timeout, nuclei_concurrency, nuclei_retries,
            )
            report(n, nuclei_file, elapsed)
            summary.append(("nuclei", n, elapsed))

    print_summary(summary, time.monotonic() - pipeline_start)


def entrypoint() -> None:
    """Point d'entrée console : commande unique avec arguments positionnels."""
    typer.run(main)


if __name__ == "__main__":
    entrypoint()
