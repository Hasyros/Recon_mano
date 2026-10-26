"""Les étapes du pipeline, portées en modules indépendants (voir `pipeline.py`).

DAG (une flèche = « doit être terminé avant »)::

    subfinder ── dnsx ──┐
                        ├─ httpx ─ katana ─ merge_map ─ httpx2 ─┬─ tree
    urlfinder ──────────┘                                       └─ nuclei (opt-in)

Chaque fonction `run_*` reproduit l'étape historique de `main()` : mêmes fichiers,
même filtrage de périmètre, mêmes replis. Ce qui change : elle lit l'état laissé
par ses dépendances dans `ctx.state` (`hosts_file`, `httpx_live`…) au lieu de
variables locales, et journalise via `ctx.log` (imprimé d'un bloc en fin de module).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from . import runner
from .io_utils import count_lines, read_lines, write_lines
from .liveness import DEFAULT_LIVE_CODES, clean_live_urls, split_httpx_output
from .pipeline import Context, Module, ModuleError, ModuleResult, ModuleSkipped
from .report import write_report as write_tree_report
from .scope import ScopeFilter
from .ui import STAGE_ICONS, console, eta_line, human_duration, report

# Large volontairement : 401/403 = endpoints protégés, 500 = crash. Les filtrer
# reviendrait à jeter les meilleures pistes.
DEFAULT_MATCH_CODES = "200,204,301,302,307,308,401,403,405,500,502,503"

# Débit nominal grossier pour les estimations de durée (ordre de grandeur, pas
# une promesse) : dnsx résout vite, httpx est plafonné par --rate-limit.
DNSX_NOMINAL_PER_SEC = 1200

Log = Callable[[Optional[str]], None]


# --------------------------------------------------------------------------- #
# Options (copie typée des paramètres CLI utiles aux modules)
# --------------------------------------------------------------------------- #


@dataclass
class Options:
    target: str
    all_sources: bool = False
    subdomains: str = ""
    wildcard_filter: bool = True
    match_codes: str = DEFAULT_MATCH_CODES
    live_codes: str = DEFAULT_LIVE_CODES
    live_code_set: Optional[Set[int]] = None
    depth: int = 2
    katana_scope: str = "rdn"
    js_crawl: bool = False
    katana_max_pages: int = 3000
    katana_duration: str = "10m"
    katana_ignore_query: bool = False
    katana_filter_similar: bool = True
    urlfinder_all: bool = True
    urlfinder_retries: int = 1
    urlfinder_retry_wait: int = 30
    threads: int = 50
    rate_limit: int = 150
    concurrency: int = 10
    httpx_bin: Optional[str] = None
    revalidate: bool = True
    tree_report: bool = True
    scope_enabled: bool = True
    nuclei: bool = False
    nuclei_mode: str = "auto"
    nuclei_targets: str = "hosts"
    nuclei_severity: str = "medium,high,critical"
    nuclei_rate_limit: int = 150
    nuclei_max_host_error: int = 10
    nuclei_timeout: int = 5
    nuclei_concurrency: int = 25
    nuclei_retries: int = 1
    skip_dnsx: bool = False
    skip_urlfinder: bool = False
    skip_httpx: bool = False
    skip_katana: bool = False


# --------------------------------------------------------------------------- #
# Fichiers
# --------------------------------------------------------------------------- #


def merge_files(sources: Sequence[Path], destination: Path) -> int:
    combined: List[str] = []
    for source in sources:
        combined.extend(read_lines(source))
    return write_lines(destination, combined)


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


def apply_scope(scope_filter: ScopeFilter, path: Path, stage: str, log: Log = console.print) -> int:
    """Filtre `path` sur le périmètre (réécriture sur place) et retourne le nombre
    de lignes gardées. Signale ce qui a été écarté ; le détail est dans le TSV."""
    kept, dropped = scope_filter.filter_file(path, stage)
    if dropped:
        log_name = scope_filter.reject_log.name if scope_filter.reject_log else "rejected_scope.tsv"
        log(f"  [dim]scope : {dropped} hors périmètre écartés ({log_name})[/dim]")
    return kept


def load_provided_subdomains(spec: str) -> List[str]:
    """Parse --subdomains : chemin de fichier (un hôte par ligne) ou liste
    séparée par des virgules/espaces. Un hôte peut aussi être une URL complète
    (http(s)://...) — seul le nom d'hôte sera gardé par les étapes suivantes."""
    spec = spec.strip()
    if not spec:
        return []
    try:
        # Une longue liste virgulée dépasse souvent la limite de longueur d'un
        # nom de fichier (ENAMETOOLONG) : is_file() lève alors une OSError au
        # lieu de renvoyer False — on la traite comme « ce n'est pas un fichier ».
        is_file = Path(spec).is_file()
    except OSError:
        is_file = False
    if is_file:
        return read_lines(Path(spec))
    return [h.strip() for h in spec.replace("\n", ",").replace(" ", ",").split(",") if h.strip()]


# --------------------------------------------------------------------------- #
# Appels d'outils (une fonction par outil, sans état)
# --------------------------------------------------------------------------- #


def stage_subfinder(target: str, destination: Path, all_sources: bool, timeout: Optional[int] = None) -> Tuple[int, float]:
    command = ["subfinder", "-d", target, "-o", str(destination)]
    if all_sources:
        command.append("-all")
    _, elapsed, _ = runner.run_command(command, "subfinder", watch=destination, timeout=timeout)
    return write_lines(destination, read_lines(destination)), elapsed


def stage_dnsx(source: Path, destination: Path, target: str, wildcard: bool, timeout: Optional[int] = None) -> Tuple[int, float]:
    command = ["dnsx", "-l", str(source), "-o", str(destination)]
    if wildcard:
        # Sans -wd, un *.cible.com fait passer tous les faux sous-domaines.
        command += ["-wd", target]
    _, elapsed, _ = runner.run_command(command, "dnsx", watch=destination, timeout=timeout)
    return write_lines(destination, read_lines(destination)), elapsed


def stage_urlfinder(
    target: str,
    destination: Path,
    retries: int,
    retry_wait: int,
    all_sources: bool,
    notice: Log = console.print,
    remaining: Callable[[], Optional[int]] = lambda: None,
) -> Tuple[int, float, str]:
    """urlfinder tape des archives publiques (Wayback…) souvent rate-limitées :
    un run peut rendre 0 — ou une fraction — alors qu'un autre en rend des milliers.

    Choix importants :

    - `-all` par défaut : sans lui urlfinder n'interroge qu'un sous-ensemble curé
      de sources, ce qui explique un « 79 au lieu de 19000 ». On veut le maximum.
    - **pas de `-silent`, mais `-v`** : c'est le seul moyen de voir la sortie par
      source ([INF] Found N, [WRN] rate limited…) et donc de savoir *pourquoi*
      un run est maigre. Les URLs propres passent par `-o`, indépendant du silent.
    - Aucun timeout par défaut : urlfinder tourne autant qu'il veut (un run sain
      prend 2+ min) ; `remaining()` ne borne que si le module a une échéance.
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
            notice(f"[yellow]urlfinder vide — nouvel essai {attempt}/{retries} dans {human_duration(wait)}…[/yellow]")
            time.sleep(wait)
        command = ["urlfinder", "-d", target, "-v", "-o", str(attempt_file)]
        if all_sources:
            command.append("-all")
        # -v sur stderr (diagnostic par source), URLs propres dans -o.
        _, elapsed, stderr = runner.run_command(
            command, "urlfinder", watch=attempt_file, silent=False, timeout=remaining()
        )
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
    live_file: Path,
    match_codes: str,
    threads: int,
    rate_limit: int,
    live_codes: Optional[Set[int]] = None,
    timeout: Optional[int] = None,
    label: str = "httpx",
) -> Tuple[int, int, int, float]:
    """Une passe httpx puis éclatement : `all_file` (annoté, tous codes retenus par
    -mc), `ok_file` (200 seuls) et `live_file` (URLs nues dont le code est dans
    `live_codes` — seule liste qui alimente katana et nuclei)."""
    _, elapsed, _ = runner.run_command(
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
        label,
        watch=jsonl_file,
        timeout=timeout,
    )
    total, alive, live = split_httpx_output(jsonl_file, all_file, ok_file, live_file, live_codes)
    return total, alive, live, elapsed


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
    timeout: Optional[int] = None,
) -> Tuple[int, float]:
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
    _, elapsed, _ = runner.run_command(command, "katana", watch=destination, timeout=timeout)
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
    deadline: Optional[int] = None,
) -> Tuple[int, float]:
    """Trois façons de piloter le coût (cibles × templates × requêtes) :

    - auto    : `-as` (Wappalyzer → tags) ne lance que les templates matchant la
                stack détectée. Rapide, précis, peu de bruit. Défaut.
    - curated : un set choisi (cve/exposure/misconfig…), sans les catégories qui
                explosent le compteur (fuzz/dos/intrusive).
    - full    : tout ce que couvre --nuclei-severity. Lent, réservé à peu d'hôtes.

    `-timeout`/`-retries`/`-mhe` bornent le temps perdu sur les hôtes lents ou
    morts ; `-c` parallélise les templates. (`timeout` = celui de nuclei -timeout ;
    `deadline` = échéance du module, en secondes.)
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
    _, elapsed, _ = runner.run_command(command, "nuclei", watch=destination, timeout=deadline)
    return len(read_lines(destination)), elapsed


# --------------------------------------------------------------------------- #
# État partagé entre modules
# --------------------------------------------------------------------------- #


def _hosts_available(ctx: Context) -> bool:
    """subfinder a rendu au moins un hôte en périmètre (sinon aval : rien à faire)."""
    return ctx.state.get("subfinder_count", 0) > 0


def ensure_httpx_input(ctx: Context) -> int:
    """Fusion hôtes (dnsx, sinon subfinder) + URLs urlfinder → 04_httpx_input.txt.

    Faite par httpx ; katana la fait aussi si l'utilisateur a désactivé httpx
    (repli historique). Idempotente : une seule fusion par run.
    """
    with ctx.lock:
        if "merged" not in ctx.state:
            hosts_file = ctx.state.get("hosts_file", ctx.paths["subfinder"])
            merged = merge_files([hosts_file, ctx.paths["urlfinder"]], ctx.paths["httpx_input"])
            ctx.state["merged"] = merged
            ctx.log(f"\n[bold]Fusion des deux branches[/bold] → {merged} entrées")
        return ctx.state["merged"]


def katana_seeds(ctx: Context) -> Tuple[Optional[Path], str]:
    """Seeds de katana (et de la carte) : (chemin, "") ou (None, raison).

    - httpx a tourné et trouvé du vivant → urls_live.txt ;
    - httpx désactivé PAR L'UTILISATEUR (--skip-httpx) → entrées brutes fusionnées
      (repli historique) ;
    - sinon (httpx sans URL vivante, en échec, binaire absent) → rien : on ne
      crawle jamais des cibles non confirmées.
    """
    if ctx.options.skip_httpx:
        ensure_httpx_input(ctx)
        return ctx.paths["httpx_input"], ""
    if ctx.state.get("httpx_live"):
        return ctx.paths["urls_live"], ""
    if ctx.state.get("httpx_ran"):
        return None, "httpx n'a trouvé aucune URL vivante"
    return None, "httpx n'a pas tourné (aucune URL confirmée)"


def final_lists(ctx: Context) -> Tuple[Path, Path]:
    """(surface vivante, liste des 200) la plus à jour : après httpx #2 si elle a tourné."""
    if ctx.state.get("httpx2_ran"):
        return ctx.paths["urls_all_final"], ctx.paths["urls_200_final"]
    return ctx.paths["urls_all"], ctx.paths["urls_200"]


def live_lists(ctx: Context) -> List[Path]:
    """Listes « vivantes » produites par CE run, la plus à jour en tête."""
    files: List[Path] = []
    if ctx.state.get("httpx2_ran"):
        files.append(ctx.paths["urls_live_final"])
    if ctx.state.get("httpx_ran"):
        files.append(ctx.paths["urls_live"])
    return files


# --------------------------------------------------------------------------- #
# Modules
# --------------------------------------------------------------------------- #


def run_subfinder(ctx: Context) -> ModuleResult:
    o, paths = ctx.options, ctx.paths
    provided_hosts = load_provided_subdomains(o.subdomains)
    if provided_hosts:
        count = write_lines(paths["subfinder"], provided_hosts)
        ctx.log(report(count, paths["subfinder"], 0.0))
        ctx.log("  [dim]Liste fournie — étape subfinder ignorée.[/dim]")
    else:
        count, elapsed = stage_subfinder(o.target, paths["subfinder"], o.all_sources, ctx.remaining())
        ctx.log(report(count, paths["subfinder"], elapsed))
    raw_count = count
    count = apply_scope(ctx.scope, paths["subfinder"], "subfinder", ctx.log)
    if not count:
        # Les modules en aval constatent l'absence d'hôtes et s'ignorent proprement.
        if raw_count:
            raise ModuleError("Aucun sous-domaine dans le périmètre, arrêt.")
        raise ModuleError("Aucun sous-domaine trouvé, arrêt.")
    ctx.state["subfinder_count"] = count
    return ModuleResult(count)


def run_dnsx(ctx: Context) -> ModuleResult:
    o, paths = ctx.options, ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — rien à résoudre")
    ctx.log(eta_line(ctx.state["subfinder_count"], DNSX_NOMINAL_PER_SEC, "hôtes à résoudre"))
    n, elapsed = stage_dnsx(paths["subfinder"], paths["dnsx"], o.target, o.wildcard_filter, ctx.remaining())
    ctx.log(report(n, paths["dnsx"], elapsed))
    n = apply_scope(ctx.scope, paths["dnsx"], "dnsx", ctx.log)
    if n:
        ctx.state["hosts_file"] = paths["dnsx"]
    else:
        ctx.log("[yellow]dnsx sans résultat — on garde la liste subfinder[/yellow]")
    return ModuleResult(n)


def run_urlfinder(ctx: Context) -> ModuleResult:
    o, paths = ctx.options, ctx.paths
    n, elapsed, uf_stderr = stage_urlfinder(
        o.target, paths["urlfinder"], o.urlfinder_retries, o.urlfinder_retry_wait, o.urlfinder_all,
        notice=lambda msg: ctx.log(f"  {msg}", now=True), remaining=ctx.remaining,
    )
    ctx.log(report(n, paths["urlfinder"], elapsed))
    # `n` brut sert aux diagnostics ci-dessous (throttling) ; le résultat du module est le filtré.
    kept = apply_scope(ctx.scope, paths["urlfinder"], "urlfinder", ctx.log)
    lines = [line.strip() for line in uf_stderr.splitlines() if line.strip()]
    # Le récap propre de l'outil ("Found N urls … in T") : toujours affiché.
    for line in [l for l in lines if "found" in l.lower() and "url" in l.lower()][-1:]:
        ctx.log(f"  [dim]urlfinder : {line}[/dim]")
    # Erreurs explicites de sources (429, timeouts…).
    problems = [
        line for line in lines
        if any(tag in line for tag in ("[WRN]", "[ERR]", "[FTL]"))
        or "rate" in line.lower() or "limit" in line.lower()
    ]
    if problems:
        ctx.log("  [yellow]urlfinder — sources en échec/limitées :[/yellow]")
        for line in problems[:8]:
            ctx.log(f"    [dim]{line}[/dim]")
    elif n < 500:
        # Peu d'URLs SANS erreur = throttling silencieux (réponses vides en 200),
        # le cas le plus fréquent sur les archives une fois le quota IP épuisé.
        ctx.log(
            "  [yellow]Peu d'URLs sans erreur signalée[/yellow] — throttling silencieux probable "
            "(réponses vides en 200)."
        )
    if n < 500 or problems:
        if not o.urlfinder_all:
            ctx.log("  [dim]Garder --urlfinder-all (défaut) pour toutes les sources.[/dim]")
        ctx.log(
            "  [dim]Pour du volume : laisser la fenêtre de quota se reposer, ou ajouter des clés "
            "d'API dans ~/.config/urlfinder/provider-config.yaml.[/dim]"
        )
    return ModuleResult(kept)


def _run_httpx_pass(
    ctx: Context, source: Path, jsonl: Path, all_f: Path, ok_f: Path, live_f: Path, entries: int, label: str,
) -> Tuple[int, int, int]:
    """Une passe httpx + journal commun à httpx #1 et #2."""
    o = ctx.options
    ctx.log(eta_line(entries, ctx.rate, f"requêtes @ {ctx.rate}/s (plancher)"))
    total, alive, live, elapsed = stage_httpx(
        ctx.state["httpx_path"], source, jsonl, all_f, ok_f, live_f,
        o.match_codes, o.threads, ctx.rate, o.live_code_set, ctx.remaining(), label,
    )
    ctx.log(report(total, all_f, elapsed))
    ctx.log(f"  [green]→ {alive} en 200[/green] · {ok_f.name}")
    ctx.log(f"  [green]→ {live} vivants ({o.live_codes})[/green] · {live_f.name}")
    return total, alive, live


def run_httpx(ctx: Context) -> ModuleResult:
    paths = ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — rien à valider")
    merged = ensure_httpx_input(ctx)
    total, _, live = _run_httpx_pass(
        ctx, paths["httpx_input"], paths["httpx_jsonl"], paths["urls_all"], paths["urls_200"],
        paths["urls_live"], merged, "httpx",
    )
    ctx.state.update(httpx_ran=True, httpx_live=live)
    if not live:
        ctx.log("[yellow]Aucune URL vivante — katana ne sera pas lancé (cibles non confirmées)[/yellow]")
    return ModuleResult(total)


def run_katana(ctx: Context) -> ModuleResult:
    o, paths = ctx.options, ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — rien à crawler")
    seeds, why = katana_seeds(ctx)
    if seeds is None:
        raise ModuleSkipped(f"{why} — katana ne crawle pas de cibles non confirmées")
    n, elapsed = stage_katana(
        seeds, paths["katana"], o.depth, o.katana_scope, o.js_crawl, ctx.rate, o.concurrency,
        o.katana_max_pages, o.katana_duration, o.katana_ignore_query, o.katana_filter_similar,
        ctx.remaining(),
    )
    ctx.log(report(n, paths["katana"], elapsed))
    n = apply_scope(ctx.scope, paths["katana"], "katana", ctx.log)
    if o.js_crawl:
        ctx.log("[dim]  -jc actif : endpoints extraits du JS non requêtés, donc non validés.[/dim]")
    return ModuleResult(n)


def run_merge_map(ctx: Context) -> ModuleResult:
    """Carte finale = seeds vivantes + crawl katana, puis périmètre strict : les
    archives et le crawl font entrer des hôtes tiers, on les écarte avant httpx #2
    et surtout avant nuclei."""
    paths = ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — pas de carte")
    seeds, _ = katana_seeds(ctx)
    merge_files(([seeds] if seeds else []) + [paths["katana"]], paths["all_urls"])
    total = apply_scope(ctx.scope, paths["all_urls"], "all_urls", ctx.log)
    ctx.state["map_total"] = total
    return ModuleResult(total)


def run_httpx2(ctx: Context) -> ModuleResult:
    """katana découvre des URLs par crawl mais ne connaît PAS leur code HTTP.
    On re-teste la carte pour obtenir les statuts réels + la liste complète des
    200 (archives ET découvertes katana), et une surface vivante propre."""
    paths = ctx.paths
    total = ctx.state.get("map_total", 0)
    if not total:
        raise ModuleSkipped("carte vide — rien à revalider")
    total_v, _, _ = _run_httpx_pass(
        ctx, paths["all_urls"], paths["httpx2_jsonl"], paths["urls_all_final"],
        paths["urls_200_final"], paths["urls_live_final"], total, "httpx #2",
    )
    ctx.state["httpx2_ran"] = True
    return ModuleResult(total_v)


def run_tree(ctx: Context) -> ModuleResult:
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — pas d'arbre")
    _, live_200_file = final_lists(ctx)
    if not (live_200_file.exists() and count_lines(live_200_file)):
        raise ModuleSkipped("aucune liste de 200 à représenter")
    n = write_tree_report(live_200_file, ctx.paths["tree_html"], f"{ctx.options.target} · 200")
    ctx.log(f"  [dim]{n} URLs ({live_200_file.name})[/dim] → {ctx.paths['tree_html'].name}")
    return ModuleResult(n)


def run_nuclei(ctx: Context) -> ModuleResult:
    o, paths = ctx.options, ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — rien à scanner")

    # Cibles = liste LIVE validée (httpx #2 si disponible, sinon #1), jamais le
    # dump urlfinder brut ni les 404/5xx de --match-codes. Repli sur l'ancien
    # chemin seulement si httpx n'a pas tourné (--skip-httpx).
    lists = live_lists(ctx)
    live_urls: List[str] = []
    for candidate in lists:
        live_urls = [u for u in read_lines(candidate) if u.startswith(("http://", "https://"))]
        if live_urls:
            break
    if not live_urls and not lists:
        live_all_file, _ = final_lists(ctx)
        live_urls = clean_live_urls(live_all_file, paths["all_urls"])
    before = len(live_urls)
    live_urls = ctx.scope.filter(live_urls, "nuclei")
    if before != len(live_urls):
        ctx.log(f"  [dim]scope : {before - len(live_urls)} hors périmètre écartés ({paths['rejected_scope'].name})[/dim]")
    hosts = dedupe_hosts(live_urls)

    # hosts (défaut) vs urls : choisi au lancement (jamais de question pendant l'exécution).
    chosen = hosts if o.nuclei_targets == "hosts" else live_urls
    count_in = write_lines(paths["nuclei_input"], chosen)
    if not count_in:
        raise ModuleSkipped("Aucune cible vivante pour nuclei — étape ignorée.")
    if not o.scope_enabled:
        ctx.log(
            "[yellow]Rappel :[/yellow] payloads actifs sur [bold]"
            f"{count_in}[/bold] cibles avec [cyan]--no-scope-filter[/cyan] : "
            "domaines tiers d'archive possibles."
        )
    ctx.log(f"  [dim]mode {o.nuclei_mode} · {o.nuclei_targets} ({count_in} cibles)[/dim]")
    ctx.log(f"  [dim]sévérité {o.nuclei_severity} · -mhe {o.nuclei_max_host_error} · -timeout {o.nuclei_timeout}s[/dim]")
    n, elapsed = stage_nuclei(
        paths["nuclei_input"], paths["nuclei"], o.nuclei_mode,
        o.nuclei_severity, ctx.rate, o.nuclei_max_host_error,
        o.nuclei_timeout, o.nuclei_concurrency, o.nuclei_retries, ctx.remaining(),
    )
    ctx.log(report(n, paths["nuclei"], elapsed))
    return ModuleResult(n)


# --------------------------------------------------------------------------- #
# Assemblage du DAG
# --------------------------------------------------------------------------- #


def build_modules(o: Options) -> List[Module]:
    """Le DAG du pipeline. L'ordre de déclaration est l'ordre de priorité (et
    celui du mode --sequential)."""
    provided = bool(load_provided_subdomains(o.subdomains))
    uf_mode = "toutes sources (-all)" if o.urlfinder_all else "sources curées"
    icon = STAGE_ICONS.get
    return [
        Module(
            "subfinder", [], run_subfinder,
            binaries=[] if provided else ["subfinder"],
            icon=icon("subfinder", "•"),
            desc="sous-domaines fournis (--subdomains)" if provided else "sous-domaines théoriques",
        ),
        Module(
            "dnsx", ["subfinder"], run_dnsx, binaries=["dnsx"], enabled=not o.skip_dnsx,
            icon=icon("dnsx", "•"), desc="validation DNS + filtrage wildcard",
        ),
        # urlfinder part de l'apex seul : aucune dépendance, il tourne en parallèle des hôtes.
        Module(
            "urlfinder", [], run_urlfinder, binaries=["urlfinder"], enabled=not o.skip_urlfinder,
            icon=icon("urlfinder", "•"), desc=f"chemins historiques (apex) · {uf_mode}",
        ),
        Module(
            "httpx", ["dnsx", "urlfinder"], run_httpx, binaries=["httpx"], enabled=not o.skip_httpx,
            network=True, rate=o.rate_limit,
            icon=icon("httpx", "•"), desc="validation + annotation (une seule passe)",
        ),
        Module(
            "katana", ["httpx"], run_katana, binaries=["katana"], enabled=not o.skip_katana,
            network=True, rate=o.rate_limit,
            icon=icon("katana", "•"), desc="crawl actif depuis les seeds vivantes",
        ),
        Module(
            "merge_map", ["katana"], run_merge_map,
            icon=icon("merge_map", "•"), desc="carte finale (seeds + crawl) + périmètre strict",
        ),
        Module(
            "httpx2", ["merge_map"], run_httpx2, binaries=["httpx"],
            enabled=o.revalidate and not o.skip_katana and not o.skip_httpx,
            network=True, rate=o.rate_limit, label="httpx #2",
            icon=icon("httpx2", "•"), desc="validation de la carte crawlée (codes réels)",
        ),
        Module(
            "tree", ["httpx2"], run_tree, enabled=o.tree_report,
            icon=icon("tree", "•"), desc="arbre HTML interactif des 200",
        ),
        Module(
            "nuclei", ["httpx2"], run_nuclei, binaries=["nuclei"], enabled=o.nuclei,
            network=True, rate=o.nuclei_rate_limit,
            icon=icon("nuclei", "•"), desc=f"mode {o.nuclei_mode} · {o.nuclei_targets}",
        ),
    ]
