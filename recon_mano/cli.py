"""Recon Mano - orchestration de la chaîne de reconnaissance ProjectDiscovery.

Pipeline : des modules indépendants, lancés par un ordonnanceur dès que leurs
dépendances sont terminées (voir `pipeline.py` et `modules.py`)::

    cible ─┬─ subfinder ─┐
           ├─ crtsh ─────┼─ subdomains ── dnsx ──┐          ┌─ katana ──────────┐
           ├─ amass ─────┘                       ├─ httpx ──┤                   ├─ merge_map ── httpx #2 ─┬─ tree
           └─ urlfinder ─────────────────────────┘          └─ nuclei #1 (opt-in)│                         └─ nuclei #2 (opt-in)
                  └─ gau ── waybackurls ───────────────────────────────────────┘

subfinder (-all), crtsh (Python), amass (passif) et urlfinder n'ont aucune dépendance :
ils tournent en parallèle. Les archives sont sérialisées (urlfinder → gau → waybackurls).
`--workers` borne les modules simultanés, `--max-rps` le débit total vers la cible
(budget global partagé par httpx, katana et nuclei). Chaque run écrit
`run_config.json` (périmètre, codes) et `run_stats.json` (durées par module).
Tout est actif par défaut sauf nuclei (`-n`, jamais par défaut), qui tourne en deux
passes : par hôte pendant le crawl, puis par URL représentative en fin de pipeline.

Invocation minimale::

    recon_mano cible.com nom_sortie [--nuclei ...]
    python -m recon_mano cible.com nom_sortie [--nuclei ...]
    recon_mano report <dossier|fichier>     (re)génère l'arbre HTML
    recon_mano merge <dossier>              rejoue la fusion finale sans relancer d'outil
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import List, Optional

try:
    import typer
except ModuleNotFoundError:
    print(
        "Module 'typer' introuvable. Installez-le avec :\n"
        "python -m pip install -r requirements.txt --break-system-packages"
    )
    raise

from . import runner
from .io_utils import count_lines
from .liveness import DEFAULT_LIVE_CODES, parse_codes
from .merge import merge_folder
from .findings import severity_line
from .config import MODULE_DEFAULTS, default_param, default_timeout_minutes, parse_module_timeouts
from .modules import (  # noqa: F401 — ré-exportés pour compatibilité
    DEFAULT_MATCH_CODES,
    Options,
    apply_scope,
    build_modules,
    dedupe_hosts,
    final_lists,
    finalize_nuclei,
    live_lists,
    load_provided_subdomains,
    merge_files,
    resolve_nuclei_passes,
)
from .pipeline import ARTIFACTS, Context, Scheduler, build_paths, write_run_config
from .report import write_report as write_tree_report
from .runner import resolve_httpx, run_command  # noqa: F401
from .scope import ScopeFilter, host_of, in_scope, parse_domains, scope_urls  # noqa: F401
from .ui import (  # noqa: F401
    STAGE_ICONS,
    console,
    human_duration,
    print_banner,
    print_summary,
    stage_header,
)

REQUIRED_TOOLS = ["subfinder", "dnsx", "httpx", "urlfinder", "katana"]

# Anciens fichiers qu'un --clean doit aussi emporter (nuclei mono-passe, avant les deux passes)
# et le fichier temporaire de waybackurls (laissé par un run interrompu).
LEGACY_ARTIFACTS = ["07_nuclei_input.txt", ".waybackurls_domains.tmp"]

# Outils optionnels : (binaire, module qu'il active, ce qui se passe sans lui).
OPTIONAL_TOOLS = [
    ("amass", "amass", "sans lui, pas de sous-domaines amass (passif)"),
    ("gau", "gau", "sans lui, pas d'URLs d'archives gau"),
    ("waybackurls", "waybackurls", "sans lui, pas d'URLs waybackurls"),
    ("nuclei", "nuclei (--nuclei)", "nécessaire seulement avec --nuclei"),
    ("gf", "nuclei passe 2", "repli sur une liste interne de paramètres suspects"),
]

# Fichiers produits par le pipeline — sert au nettoyage (--clean).
ARTIFACT_NAMES = list(ARTIFACTS.values()) + LEGACY_ARTIFACTS


# --------------------------------------------------------------------------- #
# Fichiers
# --------------------------------------------------------------------------- #


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
# Vérification des outils
# --------------------------------------------------------------------------- #


def check_tools() -> List[str]:
    missing: List[str] = []
    for tool in REQUIRED_TOOLS:
        if tool == "httpx":
            path = runner.resolve_httpx()
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

    for tool, module, fallback in OPTIONAL_TOOLS:
        path = shutil.which(tool)
        if path:
            console.print(f"[green]{tool}[/green] (optionnel, module {module}) : {path}")
        else:
            console.print(f"[dim]{tool} (optionnel, module {module}) introuvable — {fallback}[/dim]")
    console.print("[green]crtsh[/green] (module intégré) : aucun binaire requis (Python, crt.sh)")
    return missing


# --------------------------------------------------------------------------- #
# Sous-commandes report / merge
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
        candidates = [
            "urls_200_final.txt", "urls_200.txt", "urls_live_final.txt", "urls_live.txt",
            "urls_all_final.txt", "all_urls.txt", "06_katana.txt",
        ]
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


def run_merge_command(path_arg: Optional[Path]) -> None:
    """`recon_mano merge <dossier>` — rejoue la fusion finale depuis les fichiers
    déjà sur disque (aucun outil lancé) : carte, listes *_final, arbre HTML."""
    if path_arg is None:
        console.print("[bold]Usage :[/bold] recon_mano merge [cyan]<dossier>[/cyan]")
        raise typer.Exit(code=2)
    folder = Path(path_arg)
    if not folder.is_dir():
        console.print(f"[bold red]Dossier introuvable :[/bold red] {folder}")
        raise typer.Exit(code=1)

    result = merge_folder(folder)
    scope_txt = f"scope {','.join(result.scope_apexes)}" if result.scope_enabled else "scope off"
    if result.scope_excludes:
        scope_txt += f" · exclu {','.join(result.scope_excludes)}"
    console.print(f"\n[bold]merge[/bold] {folder} [dim]· {scope_txt} · codes vivants {','.join(map(str, sorted(result.live_codes)))}[/dim]")
    for name, count in result.rebuilt:
        console.print(f"  [green]→ {name}[/green] · {count} entrées")
    if not result.rebuilt:
        console.print("  [yellow]Rien à reconstruire.[/yellow]")
    for note in result.notes:
        console.print(f"  [dim]{note}[/dim]")
    raise typer.Exit()


# --------------------------------------------------------------------------- #
# Commande principale
# --------------------------------------------------------------------------- #


def main(
    target: Optional[str] = typer.Argument(None, help="Domaine apex, ou 'report' / 'merge' (sous-commandes sur un dossier de sortie)"),
    output: Optional[Path] = typer.Argument(None, help="Dossier de sortie (ou dossier/fichier si target=report, dossier si target=merge)"),
    check: bool = typer.Option(False, "--check", help="Vérifie la présence des outils puis quitte"),
    clean: bool = typer.Option(False, "--clean", help="Supprime les anciens fichiers de sortie avant de lancer"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Affiche les commandes et le flux des outils (sans board live)"),
    all_sources: bool = typer.Option(
        default_param("subfinder", "all_sources"), "--all-sources/--no-all-sources",
        help="subfinder -all : toutes les sources (défaut, plus lent mais plus complet) ; --no-all-sources pour le mode rapide",
    ),
    crtsh: bool = typer.Option(
        MODULE_DEFAULTS["crtsh"].enabled, "--crtsh/--no-crtsh",
        help="Sous-domaines depuis crt.sh (Certificate Transparency ; module Python, sans binaire ; interroge crt.sh, pas la cible)",
    ),
    crtsh_timeout: int = typer.Option(
        default_param("crtsh", "request_timeout"), "--crtsh-timeout", min=1,
        help="crt.sh : délai par requête, en secondes (crt.sh est souvent lent)",
    ),
    crtsh_retries: int = typer.Option(
        default_param("crtsh", "retries"), "--crtsh-retries", min=0,
        help="crt.sh : nouveaux essais sur erreur / 5xx / timeout (délai croissant : 5 s, 10 s…)",
    ),
    amass: bool = typer.Option(
        MODULE_DEFAULTS["amass"].enabled, "--amass/--no-amass",
        help="Sous-domaines via amass enum PASSIF (binaire amass optionnel ; module désactivé s'il est absent)",
    ),
    amass_timeout: int = typer.Option(
        default_timeout_minutes("amass"), "--amass-timeout", min=0,
        help="amass : durée max du module, en minutes (défaut 15 ; 0 = illimité). amass passif peut durer très longtemps.",
    ),
    gau: bool = typer.Option(
        MODULE_DEFAULTS["gau"].enabled, "--gau/--no-gau",
        help="URLs d'archives via gau (binaire gau optionnel ; interroge des archives publiques, pas la cible ; lancé après urlfinder)",
    ),
    gau_timeout: int = typer.Option(
        default_timeout_minutes("gau"), "--gau-timeout", min=0, help="gau : durée max du module, en minutes (défaut 15 ; 0 = illimité)",
    ),
    gau_threads: int = typer.Option(
        default_param("gau", "threads"), "--gau-threads", min=1,
        help="gau --threads (défaut 2 : prudent, les archives limitent par IP)",
    ),
    waybackurls: bool = typer.Option(
        MODULE_DEFAULTS["waybackurls"].enabled, "--waybackurls/--no-waybackurls",
        help="URLs de la Wayback Machine via waybackurls (binaire optionnel ; lancé après gau)",
    ),
    waybackurls_timeout: int = typer.Option(
        default_timeout_minutes("waybackurls"), "--waybackurls-timeout", min=0,
        help="waybackurls : durée max du module, en minutes (défaut 15 ; 0 = illimité)",
    ),
    archive_dedupe: bool = typer.Option(
        default_param("merge_map", "archive_dedupe"), "--archive-dedupe/--no-archive-dedupe",
        help="Réduit les URLs gau/waybackurls à --archive-k par signature avant httpx #2 (gau peut rendre 100k+ URLs)",
    ),
    archive_k: int = typer.Option(
        default_param("merge_map", "archive_k"), "--archive-k", min=1,
        help="URLs gardées par signature (hôte + chemin templaté + noms de paramètres) pour gau/waybackurls",
    ),
    module_timeout: List[str] = typer.Option(
        [], "--module-timeout",
        help="Timeout d'un module, en minutes : nom=minutes (répétable, 0 = illimité), ex. --module-timeout katana=30. "
             "Prioritaire sur les options dédiées. Modules : " + ", ".join(MODULE_DEFAULTS),
    ),
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
    live_codes: str = typer.Option(
        DEFAULT_LIVE_CODES, "--live-codes",
        help="Codes HTTP jugés « vivants » : seules ces URLs alimentent katana et nuclei "
             "(404/5xx exclus). --match-codes, plus large, continue de piloter les fichiers de triage.",
    ),
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
    threads: int = typer.Option(default_param("httpx", "threads"), "--threads", help="Threads httpx"),
    rate_limit: int = typer.Option(MODULE_DEFAULTS["httpx"].rate, "--rate-limit", help="Requêtes/seconde demandées par httpx et katana (plafonnées par --max-rps)"),
    concurrency: int = typer.Option(default_param("katana", "concurrency"), "--concurrency", help="Concurrence katana"),
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
        help="Domaines AJOUTÉS à la cible dans le périmètre (virgules, ex: devinci.fr,esilv.fr). "
             "Sans cette option, la question est posée au lancement (terminal) sauf avec -y.",
    ),
    exclude: str = typer.Option(
        "", "--exclude",
        help="Hôtes/domaines explicitement hors périmètre (virgules) : égaux ou sous-domaines d'une entrée.",
    ),
    no_scope_filter: bool = typer.Option(
        False, "--no-scope-filter", help="Désactive tout filtrage de périmètre (comportement historique)"
    ),
    yes: bool = typer.Option(False, "-y", "--yes", help="Ne pose aucune question (périmètre = cible + --in-scope)"),
    nuclei: bool = typer.Option(
        False, "-n", "--nuclei",
        help="Lance nuclei (opt-in, jamais par défaut) en deux passes : par hôte vivant (pendant le crawl katana) "
             "puis par URL représentative (fin de pipeline).",
    ),
    nuclei_mode: str = typer.Option(
        "auto", "--nuclei-mode",
        help="auto (-as tech-aware, défaut) | curated (tags CVE/expo/misconfig, sans fuzz) | full (tout selon --nuclei-severity)",
    ),
    nuclei_passes: Optional[str] = typer.Option(
        None, "--nuclei-passes",
        help="Passes nuclei à lancer : 1 (par hôte), 2 (par URL représentative) ou 1,2 (défaut). Prioritaire sur --nuclei-targets.",
    ),
    nuclei_targets: Optional[str] = typer.Option(
        None, "--nuclei-targets",
        help="Compatibilité : hosts → passe 1 seule · urls → les deux passes (défaut si absent). Remplacé par --nuclei-passes.",
    ),
    nuclei_severity: str = typer.Option(
        "medium,high,critical", "--nuclei-severity",
        help="Sévérités nuclei de la passe 1 et du run DAST de la passe 2 (le run exposition de la passe 2 n'est pas filtré)",
    ),
    nuclei_rate_limit: int = typer.Option(
        MODULE_DEFAULTS["nuclei1"].rate, "--nuclei-rate-limit",
        help="nuclei passe 1 : débit demandé (req/s, plafonné par --max-rps). 50 car la passe 1 partage le budget avec katana "
             "(150 au total : nuclei 50 + katana 100).",
    ),
    nuclei2_rate_limit: int = typer.Option(
        MODULE_DEFAULTS["nuclei2"].rate, "--nuclei2-rate-limit",
        help="nuclei passe 2 : débit demandé (req/s, plafonné par --max-rps). 150 car elle tourne en fin de pipeline, presque seule.",
    ),
    nuclei_waf_factor: float = typer.Option(
        0.3, "--nuclei-waf-factor", min=0.01, max=1.0,
        help="Passe 1 : les hôtes derrière un WAF/CDN (httpx -cdn) sont scannés après les autres à débit accordé × ce facteur (bans, bruit)",
    ),
    nuclei_k: int = typer.Option(
        2, "--nuclei-k", min=1,
        help="Passe 2 : nombre d'URLs gardées par signature (hôte + chemin templaté + noms de paramètres)",
    ),
    nuclei_priority: bool = typer.Option(
        True, "--nuclei-priority/--no-nuclei-priority",
        help="Passe 2 : run exposition/misconfig sur les chemins sensibles (admin, api, upload, config, debug…), sans filtre de sévérité",
    ),
    nuclei_max_host_error: int = typer.Option(
        10, "--nuclei-max-host-error", help="nuclei -mhe : abandonne un hôte après N erreurs (nuclei=30), les deux passes"
    ),
    nuclei_timeout: int = typer.Option(5, "--nuclei-timeout", help="nuclei -timeout (s) : ne pas s'attarder sur un hôte lent"),
    nuclei_concurrency: int = typer.Option(25, "--nuclei-concurrency", help="nuclei -c : templates en parallèle"),
    nuclei_retries: int = typer.Option(1, "--nuclei-retries", help="nuclei -retries"),
    skip_subfinder: bool = typer.Option(False, "--skip-subfinder"),
    skip_dnsx: bool = typer.Option(False, "--skip-dnsx"),
    skip_urlfinder: bool = typer.Option(False, "--skip-urlfinder"),
    skip_httpx: bool = typer.Option(False, "--skip-httpx"),
    skip_katana: bool = typer.Option(False, "--skip-katana"),
    max_rps: int = typer.Option(
        150, "--max-rps", min=1,
        help="Budget de débit GLOBAL (req/s) partagé par les modules qui frappent la cible (httpx, katana, nuclei)",
    ),
    workers: int = typer.Option(4, "--workers", min=1, help="Nombre maximum de modules exécutés en parallèle"),
    sequential: bool = typer.Option(False, "--sequential", help="Un module à la fois (= --workers 1) : débogage / comparaison"),
):
    """Recon Mano — (subfinder ‖ crtsh ‖ amass) → dnsx → httpx → katana ‖ nuclei #1 → httpx #2 → nuclei #2 (opt-in) ; urlfinder → gau → waybackurls en parallèle.

    Exemple : recon_mano exemple.com sortie -n
    """
    runner.set_verbose(verbose)

    # Pseudo-sous-commandes : `recon_mano report|merge <dossier>`. On les détecte
    # ici car le CLI est mono-commande (positionnels libres, pas de vraies
    # sous-commandes). 'report' et 'merge' ne sont pas des domaines valides → aucune collision.
    if target == "report":
        run_report_command(output)
    if target == "merge":
        run_merge_command(output)

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
            "  recon_mano exemple.com sortie -n --clean\n"
            "  recon_mano report exemple.com   [dim](re)génère l'arbre HTML[/dim]\n"
            "  recon_mano merge exemple.com    [dim]rejoue la fusion finale (aucun outil)[/dim]\n"
            "  recon_mano --check\n"
            "Aide complète : recon_mano --help"
        )
        raise typer.Exit(code=1)

    if nuclei_mode not in {"auto", "curated", "full"}:
        console.print("[bold red]--nuclei-mode :[/bold red] auto | curated | full")
        raise typer.Exit(code=2)
    try:
        passes = resolve_nuclei_passes(nuclei_passes, nuclei_targets)
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2)

    try:
        timeouts = {
            "amass": amass_timeout * 60 or None, "gau": gau_timeout * 60 or None,
            "waybackurls": waybackurls_timeout * 60 or None,
        }
        timeouts.update(parse_module_timeouts(module_timeout))
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2)

    try:
        live_code_set = parse_codes(live_codes)
    except ValueError:
        console.print("[bold red]--live-codes :[/bold red] codes HTTP séparés par des virgules (ex: 200,301,403)")
        raise typer.Exit(code=2)

    # --- Questions : UNIQUEMENT ici, au lancement ---------------------------- #
    # Aucune invite pendant l'exécution (elle se battrait avec le board live et
    # les autres threads) ; seulement en terminal interactif et sans -y.
    interactive = not yes and sys.stdin.isatty()

    # Périmètre : cible + --in-scope (ajout). Question posée UNE fois ; la réponse
    # remplace la liste.
    target_apex = host_of(target) or target.strip().lower()
    scope_apexes = list(dict.fromkeys([target_apex] + parse_domains(in_scope_domains)))
    scope_excludes = parse_domains(exclude)
    scope_enabled = not no_scope_filter
    if scope_enabled and not in_scope_domains.strip() and interactive:
        answer = typer.prompt("Domaines en scope (virgules)", default=target_apex)
        scope_apexes = parse_domains(str(answer)) or [target_apex]

    # Sortie par défaut = nom de la cible assaini.
    if output is None:
        output = Path(target.replace("/", "_").replace(":", "_"))
    output.mkdir(parents=True, exist_ok=True)

    if sequential:
        workers = 1

    paths = build_paths(output)
    options = Options(
        target=target, all_sources=all_sources, subdomains=subdomains, wildcard_filter=wildcard_filter,
        match_codes=match_codes, live_codes=live_codes, live_code_set=live_code_set,
        depth=depth, katana_scope=scope, js_crawl=js_crawl, katana_max_pages=katana_max_pages,
        katana_duration=katana_duration, katana_ignore_query=katana_ignore_query,
        katana_filter_similar=katana_filter_similar, urlfinder_all=urlfinder_all,
        urlfinder_retries=urlfinder_retries, urlfinder_retry_wait=urlfinder_retry_wait,
        threads=threads, rate_limit=rate_limit, concurrency=concurrency, httpx_bin=httpx_bin,
        revalidate=revalidate, tree_report=tree_report, scope_enabled=scope_enabled,
        nuclei=nuclei, nuclei_mode=nuclei_mode, nuclei_passes=passes,
        nuclei_severity=nuclei_severity, nuclei_rate_limit=nuclei_rate_limit,
        nuclei2_rate_limit=nuclei2_rate_limit, nuclei_waf_factor=nuclei_waf_factor,
        nuclei_k=nuclei_k, nuclei_priority=nuclei_priority,
        nuclei_max_host_error=nuclei_max_host_error, nuclei_timeout=nuclei_timeout,
        nuclei_concurrency=nuclei_concurrency, nuclei_retries=nuclei_retries,
        crtsh=crtsh, crtsh_timeout=crtsh_timeout, crtsh_retries=crtsh_retries,
        amass=amass, gau=gau, gau_threads=gau_threads, waybackurls=waybackurls,
        archive_dedupe=archive_dedupe, archive_k=archive_k, timeouts=timeouts,
        skip_subfinder=skip_subfinder, skip_dnsx=skip_dnsx, skip_urlfinder=skip_urlfinder,
        skip_httpx=skip_httpx, skip_katana=skip_katana,
    )

    scan_bits = []
    if nuclei:
        scan_bits.append(f"nuclei {nuclei_mode} · passe{'s' if ',' in passes else ''} {passes}")
    scan_bits.append(f"revalidate {'on' if revalidate else 'off'}")
    sources = [name for name, on in (("subfinder" + (" -all" if all_sources else ""), not skip_subfinder), ("crtsh", crtsh), ("amass", amass)) if on]
    archives = [name for name, on in (("urlfinder", not skip_urlfinder), ("gau", gau), ("waybackurls", waybackurls)) if on]
    scan_bits.append(f"sous-domaines {'+'.join(sources) or 'aucune source'}")
    scan_bits.append(f"archives {'+'.join(archives) or 'aucune'}")
    if scope_enabled:
        scan_bits.append(f"scope {','.join(scope_apexes)}")
        if scope_excludes:
            scan_bits.append(f"exclu {','.join(scope_excludes)}")
    else:
        scan_bits.append("scope off")
    scan_bits.append(f"{workers} worker{'s' if workers > 1 else ''} · {max_rps} rps max")
    print_banner([("🎯 cible ", target), ("📁 sortie", str(output)), ("⚙️  config", " · ".join(scan_bits))])

    if clean:
        clean_artifacts(output)

    # Journal des rejets remis à zéro à chaque run (créé ici, après --clean).
    scope_filter = ScopeFilter(scope_apexes, scope_excludes, paths["rejected_scope"], enabled=scope_enabled)

    ctx = Context(target=target, output=output, paths=paths, options=options, scope=scope_filter)

    # Le httpx du PATH est parfois le client HTTP Python : résolu une fois, ici.
    ctx.state["httpx_path"] = None
    if not skip_httpx:
        ctx.state["httpx_path"] = runner.resolve_httpx(httpx_bin)
        if not ctx.state["httpx_path"]:
            console.print(
                "[bold red]httpx (ProjectDiscovery) introuvable[/bold red] — modules httpx désactivés. "
                "Un `httpx` du PATH peut être le client HTTP Python.\n"
                "Installe : [cyan]go install github.com/projectdiscovery/httpx/cmd/httpx@latest[/cyan] "
                "ou passe [cyan]--httpx-bin[/cyan]."
            )

    modules = build_modules(options)
    write_run_config(paths["run_config"], {
        "target": target,
        "output": str(output),
        "scope": {"enabled": scope_enabled, "apexes": scope_apexes, "excludes": scope_excludes},
        "live_codes": sorted(live_code_set),
        "match_codes": match_codes,
        "modules": [m.name for m in modules if m.enabled],
        "archive": {"dedupe": archive_dedupe, "k": archive_k},
        "timeouts": {name: seconds for name, seconds in sorted(timeouts.items())},
        "nuclei": {
            "enabled": nuclei, "passes": passes if nuclei else "", "mode": nuclei_mode, "k": nuclei_k,
            "waf_factor": nuclei_waf_factor, "priority": nuclei_priority,
        },
        "workers": workers,
        "max_rps": max_rps,
    })

    scheduler = Scheduler(modules, ctx, max_workers=workers, max_rps=max_rps, live=True, verbose=verbose)
    scheduler.run()

    # --- Livrables ------------------------------------------------------------ #
    live_all_file, live_200_file = final_lists(ctx)
    final_file = paths["all_urls"]
    console.print()
    console.rule("[bold green]livrables[/]", align="left", style="green")
    if final_file.exists():
        console.print(f"  🗺️  [dim]carte[/dim]            [bold]{final_file}[/bold] [dim]({ctx.state.get('map_total', 0)} URLs)[/dim]")
    if live_all_file.exists():
        console.print(f"  📊 [dim]surface vivante[/dim]  [bold]{live_all_file}[/bold]")
    if live_200_file.exists():
        console.print(f"  🎯 [dim]endpoints 200[/dim]    [bold]{live_200_file}[/bold]")
    live_files = live_lists(ctx)
    if live_files:
        console.print(f"  🟢 [dim]liste live[/dim]       [bold]{live_files[0]}[/bold] [dim](katana/nuclei)[/dim]")
    if paths["tree_html"].exists():
        console.print(f"  🌳 [dim]arbre HTML[/dim]       [bold]{paths['tree_html']}[/bold]")

    if scope_filter.total_rejected:
        by_stage = ", ".join(f"{stage} {n}" for stage, n in scope_filter.rejected.items() if n)
        console.print(
            f"\n[dim]scope : {scope_filter.total_rejected} entrées hors périmètre écartées au total "
            f"({by_stage}) → {paths['rejected_scope']}[/dim]"
        )

    print_summary(scheduler.summary_rows(), scheduler.wall_clock, scheduler.sum_of_durations, scheduler.failed)
    console.print(f"[dim]stats par module → {paths['run_stats']}[/dim]")
    if nuclei:
        counts = finalize_nuclei(ctx)
        if counts is not None:
            console.print(f"[bold]nuclei[/bold] · {severity_line(counts)} [dim]→ {paths['nuclei']}[/dim]")
    if scheduler.failed:
        raise typer.Exit(code=1)


def entrypoint() -> None:
    """Point d'entrée console : commande unique avec arguments positionnels."""
    typer.run(main)


if __name__ == "__main__":
    entrypoint()
