"""Les étapes du pipeline, portées en modules indépendants (voir `pipeline.py`).

DAG (une flèche = « doit être terminé avant »)::

    subfinder ─┐
    crtsh ─────┼─ subdomains ─ dnsx ─┬─ takeover
    amass ─────┘                     ├─ naabu ─ httpx_ports ─┬─ nuclei_ports (opt-in)
    urlfinder ───────────────────────┴─ httpx ─┬─ katana ─┬─ jsluice ─┬─ secrets    │
       └─ gau ─ waybackurls ─────────────┐     └─ nuclei1 │           │             │
                                         │       (opt-in) │           │             │
                                         └─────────── merge_map ◄─────┘             │
                                                          │                         │
                                                       httpx2 ◄─────────────────────┘
                                                          ├─ tree
                                                          └─ arjun ─ nuclei2 (opt-in)

Sous-domaines : subfinder (-all), crtsh (Python, crt.sh) et amass (passif) tournent en
parallèle puis `subdomains` les fusionne (`01_subdomains.txt`, lu par dnsx). Archives :
urlfinder → gau → waybackurls sont **sérialisés** (mêmes archives Wayback/CommonCrawl,
déjà rate-limitées) mais tournent en parallèle du reste ; leurs URLs ne sont validées
par aucun httpx avant `merge_map`, qui les réduit puis les confie à httpx #2.

nuclei1 (par hôte) démarre dès qu'httpx #1 a confirmé les hôtes vivants et tourne
pendant le crawl katana ; nuclei2 (par URL représentative) clôt le pipeline.

Phase 4b : katana stocke les réponses (`responses/katana`) ; jsluice y lit les JS (endpoints
non validés → carte → httpx #2) et `secrets` les scanne (trufflehog sans vérification, sinon
gitleaks) — ni l'un ni l'autre n'envoie de requête. `takeover` repère les CNAME hors périmètre
(dnsx) puis passe subzy sur ces seuls hôtes. `naabu` scanne les ports des hôtes vivants,
`httpx_ports` valide les services web hors 80/443 (ils rejoignent les listes finales via httpx #2)
et `nuclei_ports` (opt-in) les scanne. `arjun` cherche des paramètres cachés sur quelques URLs
représentatives et nourrit le run DAST de nuclei #2.

Phase 5 : katana demande 100 req/s (et non 150) pour laisser 50 req/s à takeover / naabu / httpx ports
pendant le crawl ; httpx #1 calcule `-hash sha256` pour que katana ne crawle qu'un hôte par empreinte de
contenu (`06_katana_dedup.tsv`) ; les hôtes à framework JS passent dans un second crawl `-headless` du même
module. Les modules actifs peuvent être restreints par `Options.modules` (preset, `--enable` / `--disable`,
voir `config.resolve_modules`).

Chaque fonction `run_*` reproduit l'étape historique de `main()` : mêmes fichiers,
même filtrage de périmètre, mêmes replis. Ce qui change : elle lit l'état laissé
par ses dépendances dans `ctx.state` (`hosts_file`, `httpx_live`…) au lieu de
variables locales, et journalise via `ctx.log` (imprimé d'un bloc en fin de module).
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from . import crtsh as crtsh_client
from . import findings, runner, signatures
from .config import MODULE_DEFAULTS, default_param
from .io_utils import count_lines, read_lines, write_lines
from .liveness import (
    DEFAULT_LIVE_CODES,
    clean_live_urls,
    dedupe_seed_hosts,
    filter_live,
    iter_httpx_rows,
    js_heavy_hosts,
    parse_codes,
    protected_hosts,
    seen_urls,
    split_httpx_output,
    split_httpx_rows,
    union_rows,
)
from .pipeline import Context, Module, ModuleError, ModuleResult, ModuleSkipped, Status
from .report import write_report as write_tree_report
from .scope import ScopeFilter, host_of
from .signatures import host_port
from . import surface
from .ui import STAGE_ICONS, console, eta_line, human_duration, report

# Large volontairement : 401/403 = endpoints protégés, 500 = crash. Les filtrer
# reviendrait à jeter les meilleures pistes.
DEFAULT_MATCH_CODES = "200,204,301,302,307,308,401,403,405,500,502,503"

# Débit nominal grossier pour les estimations de durée (ordre de grandeur, pas
# une promesse) : dnsx résout vite, httpx est plafonné par --rate-limit.
DNSX_NOMINAL_PER_SEC = 1200

# nuclei : tags exclus. Passe 1 écarte aussi `fuzz` (la passe 2 s'en charge, via -dast) ;
# la passe 2 garde fuzz mais n'exécute jamais de dos ni d'intrusive.
NUCLEI1_EXCLUDE_TAGS = "fuzz,dos,intrusive"
NUCLEI2_EXCLUDE_TAGS = "dos,intrusive"
NUCLEI_CURATED_TAGS = "cve,exposure,misconfig,takeover,default-login"
NUCLEI_EXPOSURE_TAGS = "exposure,misconfig"

Log = Callable[[Optional[str]], None]


# --------------------------------------------------------------------------- #
# Options (copie typée des paramètres CLI utiles aux modules)
# --------------------------------------------------------------------------- #


# Archives : gau et waybackurls interrogent les mêmes sources publiques qu'urlfinder.
GAU_BLACKLIST = "png,jpg,jpeg,gif,svg,ico,webp,bmp,css,woff,woff2,ttf,eot,otf,mp3,mp4,webm"
AMASS_SUBS_TIMEOUT = 120  # s : lecture des noms dans la base amass (rapide)
# Sources d'URLs NON validées, dans l'ordre de fusion dans la carte : archives publiques et endpoints
# extraits du JS (jsluice). Toutes passent par httpx #2 avant d'alimenter quoi que ce soit.
ARCHIVE_MODULES = ("gau", "waybackurls", "jsluice")


@dataclass
class Options:
    target: str
    all_sources: bool = default_param("subfinder", "all_sources")
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
    katana_store: bool = default_param("katana", "store")           # réponses stockées : requis par jsluice et secrets
    katana_rate_limit: int = MODULE_DEFAULTS["katana"].rate         # req/s demandées (100 : laisse 50 aux autres modules)
    katana_dedupe_hosts: bool = default_param("katana", "dedupe_hosts")
    katana_headless: str = default_param("katana", "headless")      # auto | off | all
    katana_headless_concurrency: int = default_param("katana", "headless_concurrency")
    katana_no_sandbox: str = default_param("katana", "no_sandbox")  # auto (root) | on | off
    urlfinder_all: bool = True
    urlfinder_retries: int = 1
    urlfinder_retry_wait: int = 30
    threads: int = default_param("httpx", "threads")
    rate_limit: int = MODULE_DEFAULTS["httpx"].rate
    concurrency: int = default_param("katana", "concurrency")
    httpx_bin: Optional[str] = None
    revalidate: bool = True
    tree_report: bool = True
    scope_enabled: bool = True
    nuclei: bool = False
    nuclei_mode: str = "auto"
    nuclei_passes: str = "1,2"              # « 1 », « 2 » ou « 1,2 » (voir resolve_nuclei_passes)
    nuclei_severity: str = "medium,high,critical"
    nuclei_rate_limit: int = MODULE_DEFAULTS["nuclei1"].rate             # passe 1 : partage le budget avec katana
    nuclei2_rate_limit: int = MODULE_DEFAULTS["nuclei2"].rate           # passe 2 : fin de pipeline, presque seule
    nuclei_waf_factor: float = 0.3          # débit des hôtes derrière WAF/CDN = accordé × facteur
    nuclei_k: int = 2                       # URLs gardées par signature (passe 2)
    nuclei_priority: bool = True            # passe 2 : run « exposition » sur les chemins sensibles
    nuclei_max_host_error: int = 10
    nuclei_timeout: int = 5
    nuclei_concurrency: int = 25
    nuclei_retries: int = 1
    # Sources de sous-domaines et d'URLs historiques (tout actif par défaut).
    crtsh: bool = MODULE_DEFAULTS["crtsh"].enabled
    crtsh_timeout: int = default_param("crtsh", "request_timeout")   # s, par requête
    crtsh_retries: int = default_param("crtsh", "retries")
    crtsh_backoff: float = default_param("crtsh", "backoff")         # s, doublé à chaque essai
    amass: bool = MODULE_DEFAULTS["amass"].enabled
    gau: bool = MODULE_DEFAULTS["gau"].enabled
    gau_threads: int = default_param("gau", "threads")
    gau_http_timeout: int = default_param("gau", "http_timeout")     # s, par requête
    gau_providers: str = ""                                           # vide = ceux de gau
    waybackurls: bool = MODULE_DEFAULTS["waybackurls"].enabled
    archive_dedupe: bool = default_param("merge_map", "archive_dedupe")
    archive_k: int = default_param("merge_map", "archive_k")
    # Phase 4b (tout actif par défaut ; seul nuclei, dont nuclei_ports, reste opt-in).
    jsluice: bool = MODULE_DEFAULTS["jsluice"].enabled
    jsluice_concurrency: int = default_param("jsluice", "concurrency")
    jsluice_max_bytes: int = default_param("jsluice", "max_bytes")
    secrets: bool = MODULE_DEFAULTS["secrets"].enabled
    takeover: bool = MODULE_DEFAULTS["takeover"].enabled
    takeover_rate: int = MODULE_DEFAULTS["takeover"].rate
    takeover_concurrency: int = default_param("takeover", "concurrency")
    takeover_http_timeout: int = default_param("takeover", "http_timeout")
    naabu: bool = MODULE_DEFAULTS["naabu"].enabled
    naabu_rate: int = MODULE_DEFAULTS["naabu"].rate
    ports: str = default_param("naabu", "ports")                    # top-100 | top-1000 | liste (80,443,8080-8090)
    naabu_allow_full: bool = default_param("naabu", "allow_full")
    httpx_ports: bool = MODULE_DEFAULTS["httpx_ports"].enabled
    httpx_ports_rate: int = MODULE_DEFAULTS["httpx_ports"].rate
    arjun: bool = MODULE_DEFAULTS["arjun"].enabled
    arjun_rate: int = MODULE_DEFAULTS["arjun"].rate
    arjun_max: int = default_param("arjun", "max_urls")
    arjun_threads: int = default_param("arjun", "threads")
    arjun_http_timeout: int = default_param("arjun", "http_timeout")
    arjun_stable: bool = default_param("arjun", "stable")
    # Timeouts de module en secondes (None = illimité) : surcharge de `config.MODULE_DEFAULTS`.
    timeouts: Dict[str, Optional[int]] = field(default_factory=dict)
    skip_subfinder: bool = False
    skip_dnsx: bool = False
    skip_urlfinder: bool = False
    skip_httpx: bool = False
    skip_katana: bool = False
    # État final des modules (`config.resolve_modules`) : un module absent ou à True suit ses options
    # habituelles, à False il est désactivé (preset, --disable).
    modules: Optional[Dict[str, bool]] = None

    def __post_init__(self) -> None:
        # Les cinq étapes « skip » portent des replis historiques (httpx désactivé → katana sur les
        # entrées brutes, --subdomains…) : un module éteint par `modules` passe par le même chemin.
        for name in ("subfinder", "dnsx", "urlfinder", "httpx", "katana"):
            if self.modules and self.modules.get(name) is False:
                setattr(self, f"skip_{name}", True)

    def module_on(self, name: str) -> bool:
        """Faux si `modules` (preset / --enable / --disable) éteint ce module."""
        return self.modules is None or self.modules.get(name, True)

    def module_timeout(self, name: str) -> Optional[int]:
        """Timeout (s) du module : option CLI si fournie, sinon défaut de `config`."""
        if name in self.timeouts:
            return self.timeouts[name]
        return MODULE_DEFAULTS[name].timeout

    def nuclei_pass_enabled(self, number: int) -> bool:
        """La passe `number` (1 ou 2) est-elle active ? Toujours False sans -n."""
        return self.nuclei and str(number) in self.nuclei_passes.split(",")


def resolve_nuclei_passes(passes: Optional[str] = None, targets: Optional[str] = None) -> str:
    """Passes nuclei à lancer : `--nuclei-passes` l'emporte, sinon `--nuclei-targets`
    (compatibilité : `hosts` → passe 1 seule, `urls` → les deux), sinon les deux.

    Retourne « 1 », « 2 » ou « 1,2 ». Lève ValueError sur une valeur inconnue.
    """
    if passes is not None:
        tokens = [t for t in re.split(r"[,\s]+", passes.strip()) if t]
        if not tokens or any(t not in {"1", "2"} for t in tokens):
            raise ValueError("--nuclei-passes : 1, 2 ou 1,2")
        return ",".join(sorted(set(tokens)))
    if targets is None or targets == "urls":
        return "1,2"
    if targets == "hosts":
        return "1"
    raise ValueError("--nuclei-targets : hosts | urls")


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


def stage_subfinder(
    domains: "Sequence[str] | str", destination: Path, all_sources: bool, timeout: Optional[int] = None
) -> Tuple[int, float]:
    """subfinder sur un ou plusieurs apex (un `-d` par apex)."""
    apexes = [domains] if isinstance(domains, str) else list(domains)
    command = ["subfinder"]
    for apex in apexes:
        command += ["-d", apex]
    command += ["-o", str(destination)]
    if all_sources:
        command.append("-all")
    _, elapsed, _ = runner.run_command(command, "subfinder", watch=destination, timeout=timeout)
    return write_lines(destination, read_lines(destination)), elapsed


def stage_amass(
    domains: Sequence[str],
    destination: Path,
    timeout_minutes: Optional[int] = None,
    timeout: Optional[int] = None,
) -> Tuple[int, float, int]:
    """amass **passif**, en deux temps indépendants de la version (v4 et v5) :

    1. `amass enum -passive -d … [-timeout N] -nocolor` remplit la base d'amass.
       `-passive` est le défaut en v5 (option dépréciée mais acceptée) ; jamais
       `-active` (zone transfers, certificats : trafic vers la cible). En v5 `enum`
       n'a plus de `-o` (résultats sur la sortie standard) et `-timeout` est un délai
       *sans progrès* (en v4, durée totale) : le vrai plafond est l'échéance du module.
    2. `amass subs -names -d …` relit les noms de la base, un par ligne, capturés par
       redirection de la sortie standard (pas de `-o`, pas de `-silent`, qui couperait
       la sortie).

    Pas de `-silent` ajouté par `run_command` pour la même raison (`silent=False`).
    Retourne (noms, secondes, code de retour de `enum`).
    """
    joined = ",".join(domains)
    enum = ["amass", "enum", "-passive", "-d", joined]
    if timeout_minutes:
        enum += ["-timeout", str(timeout_minutes)]
    enum.append("-nocolor")
    rc, elapsed, _ = runner.run_command(enum, "amass", silent=False, timeout=timeout)

    raw = destination.with_name(destination.name + ".raw")
    raw.unlink(missing_ok=True)
    try:
        _, elapsed_subs, _ = runner.run_command(
            ["amass", "subs", "-names", "-d", joined, "-nocolor"], "amass subs",
            watch=raw, stdout_to=raw, silent=False, timeout=AMASS_SUBS_TIMEOUT,
        )
        # « nom » ou « nom ip… » ; « No names were discovered » est écarté par clean_name.
        names = [crtsh_client.clean_name(line.split()[0]) for line in read_lines(raw)]
    finally:
        raw.unlink(missing_ok=True)
    return write_lines(destination, sorted({n for n in names if n})), elapsed + elapsed_subs, rc


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


def only_http(lines: Sequence[str]) -> List[str]:
    return [line for line in lines if line.startswith(("http://", "https://"))]


def stage_gau(
    domains: Sequence[str],
    destination: Path,
    threads: int,
    http_timeout: int,
    providers: str = "",
    timeout: Optional[int] = None,
) -> Tuple[int, float, str]:
    """gau (archives Wayback / CommonCrawl / OTX / urlscan) sur les apex, sous-domaines inclus.

    Les URLs sortent sur la sortie standard, capturée dans `destination` (gau n'a pas
    de `-silent` : `silent=False`). On évite `--o` : gau y *ajoute* (ouverture en append),
    un fichier d'un run précédent serait complété au lieu d'être remplacé. `--blacklist`
    écarte à la source les extensions statiques courantes ; le reste est trié à la fusion.
    """
    destination.unlink(missing_ok=True)
    command = [
        "gau", "--subs", "--threads", str(threads), "--timeout", str(http_timeout),
        "--blacklist", GAU_BLACKLIST,
    ]
    if providers.strip():
        command += ["--providers", providers.strip()]
    command += list(domains)
    _, elapsed, stderr = runner.run_command(
        command, "gau", watch=destination, stdout_to=destination, silent=False, timeout=timeout
    )
    return write_lines(destination, only_http(read_lines(destination))), elapsed, stderr


def stage_waybackurls(
    domains: Sequence[str], destination: Path, domains_file: Path, timeout: Optional[int] = None
) -> Tuple[int, float, str]:
    """waybackurls : les domaines arrivent sur l'entrée standard (sans argument il lit un
    domaine par ligne ; avec un argument il n'en prend qu'un seul). Sous-domaines inclus
    (pas de `-no-subs`). Sortie standard → `destination`."""
    destination.unlink(missing_ok=True)
    write_lines(domains_file, list(domains))
    try:
        _, elapsed, stderr = runner.run_command(
            ["waybackurls"], "waybackurls", watch=destination, stdout_to=destination,
            stdin_from=domains_file, silent=False, timeout=timeout,
        )
    finally:
        domains_file.unlink(missing_ok=True)
    return write_lines(destination, only_http(read_lines(destination))), elapsed, stderr


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
    cdn: bool = False,
    split: bool = True,
    hashes: str = "",
) -> Tuple[int, int, int, float]:
    """Une passe httpx puis éclatement : `all_file` (annoté, tous codes retenus par
    -mc), `ok_file` (200 seuls) et `live_file` (URLs nues dont le code est dans
    `live_codes` — seule liste qui alimente katana et nuclei).

    `cdn` ajoute `-cdn` (champs `cdn`, `cdn_name`, `cdn_type` dans le JSONL) : demandé
    seulement quand nuclei passe 1 est actif, pour ralentir derrière les WAF/CDN.
    Sans lui, la commande est strictement celle d'avant.

    `hashes` ajoute `-hash <algo>` (httpx : md5, mmh3, simhash, sha1, sha256, sha512) : champ JSONL
    `hash` = {`body_sha256`, `header_sha256`}, lu pour dédoublonner les hôtes de katana. Vide = rien
    de changé à la commande.

    `split=False` : seule la passe est lancée (le JSONL est écrit), l'éclatement en
    listes est laissé à l'appelant — httpx #2 fusionne d'abord ses lignes avec celles
    de httpx #1."""
    command = [
        binary,
        "-l",
        str(source),
        "-json",
        "-status-code",
        "-title",
        "-content-length",
        "-tech-detect",
    ]
    if cdn:
        command.append("-cdn")
    if hashes:
        command += ["-hash", hashes]
    command += [
        "-match-code",
        match_codes,
        "-threads",
        str(threads),
        "-rate-limit",
        str(rate_limit),
        "-o",
        str(jsonl_file),
    ]
    _, elapsed, _ = runner.run_command(command, label, watch=jsonl_file, timeout=timeout)
    if not split:
        return count_lines(jsonl_file), 0, 0, elapsed
    total, alive, live = split_httpx_output(jsonl_file, all_file, ok_file, live_file, live_codes)
    return total, alive, live, elapsed


def running_as_root() -> bool:
    """Vrai si le processus tourne en root (Kali) : Chromium refuse alors de démarrer sans -no-sandbox."""
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def katana_command(
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
    store_dir: Optional[Path] = None,
    headless: bool = False,
    no_sandbox: bool = False,
) -> List[str]:
    """Commande katana. `headless` ajoute `-headless` (navigateur sans tête, expérimental) et, si
    `no_sandbox`, `-no-sandbox` (indispensable en root). Pas de `-xhr-extraction` : il n'écrit les
    requêtes XHR que dans une sortie `-jsonl`, or la nôtre est une liste d'URLs. Pas de
    `-store-response` en headless : katana ne le gère pas dans ce mode (le stockage reste au crawl
    standard). `-crawl-duration` s'applique PAR SEED, pas à l'ensemble du run."""
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
        command += ["-crawl-duration", duration.strip()]  # coupe après la durée (par seed)
    if js_crawl:
        command.append("-jc")
    if headless:
        command.append("-headless")
        if no_sandbox:
            command.append("-no-sandbox")
    elif store_dir is not None:
        # Réponses brutes sur disque : jsluice et secrets travaillent hors ligne dessus (aucune requête de plus).
        command += ["-store-response", "-store-response-dir", str(store_dir)]
    command += ["-o", str(destination)]
    return command


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
    store_dir: Optional[Path] = None,
    headless: bool = False,
    no_sandbox: bool = False,
) -> Tuple[int, float, int, str]:
    """Un crawl katana → `destination`. Retourne (URLs, secondes, code retour, stderr) : le code sert
    à repérer l'échec d'un crawl headless (pas de Chrome…)."""
    command = katana_command(
        source, destination, depth, scope, js_crawl, rate_limit, concurrency, max_pages, duration,
        ignore_query, filter_similar, store_dir, headless, no_sandbox,
    )
    rc, elapsed, stderr = runner.run_command(
        command, "katana headless" if headless else "katana", watch=destination, timeout=timeout
    )
    return write_lines(destination, read_lines(destination)), elapsed, rc, stderr


def stage_jsluice(files_list: Path, destination: Path, mode: str, concurrency: int, timeout: Optional[int] = None) -> float:
    """`jsluice urls|secrets` sur les fichiers listés dans `files_list`. Sans argument fichier,
    jsluice lit les chemins sur l'entrée standard (un par ligne) : pas de limite de longueur de
    commande. Sortie standard (un objet JSON par ligne, champ `filename`) capturée dans
    `destination` ; jsluice n'a pas de `-silent` (`silent=False`). Local : aucune requête."""
    _, elapsed, _ = runner.run_command(
        ["jsluice", mode, "-c", str(concurrency)], f"jsluice {mode}",
        watch=destination, stdout_to=destination, stdin_from=files_list, silent=False, timeout=timeout,
    )
    return elapsed


def stage_trufflehog(directory: Path, destination: Path, timeout: Optional[int] = None) -> float:
    """trufflehog sur un dossier. **`--no-verification` toujours** : vérifier un secret revient à
    l'essayer chez son fournisseur, c'est-à-dire à utiliser un identifiant tiers trouvé — hors
    périmètre. Jamais `--only-verified` / `--results=verified`. Sortie JSON (une ligne par
    découverte) sur la sortie standard, capturée ; pas de `-silent` (`silent=False`)."""
    _, elapsed, _ = runner.run_command(
        ["trufflehog", "filesystem", str(directory), "--no-verification", "--json", "--no-update", "--no-color"],
        "trufflehog", watch=destination, stdout_to=destination, silent=False, timeout=timeout,
    )
    return elapsed


def stage_gitleaks(directory: Path, report_file: Path, timeout: Optional[int] = None) -> float:
    """gitleaks (repli de trufflehog) : `gitleaks dir` (v8.19+), sinon l'ancien
    `gitleaks detect --no-git --source` ; rapport JSON dans `report_file`. `--exit-code 0` :
    des fuites trouvées ne sont pas une erreur ; pas de `--redact` (la preuve reste sur disque,
    dans 10_secrets.jsonl) mais jamais affichée."""
    report_file.unlink(missing_ok=True)
    tail = ["--report-format", "json", "--report-path", str(report_file), "--no-banner", "--exit-code", "0", "--log-level", "error"]
    rc, elapsed, _ = runner.run_command(
        ["gitleaks", "dir", str(directory), *tail], "gitleaks", silent=False, timeout=timeout
    )
    if rc not in (0, 124) and not report_file.exists():
        _, again, _ = runner.run_command(
            ["gitleaks", "detect", "--no-git", "--source", str(directory), *tail], "gitleaks", silent=False, timeout=timeout
        )
        elapsed += again
    return elapsed


def stage_dnsx_cname(source: Path, destination: Path, timeout: Optional[int] = None) -> Tuple[int, float]:
    """`dnsx -cname -resp -json` : enregistrements CNAME des hôtes vivants (interroge les résolveurs,
    pas la cible). Une ligne JSON par hôte, champ `cname`."""
    destination.unlink(missing_ok=True)
    command = ["dnsx", "-l", str(source), "-cname", "-resp", "-json", "-o", str(destination)]
    _, elapsed, _ = runner.run_command(command, "dnsx cname", watch=destination, timeout=timeout)
    return count_lines(destination), elapsed


def stage_subzy(
    targets: Path, output: Path, concurrency: int, http_timeout: int, timeout: Optional[int] = None
) -> float:
    """subzy sur les seuls candidats (CNAME hors périmètre). `--hide_fails` : seuls les cas utiles
    à l'écran ; `--https` : schéma par défaut des hôtes nus ; JAMAIS `--verify_ssl` (un certificat
    invalide ne doit pas masquer un service dangling). Résultats : tableau JSON dans `output`.
    Pas de `-silent` (`silent=False`)."""
    output.unlink(missing_ok=True)
    command = [
        "subzy", "run", "--targets", str(targets), "--concurrency", str(concurrency),
        "--timeout", str(http_timeout), "--hide_fails", "--https", "--output", str(output),
    ]
    _, elapsed, _ = runner.run_command(command, "subzy", silent=False, timeout=timeout)
    return elapsed


def stage_naabu(
    hosts: Path, destination: Path, ports: Sequence[str], rate: int, timeout: Optional[int] = None
) -> Tuple[int, float]:
    """naabu sur les hôtes vivants. `-exclude-cdn` : derrière un CDN/WAF seuls 80/443 sont sondés
    (inutile — et mal vu — de scanner l'infrastructure d'un tiers) ; `-rate` = débit accordé
    (paquets/s) ; `-retries 1` (défaut 3) ; type de scan laissé à naabu (CONNECT sans root, SYN
    sinon). Sortie JSON (`host`, `ip`, `port`) dans `destination`, écrite au fil de l'eau (un
    timeout garde les ports déjà trouvés)."""
    destination.unlink(missing_ok=True)
    command = [
        "naabu", "-list", str(hosts), *ports, "-rate", str(rate), "-retries", "1",
        "-exclude-cdn", "-json", "-o", str(destination),
    ]
    _, elapsed, _ = runner.run_command(command, "naabu", watch=destination, timeout=timeout)
    return count_lines(destination), elapsed


def stage_arjun(
    source: Path, destination: Path, rate: int, threads: int, http_timeout: int, stable: bool,
    timeout: Optional[int] = None,
) -> float:
    """arjun (GET) sur une liste d'URLs. `--rate-limit` = débit accordé (req/s) ; `-t` threads ;
    `-T` délai par requête. `--stable` (1 thread + 3 à 9 s de pause par requête) est désactivé par
    défaut : avec ~100+ requêtes par URL il rendrait le module inutilisable ; le débit est borné
    par `--rate-limit`. Sortie JSON `-oJ` ; pas de `-silent` (`silent=False`)."""
    destination.unlink(missing_ok=True)
    command = [
        "arjun", "-i", str(source), "-oJ", str(destination), "-m", "GET",
        "-t", str(threads), "-T", str(http_timeout), "--rate-limit", str(rate),
    ]
    if stable:
        command.append("--stable")
    _, elapsed, _ = runner.run_command(command, "arjun", silent=False, timeout=timeout)
    return elapsed


def nuclei_pass1_filters(mode: str, severity: str) -> List[str]:
    """Templates de la passe 1 (par hôte). Trois façons de piloter le coût
    (cibles × templates × requêtes) :

    - auto    : `-as` (Wappalyzer → tags) ne lance que les templates matchant la
                stack détectée. Rapide, précis, peu de bruit. Défaut.
    - curated : un set choisi (cve/exposure/misconfig…), sans les catégories qui
                explosent le compteur (fuzz/dos/intrusive).
    - full    : tout ce que couvre --nuclei-severity. Lent, réservé à peu d'hôtes.

    `-etags fuzz,dos,intrusive` dans les trois modes, et jamais `-dast` : la passe 1
    ne fait rien d'offensif au-delà des templates de détection.
    """
    exclude = ["-etags", NUCLEI1_EXCLUDE_TAGS]
    if mode == "auto":
        return ["-as", "-severity", severity, *exclude]
    if mode == "curated":
        return ["-tags", NUCLEI_CURATED_TAGS, *exclude, "-severity", severity]
    return ["-severity", severity, *exclude]  # full


def nuclei_dast_filters(severity: str) -> List[str]:
    """Passe 2, run A : fuzzing DAST des paramètres, au niveau de sévérité configuré."""
    return ["-dast", "-severity", severity, "-etags", NUCLEI2_EXCLUDE_TAGS]


def nuclei_exposure_filters() -> List[str]:
    """Passe 2, run B : exposition/misconfig sur les chemins sensibles. Volontairement
    SANS filtre de sévérité : les fichiers exposés « info/low » (.env, .git, phpinfo…)
    sont justement ce qu'on cherche."""
    return ["-tags", NUCLEI_EXPOSURE_TAGS, "-etags", NUCLEI2_EXCLUDE_TAGS]


def stage_nuclei(
    source: Path,
    output: Path,
    filters: Sequence[str],
    rate_limit: int,
    max_host_error: int,
    timeout: int,
    concurrency: int,
    retries: int,
    deadline: Optional[int] = None,
    label: str = "nuclei",
) -> Tuple[int, float]:
    """Un lot nuclei → `output` en JSONL. Retourne (findings valides, secondes).

    `-timeout`/`-retries`/`-mhe` bornent le temps perdu sur les hôtes lents ou
    morts ; `-c` parallélise les templates ; `-rate-limit` est le débit accordé par
    l'ordonnanceur. (`timeout` = celui de nuclei -timeout ; `deadline` = échéance du
    module, en secondes.)
    """
    command = [
        "nuclei", "-l", str(source), *filters,
        "-rate-limit", str(rate_limit),
        "-concurrency", str(concurrency),
        "-timeout", str(timeout),
        "-retries", str(retries),
        # -mhe : abandonne un hôte après N erreurs (défaut nuclei = 30, trop sur
        # des cibles d'archive souvent mortes).
        "-max-host-error", str(max_host_error),
        "-jsonl", "-o", str(output),
    ]
    output.unlink(missing_ok=True)
    _, elapsed, _ = runner.run_command(command, label, watch=output, timeout=deadline)
    return len(findings.valid_json_lines(output)), elapsed


# --------------------------------------------------------------------------- #
# État partagé entre modules
# --------------------------------------------------------------------------- #


def _hosts_available(ctx: Context) -> bool:
    """`subdomains` a rendu au moins un hôte en périmètre (sinon aval : rien à faire).

    (Clé d'état historique `subfinder_count` : avant les sources multiples, c'était le
    décompte de subfinder.)"""
    return ctx.state.get("subfinder_count", 0) > 0


def scope_apexes(ctx: Context) -> List[str]:
    """Apex à énumérer : cible + `--in-scope` (l'apex de la cible si le périmètre est vide)."""
    return list(ctx.scope.apexes) or [host_of(ctx.target) or ctx.target.strip().lower()]


def note_raw_hosts(ctx: Context, source: str, count: int) -> None:
    """Retient combien d'hôtes une source a rendus AVANT le filtre de périmètre
    (pour que `subdomains` distingue « rien trouvé » de « rien dans le périmètre »)."""
    with ctx.lock:
        ctx.state.setdefault("raw_hosts", {})[source] = count


def produced(ctx: Context, name: str) -> bool:
    """Le module a réellement produit son fichier dans CE run (terminé ou en timeout) —
    un fichier périmé d'un run précédent ne compte pas."""
    return ctx.status(name) in (Status.DONE, Status.TIMEOUT)


def ensure_httpx_input(ctx: Context) -> int:
    """Fusion hôtes (dnsx, sinon subfinder) + URLs urlfinder → 04_httpx_input.txt.

    Faite par httpx ; katana la fait aussi si l'utilisateur a désactivé httpx
    (repli historique). Idempotente : une seule fusion par run.
    """
    with ctx.lock:
        if "merged" not in ctx.state:
            hosts_file = ctx.state.get("hosts_file", ctx.paths["subdomains"])
            sources = [hosts_file]
            # urlfinder désactivé (preset, --skip-urlfinder) : son fichier d'un run précédent ne compte pas.
            if "urlfinder" not in ctx.records or produced(ctx, "urlfinder"):
                sources.append(ctx.paths["urlfinder"])
            merged = merge_files(sources, ctx.paths["httpx_input"])
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
    """subfinder (`-all` par défaut) sur tous les apex du périmètre — ou la liste
    `--subdomains`, qui le remplace. Un résultat vide n'est plus fatal ici : c'est
    `subdomains` qui arrête le pipeline si AUCUNE source ne rend d'hôte."""
    o, paths = ctx.options, ctx.paths
    provided_hosts = load_provided_subdomains(o.subdomains)
    if provided_hosts:
        count = write_lines(paths["subfinder"], provided_hosts)
        ctx.log(report(count, paths["subfinder"], 0.0))
        ctx.log("  [dim]Liste fournie — étape subfinder ignorée.[/dim]")
    else:
        count, elapsed = stage_subfinder(scope_apexes(ctx), paths["subfinder"], o.all_sources, ctx.remaining())
        ctx.log(report(count, paths["subfinder"], elapsed))
    raw_count = count
    note_raw_hosts(ctx, "subfinder", raw_count)
    count = apply_scope(ctx.scope, paths["subfinder"], "subfinder", ctx.log)
    note = ""
    if not count:
        note = "aucun sous-domaine dans le périmètre" if raw_count else "aucun sous-domaine trouvé"
    return ModuleResult(count, note=note)


def run_crtsh(ctx: Context) -> ModuleResult:
    """Sous-domaines vus dans les certificats (crt.sh), un appel par apex du périmètre.

    Pas de binaire : `urllib`. crt.sh est souvent lent ou en 5xx → délai par requête,
    deux nouveaux essais avec délai croissant, et on s'arrête à l'échéance du module.
    Un apex en échec n'empêche pas les autres ; tous en échec → module en échec (le
    pipeline continue, `subdomains` se contente des autres sources)."""
    o, paths = ctx.options, ctx.paths
    paths["crtsh"].unlink(missing_ok=True)
    domains = scope_apexes(ctx)
    request_timeout = o.crtsh_timeout
    if ctx.remaining() is not None:
        request_timeout = max(min(request_timeout, ctx.remaining()), 1)
    outcome = crtsh_client.fetch_domains(
        domains,
        request_timeout=request_timeout, retries=o.crtsh_retries, backoff=o.crtsh_backoff,
        expired=lambda: ctx.deadline is not None and time.monotonic() >= ctx.deadline,
        notice=lambda message: ctx.log(f"  {message}", now=True),
    )
    names, errors = outcome["names"], outcome["errors"]
    for domain, message in errors.items():
        ctx.log(f"  [yellow]crt.sh {domain} : {message}[/yellow]")
    if errors and len(errors) == len(domains):
        raise ModuleError("crt.sh : " + " ; ".join(f"{d} : {m}" for d, m in errors.items()))
    raw_count = write_lines(paths["crtsh"], names)
    note_raw_hosts(ctx, "crtsh", raw_count)
    ctx.log(report(raw_count, paths["crtsh"], 0.0))
    kept = apply_scope(ctx.scope, paths["crtsh"], "crtsh", ctx.log)
    note = f"{len(errors)}/{len(domains)} apex en échec" if errors else ""
    return ModuleResult(kept, note=note)


def run_amass(ctx: Context) -> ModuleResult:
    """amass passif sur les apex du périmètre (voir `stage_amass`). Peut être très long :
    échéance du module = `--amass-timeout` (15 min par défaut). Au-delà, `enum` est tué
    et les noms déjà en base sont quand même relus."""
    o, paths = ctx.options, ctx.paths
    paths["amass"].unlink(missing_ok=True)
    limit = o.module_timeout("amass")
    count, elapsed, rc = stage_amass(
        scope_apexes(ctx), paths["amass"], math.ceil(limit / 60) if limit else None, ctx.remaining()
    )
    ctx.log(report(count, paths["amass"], elapsed))
    note_raw_hosts(ctx, "amass", count)
    if rc == 124:
        ctx.log("  [yellow]amass enum interrompu à l'échéance — noms déjà trouvés conservés[/yellow]")
    elif rc != 0 and not count:
        raise ModuleError(f"amass enum a échoué (code {rc})")
    kept = apply_scope(ctx.scope, paths["amass"], "amass", ctx.log)
    return ModuleResult(kept)


def run_subdomains(ctx: Context) -> ModuleResult:
    """Fusion des sources de sous-domaines (subfinder, crtsh, amass) → `01_subdomains.txt`.

    Seules les sources qui ont produit leur fichier dans CE run comptent. Dédoublonnage
    insensible à la casse, puis périmètre. Si aucune source ne rend d'hôte en périmètre :
    échec (tout l'aval est ignoré), comme l'arrêt historique de subfinder."""
    paths = ctx.paths
    merged: Dict[str, str] = {}   # clé minuscule -> première écriture
    used: List[str] = []
    for name in ("subfinder", "crtsh", "amass"):
        if not (produced(ctx, name) and paths[name].exists()):
            continue
        lines = read_lines(paths[name])
        used.append(f"{name} {len(lines)}")
        for line in lines:
            merged.setdefault(line.lower(), line)
    raw_count = write_lines(paths["subdomains"], list(merged.values()))
    ctx.log(report(raw_count, paths["subdomains"], 0.0))
    count = apply_scope(ctx.scope, paths["subdomains"], "subdomains", ctx.log)
    if not count:
        # Les modules en aval constatent l'absence d'hôtes et s'ignorent proprement.
        if raw_count or sum(ctx.state.get("raw_hosts", {}).values()):
            raise ModuleError("Aucun sous-domaine dans le périmètre, arrêt.")
        raise ModuleError("Aucun sous-domaine trouvé, arrêt.")
    ctx.state["subfinder_count"] = count
    return ModuleResult(count, note=" · ".join(used))


def run_dnsx(ctx: Context) -> ModuleResult:
    o, paths = ctx.options, ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — rien à résoudre")
    ctx.log(eta_line(ctx.state["subfinder_count"], DNSX_NOMINAL_PER_SEC, "hôtes à résoudre"))
    n, elapsed = stage_dnsx(paths["subdomains"], paths["dnsx"], o.target, o.wildcard_filter, ctx.remaining())
    ctx.log(report(n, paths["dnsx"], elapsed))
    n = apply_scope(ctx.scope, paths["dnsx"], "dnsx", ctx.log)
    if n:
        ctx.state["hosts_file"] = paths["dnsx"]
    else:
        ctx.log("[yellow]dnsx sans résultat — on garde la liste des sous-domaines[/yellow]")
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


def _archive_hint(ctx: Context, tool: str, count: int) -> None:
    if count < 500:
        ctx.log(
            f"  [yellow]Peu d'URLs[/yellow] — {tool} partage les archives (Wayback, CommonCrawl…) avec urlfinder, "
            "souvent rate-limitées par IP : un résultat maigre est rarement une cible sans historique."
        )


def run_gau(ctx: Context) -> ModuleResult:
    """gau : URLs d'archives publiques (hors cible). Lancé APRÈS urlfinder — mêmes
    archives, déjà rate-limitées. Ces URLs ne sont PAS testées ici : `merge_map` les
    réduit puis httpx #2 les valide ; elles n'alimentent jamais katana ni nuclei en direct."""
    o, paths = ctx.options, ctx.paths
    n, elapsed, _ = stage_gau(
        scope_apexes(ctx), paths["gau"], o.gau_threads, o.gau_http_timeout, o.gau_providers, ctx.remaining()
    )
    ctx.log(report(n, paths["gau"], elapsed))
    kept = apply_scope(ctx.scope, paths["gau"], "gau", ctx.log)
    _archive_hint(ctx, "gau", n)
    return ModuleResult(kept)


def run_waybackurls(ctx: Context) -> ModuleResult:
    """waybackurls : archive Wayback seule. Lancé APRÈS gau (voir `run_gau`)."""
    paths = ctx.paths
    n, elapsed, _ = stage_waybackurls(
        scope_apexes(ctx), paths["waybackurls"], ctx.output / ".waybackurls_domains.tmp", ctx.remaining()
    )
    ctx.log(report(n, paths["waybackurls"], elapsed))
    kept = apply_scope(ctx.scope, paths["waybackurls"], "waybackurls", ctx.log)
    _archive_hint(ctx, "waybackurls", n)
    return ModuleResult(kept)


def _run_httpx_pass(
    ctx: Context, source: Path, jsonl: Path, all_f: Path, ok_f: Path, live_f: Path, entries: int, label: str,
    cdn: bool = False, hashes: str = "",
) -> Tuple[int, int, int]:
    """Une passe httpx + journal commun à httpx #1 et #2."""
    o = ctx.options
    ctx.log(eta_line(entries, ctx.rate, f"requêtes @ {ctx.rate}/s (plancher)"))
    total, alive, live, elapsed = stage_httpx(
        ctx.state["httpx_path"], source, jsonl, all_f, ok_f, live_f,
        o.match_codes, o.threads, ctx.rate, o.live_code_set, ctx.remaining(), label, cdn, hashes=hashes,
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
        paths["urls_live"], merged, "httpx", cdn=ctx.options.nuclei_pass_enabled(1) and ctx.options.module_on("nuclei1"),
        hashes=KATANA_HASH if katana_dedupes(ctx.options) else "",
    )
    ctx.state.update(httpx_ran=True, httpx_live=live)
    if not live:
        ctx.log("[yellow]Aucune URL vivante — katana ne sera pas lancé (cibles non confirmées)[/yellow]")
    return ModuleResult(total)


# Empreinte de contenu demandée à httpx #1 pour le dédoublonnage des hôtes de katana (champ JSONL
# `hash.body_sha256`).
KATANA_HASH = "sha256"


@dataclass
class KatanaPlan:
    """Ce que katana va crawler : seeds standard, seeds headless, hôtes écartés (doublons de contenu)."""

    standard: List[str]
    headless: List[str]
    dropped: List[Tuple[str, str, str]] = field(default_factory=list)   # (hôte gardé, hôte écarté, empreinte)
    frameworks: Dict[str, List[str]] = field(default_factory=dict)      # hôte headless -> frameworks JS


def plan_katana(seeds: List[str], rows: List[Dict[str, Any]], dedupe: bool, headless: str) -> KatanaPlan:
    """Répartit les seeds : doublons de contenu écartés (`dedupe`), puis seeds des hôtes à framework
    JS vers le crawl headless (`auto`), tous (`all`) ou aucun (`off`). `rows` = lignes d'httpx #1 ;
    vides, ni dédoublonnage ni détection (`all` n'en a pas besoin)."""
    dropped: List[Tuple[str, str, str]] = []
    kept = list(seeds)
    if dedupe and rows:
        kept, dropped = dedupe_seed_hosts(kept, rows)
    frameworks: Dict[str, List[str]] = {}
    if headless == "all":
        frameworks = {host_port(url): [] for url in kept}
    elif headless == "auto" and rows:
        heavy = js_heavy_hosts(rows)
        for host in dict.fromkeys(host_port(url) for url in kept):
            if host in heavy:
                frameworks[host] = heavy[host]
    deep = [url for url in kept if host_port(url) in frameworks]
    standard = [url for url in kept if host_port(url) not in frameworks]
    return KatanaPlan(standard, deep, dropped, frameworks)


def katana_dedupes(o: "Options") -> bool:
    """httpx #1 doit calculer les empreintes (`-hash`) : dédoublonnage demandé ET katana actif."""
    return o.katana_dedupe_hosts and not o.skip_katana and o.module_on("katana")


def run_katana(ctx: Context) -> ModuleResult:
    """Crawl katana des seeds vivantes, en un ou deux passages dans le même module.

    - **Dédoublonnage par contenu** (`--katana-dedupe-hosts`, défaut) : les hôtes dont la racine a la
      même empreinte (hash du corps httpx + code + taille) ne sont crawlés qu'une fois (le premier) ;
      les écartés sont listés dans `06_katana_dedup.tsv`. Les livrables ne perdent aucun hôte.
    - **Headless ciblé** (`--katana-headless`, défaut auto) : les hôtes à framework JS (d'après
      `httpx -tech-detect`) passent dans un second crawl `-headless`, à concurrence réduite, après le crawl
      standard. Si ce second crawl échoue (pas de Chrome…), les résultats du crawl standard sont gardés.
      Katana ne stocke pas les réponses en headless : jsluice et secrets ne voient que le crawl standard.
    Sorties fusionnées dans `06_katana.txt`."""
    o, paths = ctx.options, ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — rien à crawler")
    seeds, why = katana_seeds(ctx)
    if seeds is None:
        raise ModuleSkipped(f"{why} — katana ne crawle pas de cibles non confirmées")
    for key in ("katana", "katana_seeds", "katana_headless_seeds", "katana_dedup"):
        paths[key].unlink(missing_ok=True)
    store_dir = paths["responses_dir"] if o.katana_store else None
    if store_dir is not None:
        # index.txt est ouvert en ajout par katana : on repart d'un dossier vide (jamais de réponses périmées).
        shutil.rmtree(store_dir, ignore_errors=True)
        store_dir.mkdir(parents=True, exist_ok=True)

    # Lignes httpx #1 : seulement si les seeds en viennent (pas le repli --skip-httpx sur les entrées brutes).
    rows = list(iter_httpx_rows(read_lines(paths["httpx_jsonl"]))) if seeds == paths["urls_live"] else []
    plan = plan_katana(read_lines(seeds), rows, o.katana_dedupe_hosts, o.katana_headless)
    notes: List[str] = []
    if plan.dropped:
        write_lines(paths["katana_dedup"], [f"{kept}\t{gone}\t{fp}" for kept, gone, fp in plan.dropped])
        notes.append(f"{len(plan.dropped)} hôtes dédoublonnés")
        ctx.log(
            f"  [dim]dédoublonnage : {len(plan.dropped)} hôte(s) au contenu identique à un autre ne sont pas crawlés "
            f"→ {paths['katana_dedup'].name} (livrables inchangés)[/dim]"
        )
    elif o.katana_dedupe_hosts and rows:
        ctx.log("  [dim]dédoublonnage : aucun hôte au contenu identique[/dim]")
    standard_seeds = seeds
    if plan.dropped or plan.headless:
        standard_seeds = paths["katana_seeds"]
        write_lines(standard_seeds, plan.standard)

    if plan.standard or not plan.headless:
        count, elapsed, _, _ = stage_katana(
            standard_seeds, paths["katana"], o.depth, o.katana_scope, o.js_crawl, ctx.rate, o.concurrency,
            o.katana_max_pages, o.katana_duration, o.katana_ignore_query, o.katana_filter_similar,
            ctx.remaining(), store_dir,
        )
        ctx.log(report(count, paths["katana"], elapsed))
    if plan.headless:
        notes.extend(_run_katana_headless(ctx, plan))
    if not paths["katana"].exists():
        write_lines(paths["katana"], [])
    n = apply_scope(ctx.scope, paths["katana"], "katana", ctx.log)
    if o.js_crawl:
        ctx.log("[dim]  -jc actif : endpoints extraits du JS non requêtés, donc non validés.[/dim]")
    if store_dir is not None:
        files, size = surface.dir_size(store_dir)
        notes.insert(0, f"{files} réponses stockées ({surface.human_size(size)})")
        ctx.log(f"  [dim]réponses brutes dans {store_dir.relative_to(ctx.output)} (jsluice et secrets les lisent hors ligne)[/dim]")
    return ModuleResult(n, note=" · ".join(notes))


def _run_katana_headless(ctx: Context, plan: KatanaPlan) -> List[str]:
    """Second crawl, `-headless`, sur les hôtes JS ; fusionne sa sortie dans `06_katana.txt`.
    Ne lève jamais : un échec (pas de Chrome…) est journalisé et le crawl standard est conservé.
    Retourne les notes à afficher dans le récapitulatif."""
    o, paths = ctx.options, ctx.paths
    sandbox = {"on": True, "off": False}.get(o.katana_no_sandbox, running_as_root())
    hosts = list(plan.frameworks)
    shown = ", ".join(f"{h} ({'/'.join(f) if f else 'forcé'})" for h, f in list(plan.frameworks.items())[:5])
    ctx.log(
        f"  [dim]headless ({o.katana_headless}) : {len(hosts)} hôte(s) JS · {len(plan.headless)} seeds · "
        f"concurrence {o.katana_headless_concurrency}{' · -no-sandbox' if sandbox else ''} — {shown}"
        f"{' …' if len(hosts) > 5 else ''}[/dim]"
    )
    write_lines(paths["katana_headless_seeds"], plan.headless)
    if ctx.deadline is not None and time.monotonic() >= ctx.deadline:
        ctx.log("  [yellow]délai du module épuisé : crawl headless non lancé[/yellow]")
        return ["headless non lancé (délai)"]
    raw = ctx.output / ".katana_headless.tmp"
    raw.unlink(missing_ok=True)
    try:
        found, elapsed, rc, stderr = stage_katana(
            paths["katana_headless_seeds"], raw, o.depth, o.katana_scope, o.js_crawl, ctx.rate,
            o.katana_headless_concurrency, o.katana_max_pages, o.katana_duration, o.katana_ignore_query,
            o.katana_filter_similar, ctx.remaining(), None, True, sandbox,
        )
        ok = rc in (0, 124)    # 124 = délai du module : ce qui a été trouvé est gardé
        if ok:
            ctx.log(report(found, raw, elapsed))
        else:
            detail = (stderr.strip().splitlines() or [""])[-1][:160]
            ctx.log(
                f"  [yellow]katana headless en échec (code {rc}{' : ' + detail if detail else ''}) — résultats du "
                "crawl standard conservés (Chrome/Chromium installé ? voir README)[/yellow]"
            )
        merged = write_lines(paths["katana"], read_lines(paths["katana"]) + (read_lines(raw) if ok else []))
    finally:
        raw.unlink(missing_ok=True)
    if ok:
        ctx.log(f"  [dim]fusion standard + headless → {merged} entrées · {paths['katana'].name}[/dim]")
        if o.katana_store:
            ctx.log("  [dim]katana ne stocke pas les réponses en headless : jsluice et secrets ne voient que le crawl standard[/dim]")
    return [f"{len(hosts)} hôtes headless" if ok else f"headless en échec (code {rc})"]


def _stored_responses(ctx: Context, stage: str) -> List[surface.StoredResponse]:
    """Réponses stockées par katana dans CE run, limitées au périmètre (étape `stage`)."""
    if not ctx.options.katana_store:
        raise ModuleSkipped("--no-katana-store : katana n'a stocké aucune réponse")
    if not produced(ctx, "katana"):
        raise ModuleSkipped("katana n'a pas tourné dans ce run — aucune réponse stockée")
    responses = surface.read_katana_index(ctx.paths["responses_dir"])
    if not responses:
        raise ModuleSkipped("aucune réponse stockée par katana (index vide)")
    in_scope = set(ctx.scope.filter([r.url for r in responses], stage))
    return [r for r in responses if r.url in in_scope]


def run_jsluice(ctx: Context) -> ModuleResult:
    """jsluice sur les JS stockés par katana : endpoints (`urls`) et secrets (`secrets`).

    Aucune requête : seulement des fichiers locaux. Le corps de chaque JS est extrait de la
    réponse brute (jsluice ne voit ni la requête ni les en-têtes). Les endpoints relatifs sont
    résolus contre l'URL du JS qui les contient ; seuls http(s) en périmètre restent, statiques
    exclus. Ils ne sont **pas validés** : `merge_map` les prend comme les archives, httpx #2 les
    teste avant que quoi que ce soit s'en serve. `09_jsluice_secrets.jsonl` = sortie brute de
    jsluice (secrets en clair : fichier sensible) ; `secrets` en tire le résumé masqué."""
    o, paths = ctx.options, ctx.paths
    for key in ("jsluice", "jsluice_secrets"):
        paths[key].unlink(missing_ok=True)
    responses = _stored_responses(ctx, "jsluice")
    js_dir = paths["responses_js"]
    shutil.rmtree(js_dir, ignore_errors=True)
    files_list, raw_urls = ctx.output / ".jsluice_files.tmp", ctx.output / ".jsluice_urls.tmp"
    try:
        extracted, too_big = surface.extract_js_bodies(responses, js_dir, o.jsluice_max_bytes)
        if too_big:
            ctx.log(f"  [dim]{too_big} JS de plus de {surface.human_size(o.jsluice_max_bytes)} ignorés[/dim]")
        if not extracted:
            raise ModuleSkipped("aucun fichier JS dans les réponses stockées")
        write_lines(files_list, [str(path) for path, _ in extracted])
        lookup = surface.source_lookup(extracted)
        elapsed = stage_jsluice(files_list, raw_urls, "urls", o.jsluice_concurrency, ctx.remaining())
        urls = surface.parse_jsluice_urls(read_lines(raw_urls), lookup)
        elapsed += stage_jsluice(files_list, paths["jsluice_secrets"], "secrets", o.jsluice_concurrency, ctx.remaining())
    finally:
        for temp in (files_list, raw_urls):
            temp.unlink(missing_ok=True)
        shutil.rmtree(js_dir, ignore_errors=True)
    secrets = findings.valid_json_lines(paths["jsluice_secrets"])
    write_lines(paths["jsluice_secrets"], secrets)
    write_lines(paths["jsluice"], urls)
    ctx.log(report(len(urls), paths["jsluice"], elapsed))
    kept = apply_scope(ctx.scope, paths["jsluice"], "jsluice", ctx.log)
    ctx.log(f"  [dim]{len(extracted)} JS analysés · {len(secrets)} secret(s) candidat(s) → {paths['jsluice_secrets'].name}[/dim]")
    ctx.log("  [dim]endpoints non validés : ils entrent dans la carte, httpx #2 les teste[/dim]")
    return ModuleResult(kept, note=f"{len(extracted)} JS · {len(secrets)} secrets")


def run_secrets(ctx: Context) -> ModuleResult:
    """Secrets dans les réponses stockées par katana : trufflehog (**`--no-verification`**), à défaut
    gitleaks ; les secrets de `jsluice secrets` sont fusionnés au résumé.

    Aucune requête, et surtout aucune vérification : vérifier un secret l'essaierait chez son
    fournisseur, soit utiliser un identifiant tiers trouvé. `10_secrets.jsonl` = sorties brutes
    (secrets EN CLAIR : fichier sensible, à ne pas partager) ; `10_secrets.txt` et la console ne
    montrent que le détecteur, l'URL d'origine et le début du secret suivi de « … »."""
    paths = ctx.paths
    for key in ("secrets_jsonl", "secrets_txt"):
        paths[key].unlink(missing_ok=True)
    _stored_responses(ctx, "secrets")   # contrôles (option, katana, index) ; l'analyse porte sur le dossier entier
    lookup = surface.url_lookup(surface.read_katana_index(paths["responses_dir"]))
    raw = ctx.output / ".secrets.tmp"
    found: List[surface.SecretFinding] = []
    try:
        if shutil.which("trufflehog"):
            tool = "trufflehog"
            elapsed = stage_trufflehog(paths["responses_dir"], raw, ctx.remaining())
            found = surface.parse_trufflehog(read_lines(raw), lookup)
        else:
            tool = "gitleaks"
            elapsed = stage_gitleaks(paths["responses_dir"], raw, ctx.remaining())
            report_text = raw.read_text(encoding="utf-8", errors="replace") if raw.exists() else ""
            found = surface.parse_gitleaks(report_text, lookup)
    finally:
        raw.unlink(missing_ok=True)
    sources = [tool]
    if produced(ctx, "jsluice") and paths["jsluice_secrets"].exists():
        extra = surface.parse_jsluice_secrets(read_lines(paths["jsluice_secrets"]), lookup)
        found += extra
        sources.append(f"jsluice {len(extra)}")
    # Périmètre : une découverte dont l'URL d'origine est connue et hors périmètre est écartée.
    urls = sorted({f.url for f in found if f.url})
    allowed = set(ctx.scope.filter(urls, "secrets"))
    found = [f for f in found if not f.url or f.url in allowed]
    unique: Dict[Tuple[str, str, str], surface.SecretFinding] = {}
    for finding in found:
        unique.setdefault((finding.detector, finding.url or finding.file, finding.redacted), finding)
    ordered = sorted(unique.values(), key=lambda f: (f.detector, f.url or f.file, f.redacted))
    write_lines(paths["secrets_jsonl"], [f.raw for f in ordered])
    write_lines(paths["secrets_txt"], [surface.summary_line(f) for f in ordered])
    ctx.log(report(len(ordered), paths["secrets_txt"], elapsed))
    if ordered:
        by_detector: Dict[str, int] = {}
        for finding in ordered:
            by_detector[finding.detector] = by_detector.get(finding.detector, 0) + 1
        ctx.log("  [yellow]" + " · ".join(f"{n} {d}" for d, n in sorted(by_detector.items())) + "[/yellow]")
        ctx.log(
            f"  [dim]{paths['secrets_jsonl'].name} contient les secrets en clair : ne pas partager ni versionner ; "
            f"{paths['secrets_txt'].name} ne montre que le début masqué[/dim]"
        )
    if tool == "trufflehog":
        ctx.log("  [dim]trufflehog --no-verification : aucun secret n'est essayé chez son fournisseur[/dim]")
    return ModuleResult(len(ordered), note=" + ".join(sources))


def run_takeover(ctx: Context) -> ModuleResult:
    """Sous-domaines à risque de takeover : `dnsx -cname` sur les hôtes vivants (résolveurs, pas
    la cible), candidats = ceux dont un CNAME sort du périmètre (service tiers), puis subzy sur
    ces seuls candidats (il récupère les hôtes : `network=True`, concurrence basse).

    Sans subzy le module n'échoue pas : `11_takeover_candidates.txt` (liste utile en soi) est
    écrit et le module est terminé avec une note. Seuls les résultats vulnérables sont gardés
    (`11_takeover.jsonl` / `.txt`). Avec `-n`, nuclei #1 couvre aussi le tag `takeover` ; subzy
    reste lancé (empreintes différentes)."""
    o, paths = ctx.options, ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — rien à analyser")
    if "hosts_file" not in ctx.state:
        raise ModuleSkipped("dnsx n'a résolu aucun hôte — pas de CNAME à analyser")
    for key in ("takeover_candidates", "takeover_jsonl", "takeover_txt"):
        paths[key].unlink(missing_ok=True)
    _, elapsed = stage_dnsx_cname(ctx.state["hosts_file"], paths["dnsx_cname"], ctx.remaining())
    cnames = surface.parse_cname_rows(read_lines(paths["dnsx_cname"]))
    candidates = surface.takeover_candidates(cnames, scope_apexes(ctx), ctx.scope.excludes)
    write_lines(paths["takeover_candidates"], list(candidates))
    count = apply_scope(ctx.scope, paths["takeover_candidates"], "takeover", ctx.log)
    ctx.log(f"  [dim]{len(cnames)} hôte(s) avec CNAME · {count} pointent hors périmètre → {paths['takeover_candidates'].name}[/dim]")
    if not count:
        write_lines(paths["takeover_jsonl"], [])
        write_lines(paths["takeover_txt"], [])
        return ModuleResult(0, note="aucun CNAME hors périmètre")
    if not shutil.which("subzy"):
        ctx.log("[yellow]subzy introuvable[/yellow] — liste de candidats seulement, à tester à la main ou avec subzy.")
        return ModuleResult(count, note="subzy introuvable — candidats seulement")
    result_file = ctx.output / ".subzy.tmp"
    try:
        concurrency = max(min(o.takeover_concurrency, ctx.rate), 1)
        elapsed = stage_subzy(paths["takeover_candidates"], result_file, concurrency, o.takeover_http_timeout, ctx.remaining())
        rows_out = surface.parse_subzy(result_file.read_text(encoding="utf-8", errors="replace")) if result_file.exists() else []
    finally:
        result_file.unlink(missing_ok=True)
    vulnerable = [row for row in rows_out if surface.is_vulnerable(row)]
    write_lines(paths["takeover_jsonl"], [json.dumps(row, ensure_ascii=False) for row in vulnerable])
    write_lines(paths["takeover_txt"], [surface.takeover_line(row) for row in vulnerable])
    ctx.log(report(len(vulnerable), paths["takeover_txt"], elapsed))
    if vulnerable:
        ctx.log(f"  [bold red]{len(vulnerable)} takeover possible(s)[/bold red] — à vérifier à la main")
    return ModuleResult(len(vulnerable), note=f"{count} candidats testés" + ("" if rows_out else " · subzy sans résultat"))


def run_naabu(ctx: Context) -> ModuleResult:
    """Ports ouverts des hôtes vivants (`02_dnsx.txt`), jamais d'hôte non résolu. `--ports` :
    top-100 / top-1000 (défaut) / liste ; `full` refusé sauf `--naabu-allow-full`. `-exclude-cdn` :
    derrière un CDN/WAF seuls 80/443 sont sondés. Le débit accordé est passé à `-rate`.
    Résultats filtrés au périmètre : `12_naabu.jsonl` (sortie naabu) et `12_ports.txt` (`hôte:port`)."""
    o, paths = ctx.options, ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — rien à scanner")
    if "hosts_file" not in ctx.state:
        raise ModuleSkipped("dnsx n'a résolu aucun hôte — naabu ne scanne pas d'hôtes non confirmés")
    try:
        flags = surface.port_flags(o.ports, o.naabu_allow_full)
    except ValueError as exc:
        raise ModuleError(str(exc)) from None
    for key in ("naabu_jsonl", "ports"):
        paths[key].unlink(missing_ok=True)
    hosts = ctx.state["hosts_file"]
    ports_each = surface.port_count(flags)
    ctx.log(eta_line(count_lines(hosts) * ports_each, ctx.rate, f"sondes ({o.ports}) @ {ctx.rate}/s"))
    if ports_each > surface.MAX_EXPLICIT_PORTS:
        ctx.log("[yellow]Scan de tous les ports (--naabu-allow-full) : très long et très bruyant.[/yellow]")
    _, elapsed = stage_naabu(hosts, paths["naabu_jsonl"], flags, ctx.rate, ctx.remaining())
    entries = surface.parse_naabu(read_lines(paths["naabu_jsonl"]))
    wanted = [f"{host}:{port}" for host, port, _ in entries]
    allowed = set(ctx.scope.filter(wanted, "naabu"))
    kept = [(entry, line) for entry, (_, _, line) in zip(wanted, entries) if entry in allowed]
    if len(kept) != len(entries):
        ctx.log(f"  [dim]scope : {len(entries) - len(kept)} hors périmètre écartés ({paths['rejected_scope'].name})[/dim]")
    write_lines(paths["naabu_jsonl"], [line for _, line in kept])
    write_lines(paths["ports"], [entry for entry, _ in kept])
    ctx.log(report(len(kept), paths["ports"], elapsed))
    return ModuleResult(len(kept), note=o.ports)


def run_httpx_ports(ctx: Context) -> ModuleResult:
    """httpx sur les services `hôte:port` trouvés par naabu, hors 80/443 (déjà vus par httpx #1).
    Sortie `13_httpx_ports.jsonl` ; `urls_live_ports.txt` = URLs dont le code est « vivant »,
    en périmètre. Ces services rejoignent les listes finales (httpx #2 reprend les lignes du
    JSONL) et, avec `-n`, `nuclei_ports` les scanne."""
    o, paths = ctx.options, ctx.paths
    for key in ("httpx_ports_input", "httpx_ports_jsonl", "urls_live_ports"):
        paths[key].unlink(missing_ok=True)
    if not produced(ctx, "naabu"):
        raise ModuleSkipped("naabu n'a pas tourné dans ce run — aucun service à valider")
    web = surface.web_candidates(read_lines(paths["ports"]))
    if not write_lines(paths["httpx_ports_input"], web):
        raise ModuleSkipped("aucun port web hors 80/443")
    ctx.log(eta_line(len(web), ctx.rate, f"requêtes @ {ctx.rate}/s"))
    # split=False : seul le JSONL nous intéresse ici (les chemins de listes passés ne sont pas écrits).
    _, _, _, elapsed = stage_httpx(
        ctx.state["httpx_path"], paths["httpx_ports_input"], paths["httpx_ports_jsonl"], paths["urls_live_ports"],
        paths["urls_live_ports"], paths["urls_live_ports"], o.match_codes, o.threads, ctx.rate,
        o.live_code_set, ctx.remaining(), "httpx ports", split=False,
    )
    rows = list(iter_httpx_rows(read_lines(paths["httpx_ports_jsonl"])))
    live = filter_live(rows, o.live_code_set or parse_codes(o.live_codes))
    write_lines(paths["urls_live_ports"], live)
    ctx.log(report(len(rows), paths["httpx_ports_jsonl"], elapsed))
    kept = apply_scope(ctx.scope, paths["urls_live_ports"], "httpx_ports", ctx.log)
    ctx.log(f"  [green]→ {kept} vivants ({o.live_codes})[/green] · {paths['urls_live_ports'].name}")
    ctx.state["httpx_ports_ran"] = True
    return ModuleResult(len(rows), note=f"{len(web)} services testés")


def port_rows(ctx: Context) -> List[Dict[str, Any]]:
    """Lignes httpx des services hors 80/443, SEULEMENT si `httpx_ports` les a produites dans CE run."""
    if not ctx.state.get("httpx_ports_ran"):
        return []
    return list(iter_httpx_rows(read_lines(ctx.paths["httpx_ports_jsonl"])))


def run_nuclei_ports(ctx: Context) -> ModuleResult:
    """nuclei sur les services web hors 80/443 : mêmes réglages que la passe 1 (par racine
    `scheme://hôte:port`, `-as` selon `--nuclei-mode`, `-etags fuzz,dos,intrusive`, jamais `-dast`).
    Opt-in (`-n`) et suit `--nuclei-passes` (variante de la passe 1). Sortie : `nuclei_ports.jsonl`,
    reprise dans `nuclei.txt`."""
    o, paths = ctx.options, ctx.paths
    for key in ("nuclei_ports_input", "nuclei_ports_jsonl"):
        paths[key].unlink(missing_ok=True)
    if not ctx.state.get("httpx_ports_ran"):
        raise ModuleSkipped("httpx_ports n'a pas tourné — aucun service confirmé vivant")
    live_urls = [u for u in read_lines(paths["urls_live_ports"]) if u.startswith(("http://", "https://"))]
    before = len(live_urls)
    live_urls = ctx.scope.filter(live_urls, "nuclei_ports")
    if before != len(live_urls):
        ctx.log(f"  [dim]scope : {before - len(live_urls)} hors périmètre écartés ({paths['rejected_scope'].name})[/dim]")
    count_in = write_lines(paths["nuclei_ports_input"], dedupe_hosts(live_urls))
    if not count_in:
        raise ModuleSkipped("aucun service web vivant hors 80/443")
    _warn_no_scope(ctx, count_in, "services")
    filters = nuclei_pass1_filters(o.nuclei_mode, o.nuclei_severity)
    ctx.log(
        f"  [dim]mode {o.nuclei_mode} · {count_in} service(s) · sévérité {o.nuclei_severity} · "
        f"-etags {NUCLEI1_EXCLUDE_TAGS} · {ctx.rate}/s accordés[/dim]"
    )
    part = findings.part_path(paths["nuclei_ports_jsonl"], 1)
    try:
        stage_nuclei(
            paths["nuclei_ports_input"], part, filters, ctx.rate, o.nuclei_max_host_error, o.nuclei_timeout,
            o.nuclei_concurrency, o.nuclei_retries, ctx.remaining(), "nuclei ports",
        )
    finally:
        total = findings.merge_jsonl([part], paths["nuclei_ports_jsonl"])
    ctx.log(report(total, paths["nuclei_ports_jsonl"], 0.0))
    return ModuleResult(total)


def run_arjun(ctx: Context) -> ModuleResult:
    """arjun sur quelques URLs vivantes représentatives : une par signature, statiques exclues, URLs
    prioritaires (admin, api, upload…) d'abord, plafonnées à `--arjun-max` (30) car arjun envoie des
    centaines de requêtes par URL. Débit accordé via `--rate-limit`. Sortie `14_arjun.json` ;
    `14_arjun_params.txt` = une URL par jeu de paramètres trouvé (valeurs factices `=1`, paramètres
    existants conservés), en périmètre. Sans `-n` c'est un livrable de surface ; avec `-n`, nuclei #2
    les ajoute à son run DAST."""
    o, paths = ctx.options, ctx.paths
    for key in ("arjun_input", "arjun_json", "arjun_params"):
        paths[key].unlink(missing_ok=True)
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — rien à analyser")
    live_urls = _live_candidates(ctx, "arjun")
    targets = surface.pick_arjun_targets(live_urls, o.arjun_max)
    if not write_lines(paths["arjun_input"], targets):
        raise ModuleSkipped("aucune URL vivante non statique pour arjun")
    priority = sum(1 for u in targets if signatures.is_priority(u))
    ctx.log(
        f"  [dim]{len(live_urls)} URLs vivantes → {len(targets)} retenues (plafond {o.arjun_max}, "
        f"{priority} prioritaires d'abord) · {ctx.rate}/s accordés[/dim]"
    )
    if o.arjun_stable:
        ctx.log("  [yellow]--arjun-stable : 1 thread et 3 à 9 s de pause par requête, très lent[/yellow]")
    elapsed = stage_arjun(
        paths["arjun_input"], paths["arjun_json"], ctx.rate, o.arjun_threads, o.arjun_http_timeout,
        o.arjun_stable, ctx.remaining(),
    )
    text = paths["arjun_json"].read_text(encoding="utf-8", errors="replace") if paths["arjun_json"].exists() else ""
    found = surface.parse_arjun(text)
    write_lines(paths["arjun_params"], surface.arjun_param_urls(found))
    ctx.log(report(len(found), paths["arjun_json"], elapsed))
    kept = apply_scope(ctx.scope, paths["arjun_params"], "arjun", ctx.log)
    return ModuleResult(kept, note=f"{len(targets)} URLs testées · {len(found)} avec paramètres")


def reduce_archive(urls: Sequence[str], dedupe: bool, k: int) -> Tuple[List[str], Dict[str, int]]:
    """URLs d'archive (gau, waybackurls) prêtes pour la carte : statiques exclues, puis,
    si `dedupe`, K URLs par signature (gau peut rendre 100k+ lignes). Retourne
    (URLs gardées, décomptes). Le périmètre est déjà appliqué par l'appelant."""
    unique = list(dict.fromkeys(only_http([u.strip() for u in urls])))
    dynamic = [u for u in unique if not signatures.is_static(u)]
    kept = signatures.representatives(dynamic, k) if dedupe else dynamic
    return kept, {"raw": len(unique), "static": len(unique) - len(dynamic), "kept": len(kept)}


def build_map(
    seeds: Optional[Path],
    crawled: Sequence[Path],
    archives: Sequence[Path],
    destination: Path,
    scope: ScopeFilter,
    stage: str,
    dedupe: bool = True,
    k: int = 3,
    log: Log = console.print,
) -> Tuple[int, Dict[str, int], List[str]]:
    """Carte des URLs = seeds vivantes + crawl katana + archives réduites → `destination`,
    puis périmètre strict. Partagé par le module `merge_map` et par `recon_mano merge`.

    Les archives passent par : périmètre → statiques exclues → K par signature (si
    `dedupe`). Seeds et crawl sont repris tels quels. Retourne (URLs en carte, décomptes
    des archives : raw = en entrée, static = statiques écartées, kept = gardées, et la
    liste des URLs qui ne sont entrées dans la carte QUE par les archives — jamais
    testées, donc à ne pas confier à nuclei tant qu'httpx #2 ne les a pas validées)."""
    archive_urls: List[str] = []
    for path in archives:
        archive_urls.extend(only_http(read_lines(path)))
    archive_urls = list(dict.fromkeys(archive_urls))
    in_scope = scope.filter(archive_urls, stage) if archive_urls else []
    reduced, stats = reduce_archive(in_scope, dedupe, k)
    stats["raw"] = len(archive_urls)
    lines: List[str] = []
    for path in ([seeds] if seeds else []) + list(crawled):
        lines.extend(read_lines(path))
    write_lines(destination, lines + reduced)
    total = apply_scope(scope, destination, stage, log)
    known = set(lines)
    return total, stats, [u for u in reduced if u not in known]


def run_merge_map(ctx: Context) -> ModuleResult:
    """Carte finale = seeds vivantes + crawl katana + archives gau/waybackurls réduites,
    puis périmètre strict : les archives et le crawl font entrer des hôtes tiers, on les
    écarte avant httpx #2 et surtout avant nuclei. Attend katana ET la chaîne d'archives."""
    o, paths = ctx.options, ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — pas de carte")
    seeds, _ = katana_seeds(ctx)
    # Les fichiers d'un run précédent peuvent traîner sur le disque : on n'utilise que ceux
    # que leur module a réellement produits dans CE run (terminé ou en timeout).
    crawled = [paths["katana"]] if produced(ctx, "katana") else []
    archives = [paths[name] for name in ARCHIVE_MODULES if produced(ctx, name) and paths[name].exists()]
    total, stats, archive_only = build_map(
        seeds, crawled, archives, paths["all_urls"], ctx.scope, "all_urls",
        o.archive_dedupe, o.archive_k, ctx.log,
    )
    ctx.state["map_total"] = total
    ctx.state["archive_only"] = set(archive_only)
    note = ""
    if archives:
        mode = f"K={o.archive_k}" if o.archive_dedupe else "sans réduction"
        note = f"archives {stats['raw']} → {stats['kept']} ({mode}, {stats['static']} statiques)"
    return ModuleResult(total, note=note)


def run_httpx2(ctx: Context) -> ModuleResult:
    """katana découvre des URLs par crawl mais ne connaît PAS leur code HTTP, et les
    archives (gau, waybackurls) n'ont été testées par personne. httpx #2 ne teste QUE les
    URLs de la carte absentes de `05_httpx.jsonl` (champs `url`/`input` : les seeds
    d'httpx #1 sont déjà validées) ; `08_httpx2.jsonl` ne contient donc que les nouvelles
    lignes et `08_httpx2_input.txt` ce qui lui a été envoyé. Les listes finales sont
    ensuite construites sur l'union des lignes #1 (URLs de la carte) et #2 : statuts
    réels, liste complète des 200 et surface vivante propre."""
    o, paths = ctx.options, ctx.paths
    total = ctx.state.get("map_total", 0)
    extra_rows = port_rows(ctx)
    ports_live = bool(extra_rows) and count_lines(paths["urls_live_ports"]) > 0
    if not total and not ports_live:
        raise ModuleSkipped("carte vide — rien à revalider")
    map_urls = read_lines(paths["all_urls"])
    map_set = set(map_urls)
    # httpx #1 de CE run seulement : un 05_httpx.jsonl périmé ne doit rien « valider ».
    first_rows = list(iter_httpx_rows(read_lines(paths["httpx_jsonl"]))) if ctx.state.get("httpx_ran") else []
    seen = seen_urls(first_rows)
    todo = [u for u in map_urls if u not in seen]
    write_lines(paths["httpx2_input"], todo)
    paths["httpx2_jsonl"].unlink(missing_ok=True)
    reused = len(map_urls) - len(todo)
    ctx.log(f"  [dim]{len(map_urls)} URLs en carte · {reused} déjà validées par httpx #1 · {len(todo)} à tester[/dim]")
    elapsed = 0.0
    if todo:
        ctx.log(eta_line(len(todo), ctx.rate, f"requêtes @ {ctx.rate}/s (plancher)"))
        _, _, _, elapsed = stage_httpx(
            ctx.state["httpx_path"], paths["httpx2_input"], paths["httpx2_jsonl"], paths["urls_all_final"],
            paths["urls_200_final"], paths["urls_live_final"], o.match_codes, o.threads, ctx.rate,
            o.live_code_set, ctx.remaining(), "httpx #2", split=False,
        )
    else:
        paths["httpx2_jsonl"].write_text("", encoding="utf-8")
    new_rows = list(iter_httpx_rows(read_lines(paths["httpx2_jsonl"])))
    rows = union_rows(first_rows, new_rows, only=map_set)
    if extra_rows:
        # Services web hors 80/443 (naabu → httpx_ports) : déjà validés, repris tels quels dans les listes finales.
        rows = union_rows(rows, extra_rows)
        ctx.log(f"  [dim]+ {len(extra_rows)} service(s) hors 80/443 (httpx_ports)[/dim]")
    total_v, alive, live = split_httpx_rows(
        rows, paths["urls_all_final"], paths["urls_200_final"], paths["urls_live_final"], o.live_code_set
    )
    ctx.log(report(total_v, paths["urls_all_final"], elapsed))
    ctx.log(f"  [green]→ {alive} en 200[/green] · {paths['urls_200_final'].name}")
    ctx.log(f"  [green]→ {live} vivants ({o.live_codes})[/green] · {paths['urls_live_final'].name}")
    # Défense en profondeur : la carte est déjà dans le périmètre, les listes finales aussi.
    total_v = apply_scope(ctx.scope, paths["urls_all_final"], "httpx2", ctx.log)
    for key in ("urls_200_final", "urls_live_final"):
        apply_scope(ctx.scope, paths[key], "httpx2", lambda message: None)
    ctx.state["httpx2_ran"] = True
    return ModuleResult(total_v, note=f"{len(todo)} testées · {reused} réutilisées")


def run_tree(ctx: Context) -> ModuleResult:
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — pas d'arbre")
    _, live_200_file = final_lists(ctx)
    if not (live_200_file.exists() and count_lines(live_200_file)):
        raise ModuleSkipped("aucune liste de 200 à représenter")
    n = write_tree_report(live_200_file, ctx.paths["tree_html"], f"{ctx.options.target} · 200")
    ctx.log(f"  [dim]{n} URLs ({live_200_file.name})[/dim] → {ctx.paths['tree_html'].name}")
    return ModuleResult(n)


def _warn_no_scope(ctx: Context, count: int, unit: str) -> None:
    if not ctx.options.scope_enabled:
        ctx.log(
            "[yellow]Rappel :[/yellow] payloads actifs sur [bold]"
            f"{count}[/bold] {unit} avec [cyan]--no-scope-filter[/cyan] : "
            "domaines tiers d'archive possibles."
        )


def run_nuclei1(ctx: Context) -> ModuleResult:
    """nuclei passe 1 : un scan de détection par HÔTE vivant, pendant le crawl katana.

    Cibles = racines `scheme://host[:port]` de `urls_live.txt` (jamais le dump
    urlfinder brut ni les 404/5xx), filtrées sur le périmètre. Un même hôte sur deux
    ports donne deux cibles. Les hôtes derrière un WAF/CDN (d'après `httpx -cdn`)
    passent dans un second lot, plus lent : mêmes templates, débit × `--nuclei-waf-factor`,
    pour éviter bans et bruit.
    """
    o, paths = ctx.options, ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — rien à scanner")
    if not ctx.state.get("httpx_ran"):
        raise ModuleSkipped("httpx n'a pas tourné — aucune cible confirmée vivante")

    live_urls = [u for u in read_lines(paths["urls_live"]) if u.startswith(("http://", "https://"))]
    before = len(live_urls)
    live_urls = ctx.scope.filter(live_urls, "nuclei1")
    if before != len(live_urls):
        ctx.log(f"  [dim]scope : {before - len(live_urls)} hors périmètre écartés ({paths['rejected_scope'].name})[/dim]")
    targets = dedupe_hosts(live_urls)
    count_in = write_lines(paths["nuclei1_input"], targets)
    paths["nuclei1_normal"].unlink(missing_ok=True)
    paths["nuclei1_waf"].unlink(missing_ok=True)
    if not count_in:
        raise ModuleSkipped("Aucun hôte vivant pour nuclei — passe 1 ignorée.")
    _warn_no_scope(ctx, count_in, "hôtes")

    protected = protected_hosts(paths["httpx_jsonl"])
    waf = [t for t in targets if signatures.host_port(t) in protected]
    normal = [t for t in targets if signatures.host_port(t) not in protected]
    waf_rate = max(1, int(ctx.rate * o.nuclei_waf_factor))

    # (étiquette, fichier de cibles, débit, nombre de cibles)
    batches: List[Tuple[str, Path, int, int]] = []
    if waf:
        if normal:
            write_lines(paths["nuclei1_normal"], normal)
            batches.append(("nuclei #1", paths["nuclei1_normal"], ctx.rate, len(normal)))
        write_lines(paths["nuclei1_waf"], waf)
        batches.append(("nuclei #1 (WAF/CDN)", paths["nuclei1_waf"], waf_rate, len(waf)))
        names = ", ".join(sorted({protected[signatures.host_port(t)] for t in waf})[:4])
        ctx.log(f"  [dim]{len(waf)} hôte(s) derrière WAF/CDN ({names}) → lot séparé à {waf_rate}/s[/dim]")
    else:
        batches.append(("nuclei #1", paths["nuclei1_input"], ctx.rate, count_in))

    filters = nuclei_pass1_filters(o.nuclei_mode, o.nuclei_severity)
    ctx.log(f"  [dim]mode {o.nuclei_mode} · {count_in} hôtes · sévérité {o.nuclei_severity} · -etags {NUCLEI1_EXCLUDE_TAGS}[/dim]")
    ctx.log(f"  [dim]-mhe {o.nuclei_max_host_error} · -timeout {o.nuclei_timeout}s · {ctx.rate}/s accordés[/dim]")

    parts: List[Path] = []
    try:
        for index, (label, source, rate, size) in enumerate(batches, start=1):
            part = findings.part_path(paths["nuclei1_jsonl"], index)
            parts.append(part)
            n, elapsed = stage_nuclei(
                source, part, filters, rate, o.nuclei_max_host_error, o.nuclei_timeout,
                o.nuclei_concurrency, o.nuclei_retries, ctx.remaining(), label,
            )
            ctx.log(f"  [dim]{label} : {size} hôte(s) @ {rate}/s → {n} findings · {human_duration(elapsed)}[/dim]")
    finally:
        total = findings.merge_jsonl(parts, paths["nuclei1_jsonl"])
    ctx.log(report(total, paths["nuclei1_jsonl"], 0.0))
    return ModuleResult(total, note=f"{len(normal)} normaux · {len(waf)} WAF/CDN" if waf else "")


def _live_candidates(ctx: Context, stage: str) -> List[str]:
    """URLs vivantes (passe 2 de nuclei, arjun) : liste live la plus à jour (httpx #2, sinon #1),
    avec le repli historique si httpx n'a pas tourné (--skip-httpx)."""
    paths = ctx.paths
    lists = live_lists(ctx)
    live_urls: List[str] = []
    for candidate in lists:
        live_urls = [u for u in read_lines(candidate) if u.startswith(("http://", "https://"))]
        if live_urls:
            break
    if not live_urls and not lists:
        live_all_file, _ = final_lists(ctx)
        # Repli (--skip-httpx…) : la carte brute, MOINS les URLs d'archive que personne n'a testées.
        unvalidated = ctx.state.get("archive_only", set())
        live_urls = [u for u in clean_live_urls(live_all_file, paths["all_urls"]) if u not in unvalidated]
    before = len(live_urls)
    live_urls = ctx.scope.filter(live_urls, stage)
    if before != len(live_urls):
        ctx.log(f"  [dim]scope : {before - len(live_urls)} hors périmètre écartés ({paths['rejected_scope'].name})[/dim]")
    return live_urls


def run_nuclei2(ctx: Context) -> ModuleResult:
    """nuclei passe 2 : par URL représentative, en fin de pipeline.

    Les URLs vivantes sont réduites à K par signature (statiques exclues, voir
    `signatures.py`), puis deux runs :

    - A (DAST) : `-dast` sur celles qui ont des paramètres ;
    - B (exposition) : `-tags exposure,misconfig` sur les chemins sensibles, sans
      filtre de sévérité (désactivable : --no-nuclei-priority).
    """
    o, paths = ctx.options, ctx.paths
    if not _hosts_available(ctx):
        raise ModuleSkipped("aucun hôte en périmètre — rien à scanner")

    live_urls = _live_candidates(ctx, "nuclei2")
    dynamic = [u for u in live_urls if not signatures.is_static(u)]
    reps = signatures.representatives(dynamic, o.nuclei_k)
    for key in ("nuclei2_input", "nuclei2_params", "nuclei2_priority"):
        paths[key].unlink(missing_ok=True)
    if not write_lines(paths["nuclei2_input"], reps):
        raise ModuleSkipped("Aucune URL vivante non statique pour nuclei — passe 2 ignorée.")
    _warn_no_scope(ctx, len(reps), "URLs")
    ctx.log(
        f"  [dim]{len(live_urls)} URLs vivantes → {len(dynamic)} non statiques → "
        f"{len(reps)} représentantes (K={o.nuclei_k})[/dim]"
    )

    with_params = [u for u in reps if signatures.has_params(u)]
    # Paramètres cachés trouvés par arjun dans CE run : ajoutés APRÈS la réduction par signature
    # (leur jeu de paramètres est inédit), toujours filtrés sur le périmètre.
    if produced(ctx, "arjun") and paths["arjun_params"].exists():
        from_arjun = ctx.scope.filter(read_lines(paths["arjun_params"]), "nuclei2")
        with_params = list(dict.fromkeys(with_params + from_arjun))
        ctx.log(f"  [dim]+ {len(from_arjun)} URL(s) à paramètres d'arjun pour le run DAST[/dim]")
    write_lines(paths["nuclei2_params"], with_params)
    priority: List[str] = []
    if o.nuclei_priority:
        priority, method = signatures.select_priority(
            reps, paths["nuclei2_input"], ctx.output, ctx.log,
        )
        write_lines(paths["nuclei2_priority"], priority)
        ctx.log(f"  [dim]{len(priority)} URLs prioritaires ({method})[/dim]")

    # (étiquette, fichier, filtres) — seuls les runs qui ont des cibles.
    runs: List[Tuple[str, Path, List[str]]] = []
    if with_params:
        runs.append(("nuclei #2 DAST", paths["nuclei2_params"], nuclei_dast_filters(o.nuclei_severity)))
    else:
        ctx.log("  [dim]run DAST ignoré : aucune URL représentante avec paramètres[/dim]")
    if not o.nuclei_priority:
        ctx.log("  [dim]run exposition désactivé (--no-nuclei-priority)[/dim]")
    elif priority:
        runs.append(("nuclei #2 exposition", paths["nuclei2_priority"], nuclei_exposure_filters()))
    else:
        ctx.log("  [dim]run exposition ignoré : aucune URL prioritaire[/dim]")
    if not runs:
        raise ModuleSkipped("rien à lancer (ni paramètres, ni chemin sensible)")

    ctx.log(f"  [dim]-mhe {o.nuclei_max_host_error} · -timeout {o.nuclei_timeout}s · {ctx.rate}/s accordés[/dim]")
    parts: List[Path] = []
    try:
        for index, (label, source, filters) in enumerate(runs, start=1):
            part = findings.part_path(paths["nuclei2_jsonl"], index)
            parts.append(part)
            n, elapsed = stage_nuclei(
                source, part, filters, ctx.rate, o.nuclei_max_host_error, o.nuclei_timeout,
                o.nuclei_concurrency, o.nuclei_retries, ctx.remaining(), label,
            )
            ctx.log(f"  [dim]{label} : {count_lines(source)} URL(s) → {n} findings · {human_duration(elapsed)}[/dim]")
    finally:
        total = findings.merge_jsonl(parts, paths["nuclei2_jsonl"])
    ctx.log(report(total, paths["nuclei2_jsonl"], 0.0))
    return ModuleResult(total)


def finalize_nuclei(ctx: Context) -> Optional[Dict[str, int]]:
    """Fin de run : `nuclei.txt` = vue lisible fusionnée des deux passes (et des services hors 80/443).

    Seules les passes qui ont réellement produit leur JSONL dans CE run (terminées
    ou en timeout) comptent — un JSONL périmé d'un run précédent est ignoré. Retourne
    le décompte par sévérité, ou None si aucune passe n'a tourné (et retire alors un
    `nuclei.txt` périmé)."""
    paths = ctx.paths
    produced = [
        paths[key] for module, key in (
            ("nuclei1", "nuclei1_jsonl"), ("nuclei_ports", "nuclei_ports_jsonl"), ("nuclei2", "nuclei2_jsonl"),
        )
        if ctx.status(module) in (Status.DONE, Status.TIMEOUT) and paths[key].exists()
    ]
    if not produced:
        paths["nuclei"].unlink(missing_ok=True)
        return None
    return findings.write_view(produced, paths["nuclei"])


# --------------------------------------------------------------------------- #
# Assemblage du DAG
# --------------------------------------------------------------------------- #


def build_modules(o: Options) -> List[Module]:
    """Le DAG du pipeline. L'ordre de déclaration est l'ordre de priorité (et
    celui du mode --sequential). États et timeouts par défaut : `config.MODULE_DEFAULTS`,
    surchargés par les options."""
    provided = bool(load_provided_subdomains(o.subdomains))
    uf_mode = "toutes sources (-all)" if o.urlfinder_all else "sources curées"
    icon = STAGE_ICONS.get
    timeout = o.module_timeout
    on = o.module_on
    return [
        Module(
            "subfinder", [], run_subfinder,
            binaries=[] if provided else ["subfinder"],
            # Avec --subdomains, ce module ne fait que charger la liste : --skip-subfinder ne la perd pas.
            enabled=provided or not o.skip_subfinder, timeout=timeout("subfinder"),
            icon=icon("subfinder", "•"),
            desc="sous-domaines fournis (--subdomains)" if provided
            else f"sous-domaines théoriques{' · -all' if o.all_sources else ''}",
        ),
        # Sources de sous-domaines sans dépendance : elles tournent en parallèle de subfinder.
        Module(
            "crtsh", [], run_crtsh, enabled=o.crtsh and on("crtsh"), timeout=timeout("crtsh"),
            icon=icon("crtsh", "•"), desc="sous-domaines des certificats (crt.sh, sans binaire)",
        ),
        Module(
            "amass", [], run_amass, binaries=["amass"], enabled=o.amass and on("amass"), timeout=timeout("amass"),
            icon=icon("amass", "•"), desc="sous-domaines · amass enum passif",
        ),
        Module(
            "subdomains", ["subfinder", "crtsh", "amass"], run_subdomains, enabled=on("subdomains"),
            icon=icon("subdomains", "•"), desc="fusion subfinder + crtsh + amass · périmètre",
        ),
        Module(
            "dnsx", ["subdomains"], run_dnsx, binaries=["dnsx"], enabled=not o.skip_dnsx,
            timeout=timeout("dnsx"), icon=icon("dnsx", "•"), desc="validation DNS + filtrage wildcard",
        ),
        # urlfinder part de l'apex seul : aucune dépendance, il tourne en parallèle des hôtes.
        Module(
            "urlfinder", [], run_urlfinder, binaries=["urlfinder"], enabled=not o.skip_urlfinder,
            timeout=timeout("urlfinder"), icon=icon("urlfinder", "•"),
            desc=f"chemins historiques (apex) · {uf_mode}",
        ),
        # Archives sérialisées : urlfinder → gau → waybackurls interrogent les mêmes sources
        # publiques (Wayback, CommonCrawl), déjà rate-limitées par IP. Chacune démarre quand
        # la précédente est terminée, mais toute la chaîne tourne en parallèle des hôtes.
        Module(
            "gau", ["urlfinder"], run_gau, binaries=["gau"], enabled=o.gau and on("gau"), timeout=timeout("gau"),
            icon=icon("gau", "•"), desc="URLs d'archives (gau) · après urlfinder",
        ),
        Module(
            "waybackurls", ["gau"], run_waybackurls, binaries=["waybackurls"], enabled=o.waybackurls and on("waybackurls"),
            timeout=timeout("waybackurls"), icon=icon("waybackurls", "•"),
            desc="URLs de la Wayback Machine · après gau",
        ),
        Module(
            "httpx", ["dnsx", "urlfinder"], run_httpx, binaries=["httpx"], enabled=not o.skip_httpx,
            network=True, rate=o.rate_limit, timeout=timeout("httpx"),
            icon=icon("httpx", "•"), desc="validation + annotation (une seule passe)",
        ),
        # nuclei1 AVANT katana : quand les deux deviennent prêts dans le même tour de
        # l'ordonnanceur, nuclei1 prend son budget d'abord (50 req/s) et katana
        # reçoit le reste (150 -> 100). Désactivé (sans -n) : aucun budget consommé.
        # Budget (--max-rps 150) : httpx 150 seul au départ ; puis katana 100 (+ nuclei #1 50 avec -n).
        # Sans -n, les 50 req/s restants vont à takeover (10) et naabu (40 sur 100 demandés) pendant le crawl.
        Module(
            "nuclei1", ["httpx"], run_nuclei1, binaries=["nuclei"], enabled=o.nuclei_pass_enabled(1) and on("nuclei1"),
            network=True, rate=o.nuclei_rate_limit, timeout=timeout("nuclei1"), label="nuclei #1",
            icon=icon("nuclei1", "•"), desc=f"passe 1 · par hôte · mode {o.nuclei_mode} (‖ katana)",
        ),
        Module(
            "katana", ["httpx"], run_katana, binaries=["katana"], enabled=not o.skip_katana,
            network=True, rate=o.katana_rate_limit, timeout=timeout("katana"),
            icon=icon("katana", "•"),
            desc="crawl actif depuis les seeds vivantes" + (" · réponses stockées" if o.katana_store else ""),
        ),
        # Déclarés APRÈS katana : à budget égal le crawl garde la priorité (nuclei 50 + katana 100) ;
        # takeover et naabu prennent ce qui reste (50 sans -n) et attendent sinon.
        Module(
            # Dépend aussi de httpx : sinon il démarre avant httpx #1 (chemin critique)
            # et lui prend du budget de débit.
            "takeover", ["dnsx", "httpx"], run_takeover, binaries=["dnsx"], enabled=o.takeover and on("takeover"),
            network=True, rate=o.takeover_rate, timeout=timeout("takeover"),
            icon=icon("takeover", "•"), desc="CNAME hors périmètre (dnsx) + subzy sur ces seuls candidats",
        ),
        Module(
            "naabu", ["dnsx", "httpx"], run_naabu, binaries=["naabu"], enabled=o.naabu and on("naabu"),
            network=True, rate=o.naabu_rate, timeout=timeout("naabu"),
            icon=icon("naabu", "•"), desc=f"ports des hôtes vivants · {o.ports} · -exclude-cdn",
        ),
        Module(
            "httpx_ports", ["naabu"], run_httpx_ports, binaries=["httpx"],
            enabled=o.httpx_ports and not o.skip_httpx and on("httpx_ports"),
            network=True, rate=o.httpx_ports_rate, timeout=timeout("httpx_ports"), label="httpx ports",
            icon=icon("httpx_ports", "•"), desc="services web hors 80/443 trouvés par naabu",
        ),
        Module(
            "nuclei_ports", ["httpx_ports"], run_nuclei_ports, binaries=["nuclei"],
            enabled=o.nuclei_pass_enabled(1) and on("nuclei_ports"), network=True, rate=o.nuclei_rate_limit,
            timeout=timeout("nuclei_ports"), label="nuclei ports",
            icon=icon("nuclei_ports", "•"), desc=f"réglages passe 1 · services hors 80/443 · mode {o.nuclei_mode}",
        ),
        Module(
            "jsluice", ["katana"], run_jsluice, binaries=["jsluice"], enabled=o.jsluice and on("jsluice"),
            timeout=timeout("jsluice"), icon=icon("jsluice", "•"),
            desc="endpoints et secrets des JS stockés par katana (hors ligne)",
        ),
        Module(
            "secrets", ["katana", "jsluice"], run_secrets, binaries_any=["trufflehog", "gitleaks"],
            enabled=o.secrets and on("secrets"), timeout=timeout("secrets"), icon=icon("secrets", "•"),
            desc="secrets des réponses stockées · trufflehog --no-verification (sinon gitleaks)",
        ),
        Module(
            "merge_map", ["katana", "gau", "waybackurls", "jsluice"], run_merge_map,
            enabled=on("merge_map"), icon=icon("merge_map", "•"), desc="carte finale (seeds + crawl + archives + JS) + périmètre strict",
        ),
        # Valide aussi les URLs d'archive et de JS (jamais testées avant) : actif même sans katana.
        # Attend httpx_ports : les services hors 80/443 rejoignent les listes finales.
        Module(
            "httpx2", ["merge_map", "httpx_ports"], run_httpx2, binaries=["httpx"],
            enabled=o.revalidate and not o.skip_httpx and on("httpx2"),
            network=True, rate=o.rate_limit, timeout=timeout("httpx2"), label="httpx #2",
            icon=icon("httpx2", "•"), desc="validation des URLs de la carte absentes d'httpx #1",
        ),
        Module(
            "tree", ["httpx2"], run_tree, enabled=o.tree_report and on("tree"),
            icon=icon("tree", "•"), desc="arbre HTML interactif des 200",
        ),
        Module(
            "arjun", ["httpx2"], run_arjun, binaries=["arjun"], enabled=o.arjun and on("arjun"),
            network=True, rate=o.arjun_rate, timeout=timeout("arjun"),
            icon=icon("arjun", "•"), desc=f"paramètres cachés · ≤ {o.arjun_max} URLs représentatives",
        ),
        Module(
            "nuclei2", ["httpx2", "arjun"], run_nuclei2, binaries=["nuclei"], enabled=o.nuclei_pass_enabled(2) and on("nuclei2"),
            network=True, rate=o.nuclei2_rate_limit, timeout=timeout("nuclei2"), label="nuclei #2",
            icon=icon("nuclei2", "•"), desc=f"passe 2 · URLs représentantes (K={o.nuclei_k}) · DAST + exposition",
        ),
    ]
