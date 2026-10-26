"""Registre des modules : état par défaut, débit et timeout, et presets.

Une seule table (`MODULE_DEFAULTS`) dit, pour chaque module du pipeline, s'il est
actif par défaut, le débit qu'il demande à la cible (modules réseau seulement), son
timeout et ses paramètres propres. Les options de la CLI (`--no-amass`,
`--amass-timeout`, `--module-timeout nom=min`…) **surchargent** ces valeurs ;
`Options` (modules.py) et les valeurs par défaut de Typer (cli.py) s'en servent
comme source unique.

`PRESETS` regroupe des jeux de modules (fast / surface / full) et `resolve_modules`
calcule, pour un preset + des surcharges, l'état final de chaque module. La CLI utilise
`full` pour l'instant ; l'option `--mode` n'est pas encore branchée (voir cli.py).
Précédence, de la plus forte à la plus faible : option par module (`--X` / `--no-X`,
`--skip-X`) > `--enable` / `--disable` > preset.

Règles de fond rappelées ici :

- **nuclei est le seul module opt-in** (`-n`) : `enabled=False` ici, quel que soit le preset.
- Les modules qui frappent la cible (`network=True`) ont un débit en req/s, plafonné
  par le budget global `--max-rps`. crtsh, gau et waybackurls interrogent des
  services publics (crt.sh, archives), pas la cible : `network=False`. jsluice et
  secrets ne lisent que des fichiers locaux (réponses stockées par katana) :
  `network=False` aussi. takeover est `network=True` (subzy récupère les hôtes).
- Un timeout `None` = illimité (comportement historique des outils existants) ;
  il est exprimé en secondes ici, en minutes sur la CLI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class ModuleDefaults:
    enabled: bool = True
    network: bool = False             # envoie du trafic à la cible → consomme le budget de débit
    rate: int = 0                     # req/s demandées (si network)
    timeout: Optional[int] = None     # secondes ; None = illimité
    params: Dict[str, Any] = field(default_factory=dict)
    binaries: Tuple[str, ...] = ()    # binaires externes requis (tous)
    binaries_any: Tuple[str, ...] = ()  # au moins un de ces binaires (ex. trufflehog OU gitleaks)
    note: str = ""


# Ordre = ordre de déclaration du DAG (et priorité de l'ordonnanceur).
MODULE_DEFAULTS: Dict[str, ModuleDefaults] = {
    "subfinder": ModuleDefaults(binaries=("subfinder",), params={"all_sources": True}),
    "crtsh": ModuleDefaults(
        timeout=10 * 60, params={"request_timeout": 60, "retries": 2, "backoff": 5.0},
        note="module Python (urllib), aucun binaire — interroge crt.sh, pas la cible",
    ),
    "amass": ModuleDefaults(binaries=("amass",), timeout=15 * 60, note="amass enum passif"),
    "subdomains": ModuleDefaults(note="fusion subfinder + crtsh + amass"),
    "dnsx": ModuleDefaults(binaries=("dnsx",)),
    "urlfinder": ModuleDefaults(binaries=("urlfinder",), params={"all": True, "retries": 1, "retry_wait": 30}),
    "gau": ModuleDefaults(
        binaries=("gau",), timeout=15 * 60, params={"threads": 2, "http_timeout": 45},
        note="archives publiques ; après urlfinder",
    ),
    "waybackurls": ModuleDefaults(
        binaries=("waybackurls",), timeout=15 * 60, note="archive Wayback ; après gau",
    ),
    "httpx": ModuleDefaults(binaries=("httpx",), network=True, rate=150, params={"threads": 50}),
    "nuclei1": ModuleDefaults(enabled=False, binaries=("nuclei",), network=True, rate=50, note="opt-in (-n)"),
    # katana passe AVANT takeover / naabu : à budget égal il garde la priorité. Il ne demande plus tout le
    # budget (150) mais 100 : les 50 req/s restants servent takeover / naabu / httpx ports pendant le crawl
    # (avec -n : nuclei #1 50 + katana 100 = 150).
    "katana": ModuleDefaults(
        binaries=("katana",), network=True, rate=100,
        params={
            "concurrency": 10, "store": True,
            "dedupe_hosts": True,          # un seul hôte par empreinte de contenu (httpx -hash sha256 + code + taille)
            "headless": "auto",            # auto | off | all : navigateur sans tête pour les hôtes à framework JS
            "headless_concurrency": 3,
            "no_sandbox": "auto",          # auto = -no-sandbox si root | on | off
        },
        note="stocke les réponses (responses/katana) pour jsluice et secrets ; headless ciblé, hôtes dédupliqués",
    ),
    "takeover": ModuleDefaults(
        binaries=("dnsx",), network=True, rate=10, timeout=15 * 60,
        params={"concurrency": 5, "http_timeout": 10},
        note="CNAME hors périmètre (dnsx) puis subzy sur ces seuls candidats ; sans subzy : liste de candidats seule",
    ),
    "naabu": ModuleDefaults(
        binaries=("naabu",), network=True, rate=100, timeout=30 * 60,
        params={"ports": "top-1000", "allow_full": False}, note="hôtes vivants seulement, -exclude-cdn",
    ),
    "httpx_ports": ModuleDefaults(
        binaries=("httpx",), network=True, rate=50, timeout=15 * 60, note="services web hors 80/443 trouvés par naabu",
    ),
    "nuclei_ports": ModuleDefaults(
        enabled=False, binaries=("nuclei",), network=True, rate=50, timeout=30 * 60,
        note="opt-in (-n) : réglages de la passe 1 sur les services web hors 80/443",
    ),
    "jsluice": ModuleDefaults(
        binaries=("jsluice",), timeout=10 * 60, params={"concurrency": 4, "max_bytes": 5_000_000},
        note="lit les JS stockés par katana (aucune requête)",
    ),
    "secrets": ModuleDefaults(
        binaries_any=("trufflehog", "gitleaks"), timeout=10 * 60,
        note="trufflehog (sans vérification) sinon gitleaks, sur les réponses stockées (aucune requête)",
    ),
    "merge_map": ModuleDefaults(params={"archive_dedupe": True, "archive_k": 3}),
    "httpx2": ModuleDefaults(binaries=("httpx",), network=True, rate=150),
    "tree": ModuleDefaults(),
    "arjun": ModuleDefaults(
        binaries=("arjun",), network=True, rate=20, timeout=30 * 60,
        params={"max_urls": 30, "threads": 2, "http_timeout": 15, "stable": False},
        note="paramètres cachés sur ≤ 30 URLs représentatives, débit accordé via --rate-limit",
    ),
    "nuclei2": ModuleDefaults(enabled=False, binaries=("nuclei",), network=True, rate=150, note="opt-in (-n)"),
}

# Modules de la famille nuclei : seuls opt-in (`-n`), dans tout preset.
NUCLEI_MODULES: Tuple[str, ...] = ("nuclei1", "nuclei_ports", "nuclei2")

# Presets : nom -> modules du jeu (listes simples). Un module nuclei listé n'est actif qu'avec `-n`
# (opt-in strict) ; `surface` n'en contient aucun, même avec `-n`.
PRESETS: Dict[str, List[str]] = {
    # Reconnaissance rapide : sous-domaines -> DNS -> vivacité (+ nuclei passe 1 avec -n).
    "fast": ["subfinder", "subdomains", "dnsx", "httpx", "nuclei1"],
    # Toute la surface, aucune attaque : jamais de nuclei.
    "surface": [
        "subfinder", "crtsh", "amass", "subdomains", "dnsx", "urlfinder", "gau", "waybackurls", "httpx",
        "katana", "takeover", "naabu", "httpx_ports", "jsluice", "secrets", "merge_map", "httpx2", "tree", "arjun",
    ],
    # Tout (nuclei toujours soumis à -n).
    "full": list(MODULE_DEFAULTS),
}

# Modules de « plomberie » (ni binaire ni trafic) dont l'aval lit l'état : ils sont activés
# automatiquement dès qu'un de leurs consommateurs l'est (sinon ces consommateurs s'ignoreraient
# faute de données). Les désactiver explicitement alors qu'un consommateur est actif = erreur.
# Ordre = ordre de résolution (merge_map avant subdomains, qui l'alimente en consommateurs).
PLUMBING: Dict[str, Tuple[str, ...]] = {
    "merge_map": ("httpx2",),
    "subdomains": (
        "dnsx", "httpx", "katana", "takeover", "naabu", "merge_map", "arjun", "tree",
        "nuclei1", "nuclei2",
    ),
}


def module_default(name: str) -> ModuleDefaults:
    return MODULE_DEFAULTS[name]


def default_param(module: str, key: str) -> Any:
    return MODULE_DEFAULTS[module].params[key]


def default_timeout_minutes(module: str) -> int:
    """Timeout par défaut en minutes (pour les options CLI exprimées en minutes)."""
    seconds = MODULE_DEFAULTS[module].timeout
    return 0 if seconds is None else max(int(seconds // 60), 1)


def preset_modules(name: str = "full") -> List[str]:
    try:
        return list(PRESETS[name])
    except KeyError:
        raise ValueError(f"preset inconnu {name!r} (disponibles : {', '.join(PRESETS)})") from None


def parse_module_timeouts(specs: List[str]) -> Dict[str, Optional[int]]:
    """`["amass=20", "gau=0"]` → {"amass": 1200, "gau": None} (minutes → secondes, 0 = illimité).

    Lève ValueError sur une forme invalide, un module inconnu ou une valeur négative.
    """
    result: Dict[str, Optional[int]] = {}
    for spec in specs:
        name, sep, value = spec.partition("=")
        name = name.strip().lower()
        if not sep or not name:
            raise ValueError(f"--module-timeout : « {spec} » invalide (attendu nom=minutes)")
        if name not in MODULE_DEFAULTS:
            raise ValueError(f"--module-timeout : module inconnu « {name} » ({', '.join(MODULE_DEFAULTS)})")
        try:
            minutes = float(value)
        except ValueError:
            raise ValueError(f"--module-timeout : « {value} » n'est pas un nombre de minutes") from None
        if minutes < 0:
            raise ValueError("--module-timeout : une durée négative n'a pas de sens (0 = illimité)")
        result[name] = max(int(minutes * 60), 1) if minutes > 0 else None
    return result


def parse_module_names(spec: str, option: str) -> Set[str]:
    """`"gau, amass"` → {"gau", "amass"} (virgules ou espaces). ValueError sur un module inconnu."""
    names = {token.lower() for token in spec.replace(",", " ").split() if token.strip()}
    unknown = sorted(names - set(MODULE_DEFAULTS))
    if unknown:
        raise ValueError(f"{option} : module(s) inconnu(s) « {', '.join(unknown)} » ({', '.join(MODULE_DEFAULTS)})")
    return names


def resolve_modules(
    preset: str,
    enable: Iterable[str] = (),
    disable: Iterable[str] = (),
    nuclei: bool = False,
    flags: Optional[Dict[str, bool]] = None,
) -> Dict[str, bool]:
    """État final de chaque module : {nom: actif}, dans l'ordre du registre.

    Précédence (la plus forte d'abord) : `flags` (options par module `--X/--no-X`, `--skip-X`)
    > `enable` / `disable` (`--enable` / `--disable`) > `preset`. Ensuite :

    - **nuclei** : sa famille (`NUCLEI_MODULES`) exige `nuclei=True` (`-n`). Un module nuclei
      listé par le preset reste simplement éteint sans `-n` ; l'activer *explicitement* (`enable`,
      flag) sans `-n` lève ValueError — jamais d'attaque silencieusement ignorée ni lancée.
    - **plomberie** (`PLUMBING`) : activée d'office si un consommateur l'est ; la désactiver
      explicitement alors lève ValueError.

    Lève ValueError sur un preset ou un nom de module inconnu, ou un module à la fois dans
    `enable` et `disable`.
    """
    base = set(preset_modules(preset))
    on, off, flags = set(enable), set(disable), dict(flags or {})
    for label, names in (("enable", on), ("disable", off), ("flags", flags)):
        unknown = sorted(set(names) - set(MODULE_DEFAULTS))
        if unknown:
            raise ValueError(f"module(s) inconnu(s) dans {label} : {', '.join(unknown)}")
    clash = sorted(on & off)
    if clash:
        raise ValueError(f"--enable et --disable : « {', '.join(clash)} » demandé(s) activé(s) ET désactivé(s)")

    wanted: Dict[str, bool] = {}
    for name in MODULE_DEFAULTS:
        if name in flags:
            wanted[name] = bool(flags[name])
        elif name in on:
            wanted[name] = True
        elif name in off:
            wanted[name] = False
        else:
            wanted[name] = name in base

    if not nuclei:
        for name in NUCLEI_MODULES:
            if wanted[name] and (name in on or flags.get(name)):
                raise ValueError(f"{name} fait partie de la famille nuclei, opt-in : ajoute -n (--nuclei) pour l'activer")
            wanted[name] = False

    for name, consumers in PLUMBING.items():
        needed = [c for c in consumers if wanted[c]]
        if not needed:
            continue
        if not wanted[name] and (name in flags or name in off):
            raise ValueError(f"{name} ne peut pas être désactivé : requis par {', '.join(needed)}")
        wanted[name] = True
    return wanted
