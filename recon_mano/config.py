"""Registre des modules : état par défaut, débit et timeout, et presets.

Une seule table (`MODULE_DEFAULTS`) dit, pour chaque module du pipeline, s'il est
actif par défaut, le débit qu'il demande à la cible (modules réseau seulement), son
timeout et ses paramètres propres. Les options de la CLI (`--no-amass`,
`--amass-timeout`, `--module-timeout nom=min`…) **surchargent** ces valeurs ;
`Options` (modules.py) et les valeurs par défaut de Typer (cli.py) s'en servent
comme source unique.

`PRESETS` regroupera plus tard des jeux de modules (fast / surface…) : pour l'instant
seul `full` existe — tous les modules, chacun dans son état par défaut. Il n'y a
pas encore d'option `--mode`.

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
from typing import Any, Dict, List, Optional, Tuple


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
    # katana passe AVANT takeover / naabu : à budget égal il garde la priorité (nuclei #1 50 + katana 100).
    "katana": ModuleDefaults(
        binaries=("katana",), network=True, rate=150, params={"concurrency": 10, "store": True},
        note="stocke les réponses (responses/katana) pour jsluice et secrets",
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

# Presets : nom -> modules disponibles. `full` = tous ; nuclei y figure mais reste
# désactivé tant que `-n` n'est pas passé (opt-in strict).
PRESETS: Dict[str, List[str]] = {
    "full": list(MODULE_DEFAULTS),
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
