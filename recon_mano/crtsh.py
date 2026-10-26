"""Client crt.sh (Certificate Transparency) : sous-domaines vus dans des certificats.

Python pur (`urllib.request`), aucune dépendance. crt.sh est un service public :
on l'interroge, **pas la cible** — le module reste donc hors du budget de débit.

API utilisée : `https://crt.sh/?q=%25.<domaine>&output=json` → tableau JSON dont chaque
entrée porte `name_value`, les noms du certificat séparés par `\\n` (parfois avec
`*.` en tête, parfois des adresses e-mail). crt.sh est souvent lent ou répond 502/503/504
sous charge : on réessaie avec un délai croissant.

Rien ici n'écrit de fichier ni ne filtre le périmètre : le module (modules.py) s'en charge.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Iterable, List, Optional

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
USER_AGENT = "recon_mano (passive recon; certificate transparency lookup)"

# Un libellé DNS : lettres, chiffres, `-` et `_` (présent dans des certificats réels),
# jamais en début/fin de libellé pour `-`.
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


class CrtshError(Exception):
    """Échec d'une requête crt.sh. `retryable` : cela vaut la peine de réessayer."""

    def __init__(self, message: str, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


# --------------------------------------------------------------------------- #
# Nettoyage / analyse
# --------------------------------------------------------------------------- #


def clean_name(raw: str) -> str:
    """Un nom de certificat → nom d'hôte propre en minuscules, ou "" s'il est inutilisable.

    Retire `*.` (jokers) et le point final ; écarte les adresses e-mail, les noms
    contenant un joker au milieu, une adresse IP, un seul libellé, ou un libellé invalide.
    """
    name = raw.strip().lower().rstrip(".")
    if not name or "@" in name or " " in name:
        return ""
    while name.startswith("*."):
        name = name[2:]
    if not name or "*" in name or len(name) > 253:
        return ""
    labels = name.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return ""
    if all(label.isdigit() for label in labels):  # IPv4 : pas un nom d'hôte
        return ""
    return name


def parse_payload(payload: Any) -> List[str]:
    """Réponse JSON de crt.sh → noms nettoyés, dédoublonnés, triés.

    Toute entrée qui n'est pas un objet avec un `name_value` texte est ignorée.
    """
    if not isinstance(payload, list):
        raise CrtshError("réponse inattendue (pas un tableau JSON)")
    names = set()
    for entry in payload:
        value = entry.get("name_value") if isinstance(entry, dict) else None
        if not isinstance(value, str):
            continue
        for raw in value.splitlines():
            name = clean_name(raw)
            if name:
                names.add(name)
    return sorted(names)


# --------------------------------------------------------------------------- #
# Requête
# --------------------------------------------------------------------------- #


def fetch_once(domain: str, timeout: float) -> List[str]:
    """Une requête crt.sh pour `domain`. Lève CrtshError (retryable ou non)."""
    request = urllib.request.Request(
        CRTSH_URL.format(domain=domain), headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        # 5xx et 429 : service saturé, on réessaie ; les autres 4xx ne s'amélioreront pas.
        raise CrtshError(f"HTTP {exc.code}", retryable=exc.code >= 500 or exc.code == 429) from exc
    except (socket.timeout, TimeoutError) as exc:
        raise CrtshError(f"délai de {timeout:g}s dépassé") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise CrtshError(f"délai de {timeout:g}s dépassé") from exc
        raise CrtshError(f"connexion impossible ({exc.reason})") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise CrtshError(f"erreur réseau ({exc})") from exc
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        # crt.sh renvoie parfois une page d'erreur ou un JSON tronqué avec un 200.
        raise CrtshError("JSON invalide ou tronqué") from exc
    return parse_payload(payload)


def fetch_domain(
    domain: str,
    request_timeout: float = 60,
    retries: int = 2,
    backoff: float = 5.0,
    sleep: Callable[[float], None] = time.sleep,
    expired: Callable[[], bool] = lambda: False,
    notice: Callable[[str], None] = lambda message: None,
    fetch: Optional[Callable[[str, float], List[str]]] = None,
) -> List[str]:
    """Noms de `domain` d'après crt.sh, avec `retries` nouveaux essais (délai × 2 à chaque fois).

    `expired()` est consulté avant chaque essai (échéance du module). Lève CrtshError
    quand tous les essais ont échoué ou sur une erreur non réessayable.
    """
    fetch = fetch or fetch_once
    attempts = max(int(retries), 0) + 1
    last: Optional[CrtshError] = None
    for attempt in range(attempts):
        if attempt:
            wait = backoff * (2 ** (attempt - 1))
            notice(f"crt.sh {domain} : {last} — nouvel essai {attempt}/{attempts - 1} dans {wait:g}s")
            sleep(wait)
        if expired():
            raise CrtshError("échéance du module atteinte", retryable=False)
        try:
            return fetch(domain, request_timeout)
        except CrtshError as exc:
            last = exc
            if not exc.retryable:
                raise
    assert last is not None
    raise CrtshError(f"{last} (après {attempts} essai{'s' if attempts > 1 else ''})", retryable=False)


def fetch_domains(
    domains: Iterable[str],
    **kwargs: Any,
) -> Dict[str, Any]:
    """Interroge chaque domaine. Retourne {"names": [...], "errors": {domaine: message}}."""
    names: List[str] = []
    errors: Dict[str, str] = {}
    for domain in domains:
        try:
            names.extend(fetch_domain(domain, **kwargs))
        except CrtshError as exc:
            errors[domain] = str(exc)
    return {"names": sorted(set(names)), "errors": errors}
