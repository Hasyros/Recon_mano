# Recon Mano

Pipeline Python de découverte et reconnaissance de sous-domaines, orchestrant
`subfinder`, `dnsx`, `urlfinder`, `httpx`, `katana` et (en option) `nuclei`.

> À n'utiliser que sur des cibles pour lesquelles tu disposes d'une autorisation
> explicite : programme de bug bounty dans son périmètre, mission de pentest, ou
> infrastructure t'appartenant.

## Workflow

```
cible ─┬─ subfinder → dnsx (-wd) ── hôtes ──┐
       │                                     ├─ merge → httpx ─┬─ urls_all.txt
       └─ urlfinder (-d apex) ──── URLs ────┘                  └─ urls_200.txt → katana
                                                                                   │
                                               all_urls → httpx #2 (revalidation) ─┘
                                                     │
                                     urls_200_final.txt · urls_tree.html
                                                     │
                                               [--nuclei] (opt-in)
```

**httpx #2** est essentiel : katana découvre des URLs par crawl mais ne connaît
pas leur code HTTP. La revalidation donne les statuts réels et **`urls_200_final.txt`**
= tous les 200 (archives *et* découvertes katana). L'arbre `urls_tree.html` est
généré depuis cette liste.

Trois choix de conception qui expliquent la forme du graphe :

**urlfinder est une branche parallèle, pas un maillon en aval de httpx.**
Les archives sont la seule source où un hôte *mort* a encore de la valeur. En
filtrant sur les hôtes vivants avant d'interroger la Wayback, on ne lui demande
jamais ce qu'il y avait sur les hôtes tombés — précisément les fichiers oubliés
qu'on cherche. Il part du domaine apex : un seul appel couvre déjà tous les
sous-domaines connus des archives, au lieu de N appels rate-limités.

**Les deux branches sont fusionnées avant une passe httpx unique.**
Chaîner `dnsx → urlfinder → httpx` perdrait tout hôte sans historique d'archive
— un `staging-v2` mis en ligne le mois dernier résout, sert du HTTP, mais la
Wayback ne le connaît pas. Les deux branches couvrent des ensembles disjoints
(ce qui est vivant *maintenant* / ce qui a existé *avant*), donc on les réunit
et on ne paie qu'une seule passe réseau.

**httpx n'est pas une étape, c'est un filtre.**
On le ré-applique à chaque fois qu'on génère des URLs depuis une source non
vivante. La sortie urlfinder est historique : sans ce filtre, on sèmerait katana
avec des milliers d'URLs mortes.

## Sorties

| Fichier | Contenu |
|---|---|
| `01_subfinder.txt` | Sous-domaines théoriques (bruts) |
| `02_dnsx.txt` | Sous-domaines résolvant, wildcards filtrés |
| `03_urlfinder.txt` | Chemins historiques issus des archives |
| `04_httpx_input.txt` | Fusion des deux branches (entrée httpx) |
| `05_httpx.jsonl` | Sortie httpx brute |
| `urls_all.txt` / `urls_200.txt` | Surface vivante annotée / 200 — **avant** crawl |
| `06_katana.txt` | Crawl actif (URLs découvertes, sans code HTTP) |
| `all_urls.txt` | Carte brute (seeds + crawl, non revalidée) |
| `08_httpx2.jsonl` | httpx #2 brut (revalidation de la carte) |
| **`urls_all_final.txt`** | **Triage manuel** — surface vivante complète, annotée (archives + katana) |
| **`urls_200_final.txt`** | **Tous les endpoints 200** (archives + katana) |
| `07_nuclei_input.txt` | Cibles réellement envoyées à nuclei |
| `nuclei.txt` | Findings nuclei (avec `--nuclei`) |
| **`urls_tree.html`** | **Arbre interactif repliable des 200** (à ouvrir au navigateur) |

Le fichier à lire est **`urls_all_final.txt`** (ou l'arbre `urls_tree.html`), pas
`urls_200_final.txt` seul. Un `403` est un endpoint qui existe mais qui est
protégé — c'est souvent *le* bug. Un `401` marque la surface d'API authentifiée,
un `500` un point de crash. Et beaucoup d'applis rendent `200` sur un soft-404,
donc « 200 » n'est même pas un filtre fiable pour « ça existe ».

## Installation

### Dépendances Python

```bash
python -m pip install -r requirements.txt
```

Sur Kali, si l'environnement est géré par le système et que tu acceptes le
risque d'installer globalement : ajoute `--break-system-packages`.

### Outils externes

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest   # optionnel
```

> **Piège `httpx`.** Le client HTTP Python s'installe aussi sous le nom `httpx`
> dans le PATH et n'a aucun des flags attendus. `check` distingue les deux via
> `httpx -version` ; si le mauvais binaire l'emporte, passe le bon chemin avec
> `--httpx-bin`.

### Lancer sans rien installer

Depuis le dossier du projet, aucune installation n'est nécessaire :

```bash
python -m recon_mano --check
python -m recon_mano exemple.com sortie
```

### (Optionnel) La commande courte `recon_mano`

Pour taper `recon_mano` au lieu de `python -m recon_mano`. Sur **Kali / Debian**,
le Python système est *externally-managed* (PEP 668) et refuse `pip install` —
c'est normal. Trois options, de la plus propre à la plus rapide :

```bash
# 1. pipx (recommandé par Kali) — venv isolé, commande sur le PATH
pipx install -e .        # ou: pipx install .

# 2. venv dédié
python3 -m venv .venv && .venv/bin/pip install -e .
# puis: .venv/bin/recon_mano …   (ou `source .venv/bin/activate`)

# 3. override système (au risque de casser des paquets)
python -m pip install -e . --break-system-packages
```

Vérifier les outils :

```bash
recon_mano --check     # ou: python -m recon_mano --check
```

## Usage

Invocation minimale — cible en premier, nom de sortie en second :

```bash
recon_mano exemple.com sortie
```

Le nom de sortie est optionnel (défaut : le nom de la cible). Sans installation,
la même chose marche via `python -m recon_mano exemple.com sortie`.

Le lancement affiche une bannière, un panneau de config, puis chaque étape est un
séparateur avec icône. Pendant qu'un outil tourne, un **compteur de lignes live +
temps écoulé** (`🕷️ katana · 3120 lignes · 1m04s`) prouve que ça avance, et une
estimation grossière de durée précède les étapes lourdes. À la fin : la liste des
livrables et une **table récapitulative** (résultat + temps par étape).

Options utiles :

| Flag | Effet |
|---|---|
| `--clean` | Supprime les anciens fichiers de sortie avant de lancer |
| `-v`, `--verbose` | Affiche les commandes exactes et le flux des outils en direct |
| `--check` | Vérifie la présence des outils puis quitte |
| `--all-sources` | `subfinder -all` (plus lent, plus complet) |
| `--no-wildcard-filter` | Désactive `dnsx -wd` |
| `--match-codes` | Codes retenus par httpx (défaut : large, 401/403/500 compris) |
| `--depth` | Profondeur katana (défaut 2 — les seeds sont déjà profondes) |
| `--scope` | `katana -fs` : `rdn` (défaut), `fqdn`, `dn` ou regex |
| `--js-crawl` | `katana -jc` — endpoints lus dans le JS, **non requêtés donc non validés** |
| `--katana-max-pages` / `--katana-duration` | Garde-fous crawl : plafond pages/domaine (`-mdp`, défaut 3000) · durée max (`-ct`, défaut 10m) |
| `--katana-filter-similar` / `--katana-ignore-query` | Collapse chemins similaires (`-fsu`, défaut on) · query params (`-iqp`, défaut off) |
| `--urlfinder-all` / `--urlfinder-curated` | Toutes les sources (défaut) vs sous-ensemble curé |
| `--urlfinder-retries` | Réessais si urlfinder rend 0 (défaut 1) |
| `--urlfinder-retry-wait` | Base du délai entre essais urlfinder, en s, progressif ×n (défaut 30) |
| `--rate-limit` | Requêtes/seconde (défaut 150) |
| `--revalidate` / `--no-revalidate` | Passe httpx #2 sur la carte katana → `urls_200_final.txt` (tous les 200). Défaut on |
| `--tree` / `--no-tree` | Génère `urls_tree.html` (arbre interactif des 200). Défaut on |
| `--in-scope` | Restreindre à ces domaines (liste virgulée, ex: `devinci.fr,esilv.fr`). Vide = tout garder |
| `--nuclei` | Lance nuclei sur les hôtes/URLs **vivants** |
| `--nuclei-mode` | `auto` (`-as` tech-aware, défaut) · `curated` · `full` |
| `--nuclei-targets` | `hosts` (défaut) · `urls` — sinon demandé dans un terminal |
| `--nuclei-severity` / `--nuclei-rate-limit` / `--nuclei-max-host-error` | Sévérités · débit · abandon hôte (défaut `medium,high,critical` / 150 / 10) |
| `--nuclei-timeout` / `--nuclei-concurrency` / `--nuclei-retries` | Vitesse : timeout par requête · templates parallèles · retries (défaut 5 / 25 / 1) |
| `--skip-*` | `dnsx`, `urlfinder`, `httpx`, `katana` — chaque skip retombe sur l'étape précédente |

Exemple complet :

```bash
recon_mano exemple.com sortie --clean --nuclei
```

Régénérer l'arbre HTML interactif d'un scan existant, avec la sous-commande
`report` (sur un **dossier** : prend la meilleure liste de 200 ; sur un
**fichier** : le transforme en `<fichier>.html`) :

```bash
recon_mano report sortie                      # → sortie/urls_tree.html
recon_mano report sortie/urls_all_final.txt   # arbre tous-codes (401/403/500)
```

`nuclei` est désactivé par défaut : c'est la seule étape qui envoie des
payloads, elle ne doit jamais partir sans geste explicite.

### urlfinder qui rend 0

urlfinder interroge des archives publiques (Wayback, CommonCrawl…) fortement
rate-limitées : un run peut rendre **0** alors que le même appel, lancé seul
quelques minutes plus tard, en rend des milliers. Ce n'est presque jamais une
cible sans historique.

Deux causes possibles à un résultat maigre, et le pipeline gère les deux :

- **Sources par défaut trop restreintes.** Sans `-all`, urlfinder n'interroge
  qu'un sous-ensemble curé — d'où un « 79 au lieu de 19000 ». Le pipeline passe
  **`-all` par défaut** (`--urlfinder-curated` pour revenir au sous-ensemble).
- **Throttling par IP, souvent silencieux.** Les grosses sources (waybackarchive,
  commoncrawl) répondent fréquemment par une page **vide en HTTP 200** quand ton
  IP a épuisé son quota — pas d'erreur 429. urlfinder log alors `Found 30 urls`
  **sans warning**. C'est le cas le plus trompeur : un premier run frais rend
  19000, puis les suivants (à force de relancer) tombent à quelques dizaines.

urlfinder tourne désormais en **`-v`** (plus de `-silent`) : sa sortie par source
est capturée et le pipeline **affiche toujours** son récap `Found N urls`, les
`[WRN]` de sources en échec, et — quand le résultat est bas *sans* erreur — un
avertissement explicite de throttling silencieux. Les URLs propres passent par
`-o`, indépendant du silent.

**Aucun timeout n'est imposé** : urlfinder tourne autant qu'il en a besoin (un
run sain prend 2+ minutes). Le **chrono par étape** aide à lire un résultat :
`→ 0 entrées · 5s` = coupé net ; `→ 69 entrées · 36s` = dégradé/throttlé ;
`→ 19000 · 2m` = run sain.

**Retrouver du volume** — le levier dépend de la source :

- waybackarchive / commoncrawl sont **gratuits et sans clé** : leur throttle est
  par **IP + fenêtre de temps**. Remèdes : arrêter de marteler et **laisser la
  fenêtre reposer** (quelques heures), ou changer d'**IP** (VPN / `-proxy`).
- une **clé d'API** dans `~/.config/urlfinder/provider-config.yaml` ajoute
  *d'autres* sources (urlscan, virustotal…) — ça élargit la couverture mais ne
  dé-throttle pas Wayback.

Sur résultat vide, le pipeline **réessaie** (`--urlfinder-retries`, défaut 1)
avec un délai **progressif** (`--urlfinder-retry-wait` × n° d'essai).

### Volume

`urlfinder` peut rendre 10k à 500k URLs sur une cible moyenne. Si katana traîne,
passe la liste dans [`uro`](https://github.com/s0md3v/uro) avant — il collapse
`/user/1`, `/user/2`… et les variantes de query en un seul motif :

```bash
uro -i output/urls_200.txt -o output/urls_200_uro.txt
```
