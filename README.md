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

Les étapes s'exécutent en parallèle quand leurs dépendances le permettent (voir
[Exécution parallèle](#exécution-parallèle)).

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

## Exécution parallèle

Chaque étape est un **module** indépendant ; un ordonnanceur lance un module dès
que toutes ses dépendances sont *terminées* (réussies, en échec, en timeout,
ignorées ou désactivées — c'est le module qui gère ses entrées manquantes et ses
replis). Deux modules sans lien de dépendance tournent en même temps :

```
subfinder ── dnsx ──┐
                    ├─ httpx ── katana ── merge_map ── httpx #2 ─┬─ tree
urlfinder ──────────┘                                            └─ nuclei (opt-in)
```

| Module | Dépend de | Rôle |
|---|---|---|
| `subfinder` | — | Sous-domaines (ou liste `--subdomains`) |
| `dnsx` | subfinder | Résolution DNS, wildcards filtrés |
| `urlfinder` | — | Archives, depuis l'apex seul : tourne **en parallèle** de subfinder + dnsx |
| `httpx` | dnsx, urlfinder | Fusion des hôtes et des URLs d'archive, une passe |
| `katana` | httpx | Crawl des seeds vivantes |
| `merge_map` | katana | `all_urls.txt` = seeds vivantes + crawl, périmètre strict (léger, sans réseau) |
| `httpx2` | merge_map | Revalidation de la carte |
| `tree` | httpx2 | `urls_tree.html` |
| `nuclei` | httpx2 | Opt-in (`-n`) |

- **`--workers N`** (défaut 4) : nombre maximum de modules simultanés.
  **`--sequential`** = `--workers 1` (un seul module à la fois, ordre historique) —
  pratique pour déboguer ou comparer.
- **`--max-rps N`** (défaut 150) : budget de débit **global**. `--rate-limit` et
  `--nuclei-rate-limit` ne sont plus que des débits *demandés* ; la somme des débits
  accordés aux modules qui frappent la cible (httpx, katana, nuclei) ne dépasse
  jamais `--max-rps`. Le budget est global parce que c'est la cible qui encaisse
  le trafic cumulé, pas chaque outil : deux modules à 150 req/s en parallèle font
  300 req/s côté serveur, ce qui déclenche WAF et bans. Un module reçoit
  `min(demandé, budget restant)` au démarrage ; s'il reste moins de
  `min(demandé, 10)`, il attend qu'un autre module libère du budget. Les modules
  qui n'attaquent pas la cible (subfinder, dnsx, urlfinder, merge_map, tree) n'en
  consomment pas. Pour dépasser 150 req/s, relever `--max-rps` en même temps que
  `--rate-limit`.
- **Binaire manquant** : le module est `désactivé` (« binaire X introuvable »), le
  reste du pipeline continue avec ses replis (ex. sans dnsx, httpx part de la
  liste subfinder). **Exception dans un module** : `échec`, message dans le
  récapitulatif (traceback complet avec `-v`), les modules indépendants finissent.
  Si subfinder ne rend aucun hôte en périmètre, il est en échec et tout l'aval
  est ignoré proprement (code retour 1).
- **katana ne crawle que du confirmé vivant** : si httpx n'a trouvé aucune URL
  vivante, katana est *ignoré* (jamais de crawl de cibles non confirmées). Le repli
  sur les entrées brutes fusionnées n'existe que pour `--skip-httpx`.
- **Aucune question pendant l'exécution** : périmètre et cibles nuclei
  (`hôtes vivants` / `toutes les URLs vivantes`) sont demandés au lancement ;
  `-y`, `--in-scope` et `--nuclei-targets` évitent les questions, hors terminal
  les cibles nuclei valent « hôtes ».
- **Affichage** : un board live (une ligne par module : état, lignes écrites, temps,
  débit accordé) ; chaque module imprime son bloc de détails à sa fin, puis un
  récapitulatif final avec une ligne par module (✓ terminé · ✗ échec · ⏱ timeout ·
  – ignoré · ⊘ désactivé) et la durée réelle face au cumul des modules. Avec `-v`,
  pas de board : flux des outils préfixé `outil │` et heartbeat.
- **`run_stats.json`** : par module, statut, début/fin (décalage en s), durée,
  résultat, débit accordé, note ; plus `wall_clock` (durée réelle),
  `sum_of_durations` (cumul) et `parallel_gain` (cumul − durée réelle).
- **`run_config.json`** : cible, périmètre (apex, exclusions, filtre actif), codes
  vivants / `--match-codes`, modules activés, versions (paquet, Python).

### `recon_mano merge` : rejouer la fusion

```bash
recon_mano merge sortie
```

Reconstruit, **sans lancer aucun outil**, la fin de la chaîne à partir des
fichiers déjà présents : `all_urls.txt` (seeds `urls_live.txt` + `06_katana.txt`,
périmètre strict), `urls_all_final.txt` / `urls_200_final.txt` /
`urls_live_final.txt` (depuis `08_httpx2.jsonl`, sinon `05_httpx.jsonl`) et
`urls_tree.html`. Le périmètre et les codes vivants viennent de `run_config.json`
(à défaut : périmètre déduit du nom du dossier, codes par défaut). Utile après
avoir ajouté une exclusion à `run_config.json`, édité une liste à la main ou
relancé un seul module. Les rejets du rejeu sont ajoutés à `rejected_scope.tsv`
sous l'étape `merge`.

## Sorties

| Fichier | Contenu |
|---|---|
| `01_subfinder.txt` | Sous-domaines théoriques (bruts) |
| `02_dnsx.txt` | Sous-domaines résolvant, wildcards filtrés |
| `03_urlfinder.txt` | Chemins historiques issus des archives |
| `04_httpx_input.txt` | Fusion des deux branches (entrée httpx) |
| `05_httpx.jsonl` | Sortie httpx brute |
| `urls_all.txt` / `urls_200.txt` | Surface vivante annotée / 200 — **avant** crawl |
| `urls_live.txt` | URLs nues dont le code est dans `--live-codes` — **seeds de katana** |
| `06_katana.txt` | Crawl actif (URLs découvertes, sans code HTTP) |
| `all_urls.txt` | Carte brute (seeds + crawl, non revalidée) |
| `08_httpx2.jsonl` | httpx #2 brut (revalidation de la carte) |
| **`urls_all_final.txt`** | **Triage manuel** — surface vivante complète, annotée (archives + katana) |
| **`urls_200_final.txt`** | **Tous les endpoints 200** (archives + katana) |
| `urls_live_final.txt` | Liste live après httpx #2 — **cibles de nuclei** |
| `rejected_scope.tsv` | Entrées écartées par le filtre de périmètre (`étape<TAB>hôte<TAB>ligne`), remis à zéro à chaque run |
| `07_nuclei_input.txt` | Cibles réellement envoyées à nuclei |
| `nuclei.txt` | Findings nuclei (avec `--nuclei`) |
| **`urls_tree.html`** | **Arbre interactif repliable des 200** (à ouvrir au navigateur) |
| `run_config.json` | Config du run (cible, périmètre, codes, modules) — relue par `recon_mano merge` |
| `run_stats.json` | Statut, durées et débit par module ; `wall_clock`, `sum_of_durations`, `parallel_gain` |

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

Le lancement affiche une bannière, un panneau de config, puis un **board live**
(une ligne par module : état, lignes écrites, temps écoulé, débit accordé) prouve
que ça avance pendant que les modules tournent en parallèle ; chaque module imprime
son bloc de résultats (icône, nombre d'entrées, durée, diagnostics) quand il se
termine, avec une estimation grossière de durée pour les étapes lourdes. À la fin :
la liste des livrables et une **table récapitulative** (statut, résultat et temps
par module, durée réelle face au cumul).

Options utiles :

| Flag | Effet |
|---|---|
| `--clean` | Supprime les anciens fichiers de sortie avant de lancer |
| `-v`, `--verbose` | Affiche les commandes exactes et le flux des outils en direct (sans board live) |
| `--check` | Vérifie la présence des outils puis quitte |
| `--all-sources` | `subfinder -all` (plus lent, plus complet) |
| `--subdomains` | Sous-domaines déjà connus (fichier ou liste virgulée, ex: trouvés via `ffuf`) : ignore l'étape subfinder et part directement de cette liste |
| `--no-wildcard-filter` | Désactive `dnsx -wd` |
| `--match-codes` | Codes retenus par httpx (défaut : large, 401/403/500 compris) — pilote les fichiers de triage |
| `--live-codes` | Codes jugés « vivants » (défaut `200,301,302,307,308,401,403`) : seules ces URLs alimentent katana et nuclei, jamais les 404/5xx |
| `--depth` | Profondeur katana (défaut 2 — les seeds sont déjà profondes) |
| `--scope` | `katana -fs` : `rdn` (défaut), `fqdn`, `dn` ou regex |
| `--js-crawl` | `katana -jc` — endpoints lus dans le JS, **non requêtés donc non validés** |
| `--katana-max-pages` / `--katana-duration` | Garde-fous crawl : plafond pages/domaine (`-mdp`, défaut 3000) · durée max (`-ct`, défaut 10m) |
| `--katana-filter-similar` / `--katana-ignore-query` | Collapse chemins similaires (`-fsu`, défaut on) · query params (`-iqp`, défaut off) |
| `--urlfinder-all` / `--urlfinder-curated` | Toutes les sources (défaut) vs sous-ensemble curé |
| `--urlfinder-retries` | Réessais si urlfinder rend 0 (défaut 1) |
| `--urlfinder-retry-wait` | Base du délai entre essais urlfinder, en s, progressif ×n (défaut 30) |
| `--rate-limit` | Requêtes/seconde demandées par httpx et katana (défaut 150), plafonnées par `--max-rps` |
| `--max-rps` | Budget de débit **global** en req/s partagé par httpx, katana et nuclei (défaut 150) — voir [Exécution parallèle](#exécution-parallèle) |
| `--workers` | Modules exécutés en parallèle au maximum (défaut 4) |
| `--sequential` | Un module à la fois (= `--workers 1`), pour déboguer ou comparer |
| `--revalidate` / `--no-revalidate` | Passe httpx #2 sur la carte katana → `urls_200_final.txt` (tous les 200). Défaut on |
| `--tree` / `--no-tree` | Génère `urls_tree.html` (arbre interactif des 200). Défaut on |
| `--in-scope` | Domaines **ajoutés à la cible** dans le périmètre (liste virgulée, ex: `devinci.fr,esilv.fr`). Sans lui, la question est posée au lancement (terminal) |
| `--exclude` | Hôtes/domaines hors périmètre (liste virgulée) : égaux ou sous-domaines d'une entrée |
| `--no-scope-filter` | Désactive le filtre de périmètre (comportement historique : tout est gardé) |
| `-y`, `--yes` | Ne pose aucune question au lancement (périmètre = cible + `--in-scope`, cibles nuclei = hôtes) |
| `-n`, `--nuclei` | Lance nuclei sur les hôtes/URLs **vivants** (désactivé par défaut) |
| `--nuclei-mode` | `auto` (`-as` tech-aware, défaut) · `curated` · `full` |
| `--nuclei-targets` | `hosts` (défaut) · `urls` — sinon demandé **au lancement** dans un terminal |
| `--nuclei-severity` / `--nuclei-rate-limit` / `--nuclei-max-host-error` | Sévérités · débit demandé (plafonné par `--max-rps`) · abandon hôte (défaut `medium,high,critical` / 150 / 10) |
| `--nuclei-timeout` / `--nuclei-concurrency` / `--nuclei-retries` | Vitesse : timeout par requête · templates parallèles · retries (défaut 5 / 25 / 1) |
| `--skip-*` | `dnsx`, `urlfinder`, `httpx`, `katana` — le module est ignoré, l'aval retombe sur l'étape précédente |

Exemple complet :

```bash
recon_mano exemple.com sortie --clean -n
```

Le **périmètre** est appliqué strictement après chaque étape (subfinder, dnsx,
urlfinder, katana, carte finale, cibles nuclei) : un hôte doit être la cible, un
domaine de `--in-scope` ou un de leurs sous-domaines, et ne pas être dans
`--exclude`. Ce qui est écarté est journalisé dans `rejected_scope.tsv`.

Régénérer l'arbre HTML interactif d'un scan existant, avec la sous-commande
`report` (sur un **dossier** : prend la meilleure liste de 200 ; sur un
**fichier** : le transforme en `<fichier>.html`) :

```bash
recon_mano report sortie                      # → sortie/urls_tree.html
recon_mano report sortie/urls_all_final.txt   # arbre tous-codes (401/403/500)
```

Rejouer la fusion finale d'un scan existant (carte, listes `*_final`, arbre) sans
relancer aucun outil, avec la sous-commande `merge` (détails dans
[Exécution parallèle](#recon_mano-merge--rejouer-la-fusion)) :

```bash
recon_mano merge sortie
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
