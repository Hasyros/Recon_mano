# Recon Mano — Workflow & utilisation

Guide complet du pipeline de reconnaissance. Le [README](README.md) sert de
démarrage rapide ; ce document explique **pourquoi** la chaîne est construite
ainsi et **comment** la piloter.

> ⚠️ À n'utiliser que sur des cibles pour lesquelles tu as une **autorisation
> explicite** : programme de bug bounty dans son périmètre, mission de pentest,
> ou infrastructure t'appartenant.

---

## 1. La logique : un entonnoir

L'idée directrice est d'aller **du plus large au plus précis**. On récolte un
maximum de données brutes, on élimine ce qui ne répond pas, et on ne creuse que
ce qui est vivant.

```
cible.com
   │
   ├─ [1] subfinder ─→ [2] dnsx (-wd) ──── hôtes vivants ─────┐
   │        (large)        (on valide)                         │
   │                                                           ├─ [4] httpx ─┬─→ urls_all.txt  (triage)
   │                                                           │  (filtre +   │
   └─ [3] urlfinder (-d apex) ───────────── URLs d'archive ───┘   annotation) └─→ urls_200.txt ─→ [5] katana
            (le passé)                                                                                  │
                                                              all_urls.txt (carte brute) ◀─────────────┘
                                                                    │
                                                          [5b] httpx #2 (revalidation) ─→ urls_200_final.txt
                                                                    │                     urls_all_final.txt
                                                          [6] nuclei (--nuclei, opt-in)
```

Deux branches se rejoignent : **le présent** (ce qui répond aujourd'hui, via
subfinder→dnsx) et **le passé** (ce qui a existé, via les archives). On les
fusionne, on valide, on crawle — puis **httpx #2** revalide la carte crawlée
(katana ne connaît pas les codes HTTP de ce qu'il découvre), avant nuclei.

---

## 2. Les étapes en détail

Chaque outil est lancé par le pipeline avec les flags ci-dessous. `-silent` est
ajouté automatiquement (sauf pour urlfinder, et sauf en mode `-v`).

### [1] subfinder — découverte passive

- **But** : trouver tous les sous-domaines *théoriques* de la cible.
- **Entrée** : le domaine apex.
- **Sortie** : `01_subfinder.txt` — longue liste brute, avec du bruit et des hôtes morts.

```bash
subfinder -d cible.com -o 01_subfinder.txt [-all]
```

`--all-sources` active `-all` (plus de sources, plus lent). Si subfinder ne
trouve rien, le pipeline s'arrête là.

### [2] dnsx — validation réseau

- **But** : éliminer les sous-domaines qui ne résolvent plus, et **filtrer les wildcards**.
- **Entrée** : `01_subfinder.txt`.
- **Sortie** : `02_dnsx.txt` — hôtes techniquement actifs.

```bash
dnsx -l 01_subfinder.txt -o 02_dnsx.txt -wd cible.com
```

> **Important** : le filtrage wildcard n'est **pas** activé par défaut dans dnsx.
> Sans `-wd`, un `*.cible.com` fait résoudre *tous* les faux sous-domaines, qui
> polluent tout l'aval. Le pipeline passe `-wd` par défaut
> (`--no-wildcard-filter` pour le désactiver). Si dnsx ne rend rien, on retombe
> sur la liste subfinder plutôt que de bloquer.

### [3] urlfinder — fouille passive des chemins

- **But** : retrouver des chemins et fichiers *oubliés* dans les archives publiques (Wayback, CommonCrawl…).
- **Entrée** : le **domaine apex** (pas la sortie dnsx — voir §3).
- **Sortie** : `03_urlfinder.txt` — URLs historiques.

```bash
urlfinder -d cible.com -v -o 03_urlfinder.txt [-all]
```

C'est l'étape la plus capricieuse ; tout le §5 lui est consacré. Points clés :
`-all` par défaut (toutes les sources), `-v` au lieu de `-silent` (pour voir le
diagnostic par source), **aucun timeout**, et un retry sur résultat vide.

### [4] httpx — validation + annotation

- **But** : ne garder que ce qui **répond vraiment**, et l'annoter pour le triage.
- **Entrée** : `04_httpx_input.txt` = fusion des hôtes (branche 1) **et** des URLs d'archive (branche 3).
- **Sortie** : deux fichiers (voir ci-dessous).

```bash
httpx -l 04_httpx_input.txt -json -status-code -title -content-length \
      -tech-detect -match-code 200,204,301,302,307,308,401,403,405,500,502,503 \
      -threads 50 -rate-limit 150 -o 05_httpx.jsonl
```

Le JSON brut (`05_httpx.jsonl`) est découpé en deux :

| Fichier | Contenu | Usage |
|---|---|---|
| `urls_all.txt` | URLs vivantes **annotées** `url [code] [taille] [titre] [tech]`, tous codes retenus | **triage manuel** — c'est ici que sont les bugs |
| `urls_200.txt` | uniquement les `200` | **seeds** pour katana |

> On **ne filtre pas** sur 200 comme sortie unique : un `401`/`403` = endpoint
> protégé (souvent *le* bug), un `500` = crash (point d'injection probable). Les
> jeter reviendrait à jeter les meilleures pistes. → voir `urls_all.txt`.

### [5] katana — exploration active

- **But** : découvrir les liens et chemins qui existent *aujourd'hui*.
- **Entrée** : `urls_200.txt` (seeds vivantes). Si aucun 200, repart des entrées fusionnées.
- **Sortie** : `06_katana.txt`.

```bash
katana -list urls_200.txt -depth 2 -field-scope rdn -rate-limit 150 -concurrency 10 \
       -filter-similar -max-domain-pages 3000 -crawl-duration 10m -o 06_katana.txt [-jc]
```

- `-depth 2` (et non 3) : les seeds sont déjà profondes, inutile de redescendre de 3 niveaux depuis chacune. Pas de plafond dur : le coût est ~exponentiel (`liens^depth`).
- `-field-scope rdn` : les archives ramènent des hôtes tiers (CDN, liens sortants). Sans périmètre, katana crawle hors scope — ce qui peut te sortir d'un programme de bug bounty.
- `--js-crawl` (`-jc`) : ajoute les endpoints lus dans le JS. **Non requêtés, donc non validés** — à traiter comme des pistes, pas comme du vivant.

**Garde-fous anti-explosion** (par défaut). katana déduplique déjà les URLs
identiques, mais garde distinctes les **variantes** — `?page=1,2,3…` et
`/evenement/1..900` — ce qui fait grimper à 100k+ lignes et **pilonne le WAF** :

- `-filter-similar` (`--no-katana-filter-similar` pour couper) : collapse les chemins numérotés similaires.
- `--katana-max-pages 3000` (`-mdp`, 0 = illimité) : plafond dur de pages par domaine.
- `--katana-duration 10m` (`-ct`, vide = illimité) : coupe le crawl après la durée.
- `--katana-ignore-query` (`-iqp`, **off** par défaut) : collapse aussi les query params — plus agressif, car les params ont de la valeur en bug hunting.

### Cartographie finale

`all_urls.txt` = fusion des seeds katana + du crawl katana → la carte brute du
présent. Mais katana **ne connaît pas les codes HTTP** de ce qu'il découvre.

### [5b] httpx — revalidation de la carte

- **But** : donner les vrais statuts aux URLs découvertes par katana (jamais testées).
- **Entrée** : `all_urls.txt`.
- **Sortie** : `urls_all_final.txt` (annotée, complète) + `urls_200_final.txt` (**tous** les 200).

Sans cette passe, `urls_200.txt` ne couvre que la surface d'*avant* crawl. `-fsu`
et les garde-fous ayant borné katana, revalider ~10-20k URLs (souvent vivantes,
donc rapides) est raisonnable. C'est le principe « httpx est un filtre qu'on
ré-applique à chaque source non vivante », appliqué **après** katana cette fois.
`--no-revalidate` pour couper. nuclei cible ensuite cette surface revalidée.

### [6] nuclei — optionnel, opt-in

Désactivé par défaut. C'est la **seule** étape qui envoie des payloads : elle ne
part jamais sans `--nuclei` explicite.

**Le modèle nuclei.** Coût ≈ `cibles × templates × requêtes/template`. Le dépôt
officiel a ~6000-9000 templates ; les lancer tous contre chaque URL = des
millions de requêtes (10+ min pour *un* hôte). On maîtrise les trois facteurs.

**Templates — `--nuclei-mode` :**

| Mode | Ce qu'il lance | Pour |
|---|---|---|
| `auto` *(défaut)* | `-as` : Wappalyzer détecte la stack et ne lance **que** les templates correspondants | rapide, précis, peu de bruit |
| `curated` | `-tags cve,exposure,misconfig,takeover,default-login -etags fuzz,dos,intrusive` | prévisible |
| `full` | tout ce que couvre `--nuclei-severity` | audit lent d'une poignée d'hôtes |

**Cibles — `--nuclei-targets` :** toujours la surface **vivante** (sortie httpx),
jamais le dump urlfinder brut (URLs mortes = temps infini).

- `hosts` *(défaut)* : hôtes vivants dédupliqués (`scheme://host`). Rapide.
- `urls` : toutes les URLs vivantes (chemins d'archive qui répondent encore inclus).

Si `--nuclei-targets` n'est pas donné et qu'on est dans un terminal, le pipeline
**demande** hosts vs urls après httpx (en montrant les deux comptes).

```bash
# auto sur hôtes vivants (défaut), périmètre restreint
recon_mano cible.com --nuclei --in-scope cible.com
# curated sur toutes les URLs vivantes, plus lent mais plus fin
recon_mano cible.com --nuclei --nuclei-mode curated --nuclei-targets urls
```

`-mhe` (défaut 10) fait abandonner un hôte mort après 10 erreurs au lieu de 30.

---

## 3. Trois décisions de conception

**urlfinder est une branche parallèle, pas un maillon après httpx.**
Les archives sont la seule source où un hôte *mort* a encore de la valeur. Le
brancher après httpx (donc après filtrage des vivants) reviendrait à ne jamais
demander à Wayback ce qu'il y avait sur les hôtes tombés — précisément les
fichiers oubliés qu'on cherche. Il part du **domaine apex** : un seul appel
couvre déjà tous les sous-domaines connus des archives, au lieu de N appels
rate-limités.

**Les deux branches fusionnent avant une passe httpx unique.**
Chaîner `dnsx → urlfinder → httpx` perdrait tout hôte sans historique : un
`staging-v2` mis en ligne le mois dernier résout et sert du HTTP, mais Wayback ne
le connaît pas. Les branches couvrent des ensembles disjoints (vivant *maintenant*
/ existé *avant*), donc on les réunit et on ne paie qu'**une** passe réseau.

**httpx n'est pas une étape, c'est un filtre.**
On le ré-applique dès qu'on génère des URLs depuis une source *non vivante*
(archives). Sans lui, on sèmerait katana avec des milliers d'URLs mortes.

---

## 4. Utilisation

### Installation

Dépendances Python :

```bash
python -m pip install -r requirements.txt --break-system-packages
```

Les 5 outils externes doivent être dans le `PATH` : `subfinder`, `dnsx`,
`httpx` (**celui de ProjectDiscovery**), `urlfinder`, `katana` (+ `nuclei` si tu
utilises `--nuclei`).

> **Piège httpx** : `pip install httpx` installe un client HTTP Python qui porte
> le même nom. Le pipeline détecte le bon binaire, mais si besoin force-le avec
> `--httpx-bin /usr/bin/httpx`.

Depuis le dossier du projet, **aucune installation n'est nécessaire** :
`python -m recon_mano …` fonctionne directement (il faut juste `typer` et `rich`
dans le Python courant).

Pour la commande courte `recon_mano` — sur Kali/Debian, le Python système est
*externally-managed* (PEP 668), d'où **pipx** :

```bash
pipx install -e .        # recommandé (venv isolé, commande sur le PATH)
# ou un venv dédié :  python3 -m venv .venv && .venv/bin/pip install -e .
# ou override :       python -m pip install -e . --break-system-packages
```

### Vérifier les outils

```bash
recon_mano --check
```

### Lancer un scan

Invocation minimale — **cible en premier, nom de sortie en second** :

```bash
recon_mano cible.com sortie
```

Le nom de sortie est optionnel (défaut : le nom de la cible). Sans installation :
`python -m recon_mano cible.com sortie`.

Exemples courants :

```bash
# Run complet, dossier de sortie = "output"
recon_mano cible.com output

# Repartir de zéro (efface les anciens fichiers) + lancer nuclei à la fin
recon_mano cible.com output --clean --nuclei

# Débug / test urlfinder seul (voir §5)
recon_mano cible.com output --skip-dnsx --skip-httpx --skip-katana

# Voir les commandes et le flux temps réel des outils
recon_mano cible.com output -v
```

### Lire la sortie live

Au lancement : une **bannière** ASCII (dégradé cyan→indigo) et un **panneau de
config** (cible / sortie / options actives). Chaque étape s'ouvre sur un
séparateur avec icône (`3/6  📜 urlfinder · …`).

Pendant qu'un outil tourne : un spinner avec **compteur de lignes** et **temps
écoulé** (`🕷️ katana · 3120 lignes · 1m04s`) — la preuve que ça avance. Avant les
étapes lourdes, une **estimation grossière** de durée (`≈ 53s · 8000 requêtes @
150/s`). À la fin de chaque étape, une ligne récap : `→ 8000 entrées · 22s`.

À la toute fin : la liste des **livrables** (carte, surface vivante, 200, arbre)
et une **table récapitulative** — résultat et temps par étape.

Le chrono par étape est aussi un **outil de diagnostic** (voir §5). En `-v`, les
commandes exactes et le flux stderr des outils sont affichés en direct (avec un
heartbeat de progression même quand l'outil est muet).

---

## 5. urlfinder : lire un résultat maigre

C'est le point le plus subtil du pipeline. urlfinder interroge des archives
publiques **fortement rate-limitées par IP**. Conséquence : un run peut rendre
19000 URLs, et le suivant 30 — sans que rien ne soit cassé.

### Pourquoi c'est trompeur

Quand ton IP a épuisé son quota, Wayback/CommonCrawl répondent souvent par une
**page vide en HTTP 200**, pas une erreur 429. urlfinder l'enregistre donc comme
un succès (`Found 30 urls`) **sans aucun warning**. Un premier run frais rend le
paquet complet ; les suivants (à force de relancer) tombent à quelques dizaines.

### Ce que le pipeline fait pour ça

- **`-all` par défaut** : sans lui, urlfinder n'interroge qu'un sous-ensemble curé. (`--urlfinder-curated` pour revenir en arrière.)
- **`-v` au lieu de `-silent`** : la sortie par source est capturée. Le pipeline affiche **toujours** le récap `Found N urls`, les `[WRN]` de sources en échec, et — si le résultat est bas *sans* erreur — un avertissement explicite de throttling silencieux.
- **URLs via `-o`** + filtrage des lignes `http` : robuste, indépendant du silent.
- **Aucun timeout** : urlfinder tourne autant qu'il veut (un run sain prend 2+ min).
- **Retry sur résultat vide** (`--urlfinder-retries`, défaut 1) avec délai **progressif** (`--urlfinder-retry-wait` × n°, défaut 30 s → 60 s), car les fenêtres de rate-limit se comptent en minutes.

### Diagnostiquer avec le chrono

| Ce que tu vois | Interprétation |
|---|---|
| `→ 0 entrées · 5s` | coupé net par les sources |
| `→ 69 entrées · 36s` | a tourné mais **dégradé/throttlé** |
| `→ 19000 entrées · 2m` | run sain |

Un `0` en 5 s n'est **pas** un timeout (il n'y en a pas) : ce sont les sources
qui refusent vite.

### Voir la contribution par source

```bash
urlfinder -d cible.com -all -cs -jsonl -silent \
  | jq -r '.sources // .source | if type=="array" then .[] else . end' \
  | sort | uniq -c | sort -rn
```

`-cs` (collect-sources) tague chaque URL par sa source : tu vois direct si
`waybackarchive` contribue 5 lignes ou 5000. *(Le flag JSON est `-jsonl` / `-j`,
**pas** `-json`.)*

### Retrouver du volume — le bon levier

- **waybackarchive / commoncrawl** (le gros du volume) sont **gratuits et sans clé**. Leur throttle est par **IP + fenêtre de temps**. Remèdes : arrêter de marteler et **laisser reposer** quelques heures, ou **changer d'IP** (VPN / proxy).
- Une **clé d'API** dans `~/.config/urlfinder/provider-config.yaml` ne dé-throttle **pas** Wayback. Elle débloque *d'autres* sources : **VirusTotal** (clé obligatoire), **URLScan** (quota plus haut avec clé)… Ça élargit la couverture et rend le recon **résilient** (ces sources tiennent quand Wayback te bloque), sans reproduire le pic Wayback.

---

## 6. Référence des options

| Option | Effet | Défaut |
|---|---|---|
| `cible` (positionnel) | Domaine apex | — (requis) |
| `sortie` (positionnel) | Dossier de sortie | nom de la cible |
| `--check` | Vérifie les outils puis quitte | — |
| `--clean` | Supprime les anciens fichiers de sortie avant de lancer | off |
| `-v`, `--verbose` | Affiche les commandes et le flux des outils | off |
| `--all-sources` | `subfinder -all` (plus lent) | off |
| `--wildcard-filter` / `--no-wildcard-filter` | `dnsx -wd` | on |
| `--match-codes` | `httpx -mc` | `200,204,301,302,307,308,401,403,405,500,502,503` |
| `--depth` | Profondeur katana | `2` |
| `--scope` | `katana -fs` : `rdn`, `fqdn`, `dn` ou regex | `rdn` |
| `--js-crawl` | `katana -jc` (endpoints JS, non validés) | off |
| `--katana-max-pages` | Plafond pages/domaine (`-mdp`, 0 = illimité) | `3000` |
| `--katana-duration` | Durée max du crawl (`-ct`, vide = illimité) | `10m` |
| `--katana-filter-similar` / `--no-katana-filter-similar` | `-fsu` : collapse chemins similaires | on |
| `--katana-ignore-query` | `-iqp` : collapse les query params | off |
| `--urlfinder-all` / `--urlfinder-curated` | Toutes les sources vs sous-ensemble curé | all |
| `--urlfinder-retries` | Réessais si urlfinder rend 0 | `1` |
| `--urlfinder-retry-wait` | Base du délai entre essais, en s (progressif ×n) | `30` |
| `--threads` | Threads httpx | `50` |
| `--rate-limit` | Requêtes/seconde (httpx & katana) | `150` |
| `--concurrency` | Concurrence katana | `10` |
| `--httpx-bin` | Chemin du httpx ProjectDiscovery | auto-détecté |
| `--revalidate` / `--no-revalidate` | Passe httpx #2 sur la carte katana (codes réels + tous les 200) | on |
| `--tree` / `--no-tree` | Génère `urls_tree.html` (arbre interactif des 200) | on |
| `--in-scope` | Restreindre à ces domaines (liste virgulée). Vide = tout garder | `` |
| `--nuclei` | Lance nuclei sur les hôtes/URLs vivants | off |
| `--nuclei-mode` | `auto` (`-as`) \| `curated` \| `full` | `auto` |
| `--nuclei-targets` | `hosts` \| `urls` (absent + terminal → demandé) | `hosts` |
| `--nuclei-severity` | Sévérités nuclei | `medium,high,critical` |
| `--nuclei-rate-limit` | `nuclei -rl` | `150` |
| `--nuclei-max-host-error` | `nuclei -mhe` : abandon hôte après N erreurs | `10` |
| `--nuclei-timeout` | `nuclei -timeout` (s) : ne pas s'attarder sur un hôte lent | `5` |
| `--nuclei-concurrency` | `nuclei -c` : templates en parallèle | `25` |
| `--nuclei-retries` | `nuclei -retries` | `1` |
| `--skip-dnsx` / `--skip-urlfinder` / `--skip-httpx` / `--skip-katana` | Ignore l'étape (retombe proprement sur l'entrée précédente) | off |

---

## 7. Fichiers produits

Dans le dossier de sortie :

| Fichier | Étape | Contenu |
|---|---|---|
| `01_subfinder.txt` | 1 | Sous-domaines découverts |
| `02_dnsx.txt` | 2 | Hôtes qui résolvent (wildcards filtrés) |
| `03_urlfinder.txt` | 3 | URLs historiques (archives) |
| `04_httpx_input.txt` | — | Fusion hôtes + URLs (entrée httpx) |
| `05_httpx.jsonl` | 4 | Sortie httpx brute (JSON) |
| **`urls_all.txt`** | 4 | **URLs vivantes annotées — triage manuel** |
| `urls_200.txt` | 4 | Uniquement les 200 (seeds katana) |
| `06_katana.txt` | 5 | Résultats du crawl (URLs découvertes, **sans code HTTP**) |
| `all_urls.txt` | — | Cartographie brute (seeds + crawl, non validée) |
| `08_httpx2.jsonl` | 5b | Sortie httpx #2 brute (revalidation de la carte) |
| **`urls_all_final.txt`** | 5b | **Surface vivante complète, annotée** (archives **+** crawl katana) |
| **`urls_200_final.txt`** | 5b | **TOUS les endpoints 200** (archives + katana) — le fichier à ouvrir |
| `07_nuclei_input.txt` | 6 | Cibles vivantes envoyées à nuclei (hosts ou urls) |
| `nuclei.txt` | 6 | Findings nuclei (si `--nuclei`) |
| **`urls_tree.html`** | — | **Arbre interactif repliable des 200** (à ouvrir au navigateur) |

`urls_tree.html` groupe les 200 par hôte puis par chemin, sépare pages / assets
(css/js/img masquables), flague les endpoints à fort signal (`!` : admin, api,
`.php`…) et les URLs à paramètres (`?`), avec recherche live. Généré par défaut
(`--no-tree` pour couper). Régénérable après coup avec la sous-commande `report` :

```bash
recon_mano report sortie                      # → sortie/urls_tree.html (200)
recon_mano report sortie/urls_all_final.txt   # arbre tous-codes (401/403/500)
```

Sur un **dossier**, `report` prend la meilleure liste de 200 dedans ; sur un
**fichier**, il le transforme en `<fichier>.html`.

> Sans `--revalidate` (défaut on), les découvertes katana n'ont pas de code HTTP.
> Avec, `urls_200_final.txt` contient **tous** les 200 ; `urls_200.txt` ne couvre
> que la surface d'avant-crawl.

Les deux fichiers à ouvrir en priorité sont **`urls_all.txt`** (le passé + le
présent, annotés, avec les 401/403/500) et **`all_urls.txt`** (la carte à jour).

---

## 8. Dépannage

| Symptôme | Cause probable / remède |
|---|---|
| `httpx (ProjectDiscovery) introuvable` | Un `httpx` du PATH est le client Python. Installe le vrai (`go install github.com/projectdiscovery/httpx/cmd/httpx@latest`) ou passe `--httpx-bin`. |
| urlfinder rend très peu (sans erreur) | Throttling silencieux par IP. Laisse reposer / change d'IP. → §5 |
| dnsx efface presque tout | Domaine wildcard légitime, ou résolveur lent. Diagnostique avec `--no-wildcard-filter`. |
| katana traîne / ne finit pas | urlfinder a rendu trop d'URLs. Passe `urls_200.txt` dans `uro` d'abord, ou baisse `--depth 1`. |
| katana sort du périmètre | Hôtes tiers venus des archives. Resserre `--scope fqdn` ou `dn`. |
| Une étape échoue | Le pipeline ne meurt pas sur un exit code non nul : il affiche l'erreur et continue avec ce qu'il a. |

---

## 9. Rappel éthique

Ce pipeline génère du trafic actif (httpx, katana) et, avec `--nuclei`, envoie
des payloads. Ne le lance que dans un périmètre autorisé. Les étapes passives
(subfinder, urlfinder) interrogent des tiers : reste dans les limites de leurs
conditions d'utilisation.
