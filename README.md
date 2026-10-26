# Recon Mano

Pipeline Python de reconnaissance, orchestrant `subfinder`, `crt.sh` (module Python), `amass`
(passif), `dnsx`, `urlfinder`, `gau`, `waybackurls`, `httpx`, `katana`, `jsluice`,
`trufflehog`/`gitleaks`, `subzy`, `naabu`, `arjun` et (en option) `nuclei`. Les étapes sont des
**modules** lancés en parallèle par un ordonnanceur dès que leurs dépendances sont terminées,
sous un budget de débit global vers la cible.

**Tout est actif par défaut** (jeu de modules « full ») et chaque module se coupe
individuellement. **La seule famille opt-in est nuclei** (`nuclei1`, `nuclei_ports`, `nuclei2`,
activée par `-n`), parce que c'est la seule qui envoie des payloads.

> À n'utiliser que sur des cibles pour lesquelles tu disposes d'une autorisation
> explicite : programme de bug bounty dans son périmètre, mission de pentest, ou
> infrastructure t'appartenant.

Pour comprendre ce qui se passe pendant un run : [WORKFLOW.md](WORKFLOW.md). Historique des
changements et valeurs par défaut retenues : [CHANGELOG.md](CHANGELOG.md).

## Sommaire

[Démarrage rapide](#démarrage-rapide) · [Workflow](#workflow) · [Modules](#modules) ·
[Presets et précédence](#presets-et-précédence-des-réglages) · [Exécution parallèle](#exécution-parallèle) ·
[katana](#katana) · [Options](#options) · [Fichiers produits](#fichiers-produits) ·
[Périmètre et vivacité](#périmètre-et-vivacité) · [nuclei](#nuclei-en-deux-passes) ·
[Détail des modules](#détail-des-modules) · [Installation](#installation) · [Tests et benchmark](#tests-et-benchmark)

## Démarrage rapide

```bash
python -m recon_mano --check                 # outils présents ?
python -m recon_mano exemple.com sortie      # run complet, sans nuclei
python -m recon_mano exemple.com sortie -n   # + nuclei (opt-in)
```

Le nom de sortie est optionnel (défaut : le nom de la cible). Le **périmètre** (cible +
`--in-scope`) est demandé une fois au lancement ; `-y` évite la question. À la fin : la liste
des livrables et un récapitulatif par module. Fichier à lire en priorité :
**`urls_all_final.txt`** (ou l'arbre `urls_tree.html`).

## Workflow

```
cible ─┬─ subfinder (-all) ─┐
       ├─ crt.sh ───────────┼─ subdomains → dnsx (-wd) ── hôtes ──┐
       ├─ amass (passif) ───┘                                       ├─ merge → httpx #1 ─┬─ urls_live.txt ─→ katana
       └─ urlfinder (apex) ──────────────── URLs d'archive ────────┘                     └─ urls_all.txt / urls_200.txt
              └─ gau → waybackurls  (archives sérialisées)

httpx #1 ─┬─ katana ─ réponses stockées ─┬─ jsluice (endpoints → carte, secrets)     aucune requête
          │                              └─ secrets (trufflehog sans vérification)   aucune requête
          └─ nuclei #1 (-n, par hôte, pendant le crawl)
dnsx + httpx #1 ─┬─ takeover (CNAME hors périmètre → subzy)
                 └─ naabu ─ httpx ports (hors 80/443) ─ nuclei ports (-n)
katana + jsluice + archives ─ merge_map (carte) ─ httpx #2 (URLs inédites) ─┬─ urls_*_final.txt · urls_tree.html
                                                                             └─ arjun ─ nuclei #2 (-n, par URL, fin de run)
```

Graphe exact des dépendances (une flèche = « doit être terminé avant ») :

```
subfinder ─┐
crtsh ─────┼─ subdomains ── dnsx ─┬─ takeover
amass ─────┘                      ├─ naabu ── httpx ports ─┬─ nuclei ports (-n)
urlfinder ──────────────────┐     │                        │
   └─ gau ── waybackurls ─┐ └─────┴─ httpx ─┬─ katana ─┬─ jsluice ─┬─ secrets
                          │                 └─ nuclei #1 (-n, ‖ katana)
                          └──────────────── merge_map ◄── (katana, jsluice, archives)
                                               │
              httpx #2 (attend aussi httpx ports) ─┬─ tree
                                                   └─ arjun ── nuclei #2 (-n)
```

> `takeover` et `naabu` attendent aussi **httpx #1** : sinon ils démarreraient avant lui
> et lui prendraient du budget de débit alors qu'il est sur le chemin critique.


**httpx #2** est essentiel : katana, gau/waybackurls et jsluice rendent des URLs dont personne
ne connaît le code HTTP. La revalidation donne les statuts réels et **`urls_200_final.txt`**.
Il ne teste que les URLs de la carte **absentes de `05_httpx.jsonl`** (les seeds qu'httpx #1 a
déjà validées sont reprises telles quelles, voir [httpx #2](#httpx-2-sur-les-seules-urls-inédites)).

Trois choix de conception qui expliquent la forme du graphe :

- **urlfinder est une branche parallèle, pas un maillon après httpx.** Les archives sont la
  seule source où un hôte *mort* a encore de la valeur ; filtrer sur les hôtes vivants avant de
  les interroger, c'est ne jamais demander ce qu'il y avait sur les hôtes tombés. Il part de
  l'apex : un appel couvre tous les sous-domaines connus, au lieu de N appels rate-limités.
- **Les deux branches fusionnent avant une passe httpx unique.** Chaîner `dnsx → urlfinder →
  httpx` perdrait tout hôte sans historique d'archive (un `staging-v2` récent résout mais la
  Wayback ne le connaît pas). Les ensembles sont disjoints : une seule passe réseau suffit.
- **httpx n'est pas une étape, c'est un filtre**, ré-appliqué à chaque fois qu'on génère des
  URLs depuis une source non vivante (archives, crawl, JS).

## Modules

« Réseau » = le module envoie du trafic à la cible et consomme le budget `--max-rps`. Les
valeurs par défaut vivent dans une seule table, `recon_mano/config.py` (`MODULE_DEFAULTS`) ;
les options de la CLI les surchargent.

| Module | Rôle | Dépend de | Binaire | Option(s) | Débit · timeout par défaut | Réseau |
|---|---|---|---|---|---|---|
| `subfinder` | Sous-domaines, `-all` (ou liste `--subdomains`) | — | subfinder | `--skip-subfinder`, `--no-all-sources` | illimité | non (sources passives) |
| `crtsh` | Sous-domaines des certificats (crt.sh), un appel par apex | — | **aucun** (Python) | `--no-crtsh`, `--crtsh-timeout`, `--crtsh-retries` | 10 min · 60 s/requête · 2 nouveaux essais | non (service public) |
| `amass` | `amass enum` **passif** | — | amass (optionnel) | `--no-amass`, `--amass-timeout` | **15 min** | non |
| `subdomains` | Fusion + périmètre → `01_subdomains.txt` | subfinder, crtsh, amass | — | — (plomberie) | — | non |
| `dnsx` | Résolution DNS, wildcards filtrés (`-wd`) | subdomains | dnsx | `--skip-dnsx`, `--no-wildcard-filter` | illimité | non (résolveurs) |
| `urlfinder` | Archives, depuis l'apex | — | urlfinder | `--skip-urlfinder`, `--urlfinder-*` | illimité | non (archives) |
| `gau` | URLs d'archives (Wayback, CommonCrawl, OTX, urlscan) | urlfinder | gau (optionnel) | `--no-gau`, `--gau-timeout`, `--gau-threads` | **15 min** · 2 threads | non |
| `waybackurls` | URLs de la Wayback Machine | gau | waybackurls (optionnel) | `--no-waybackurls`, `--waybackurls-timeout` | **15 min** | non |
| `httpx` | Fusion hôtes + URLs urlfinder, **une passe** de validation/annotation | dnsx, urlfinder | httpx | `--skip-httpx`, `--rate-limit`, `--threads` | **150 req/s** | **oui** |
| `nuclei1` | Passe 1 : nuclei **par hôte**, pendant le crawl | httpx | nuclei | `-n`, `--nuclei-rate-limit` | **50 req/s** | **oui** |
| `katana` | Crawl des seeds vivantes ; **stocke les réponses** ; dédoublonnage + headless ciblé | httpx | katana | `--skip-katana`, `--katana-*` | **100 req/s** · illimité | **oui** |
| `takeover` | `dnsx -cname` puis subzy sur les CNAME hors périmètre | dnsx, httpx | dnsx · subzy (optionnel) | `--no-takeover`, `--takeover-*` | **10 req/s** · **15 min** · concurrence 5 | **oui** |
| `naabu` | Ports ouverts des hôtes vivants, `-exclude-cdn` | dnsx, httpx | naabu (optionnel) | `--no-naabu`, `--ports`, `--naabu-*` | **100 sondes/s** · **30 min** · `top-1000` | **oui** |
| `httpx_ports` | httpx sur les `hôte:port` hors 80/443 | naabu | httpx | `--no-httpx-ports`, `--httpx-ports-rate` | **50 req/s** · **15 min** | **oui** |
| `nuclei_ports` | Réglages de la passe 1 sur les services hors 80/443 | httpx_ports | nuclei | `-n` (suit `--nuclei-passes`) | **50 req/s** · **30 min** | **oui** |
| `jsluice` | Endpoints et secrets des JS stockés par katana | katana | jsluice (optionnel) | `--no-jsluice`, `--jsluice-timeout` | **10 min** | non (fichiers locaux) |
| `secrets` | Secrets des réponses stockées, **sans vérification** | katana, jsluice | trufflehog **ou** gitleaks (optionnel) | `--no-secrets`, `--secrets-timeout` | **10 min** | non (fichiers locaux) |
| `merge_map` | Carte `all_urls.txt` (seeds + crawl + archives/JS réduits), périmètre strict | katana, gau, waybackurls, jsluice | — | `--no-archive-dedupe`, `--archive-k` (plomberie) | — | non |
| `httpx2` | Validation des URLs de la carte **absentes d'httpx #1** + services hors 80/443 | merge_map, httpx_ports | httpx | `--no-revalidate` | **150 req/s** | **oui** |
| `tree` | `urls_tree.html` | httpx2 | — | `--no-tree` | — | non |
| `arjun` | Paramètres cachés des URLs représentatives | httpx2 | arjun (optionnel) | `--no-arjun`, `--arjun-*` | **20 req/s** · **30 min** · ≤ 30 URLs | **oui** |
| `nuclei2` | Passe 2 : nuclei **par URL représentative** (DAST + exposition) | httpx2, arjun | nuclei | `-n`, `--nuclei2-rate-limit` | **150 req/s** | **oui** |

- **Binaire manquant** : le module est `désactivé` (« binaire X introuvable »), le reste
  continue avec ses replis (ex. sans dnsx, httpx part de `01_subdomains.txt`). amass, gau,
  waybackurls, jsluice, subzy, naabu, arjun, trufflehog et gitleaks sont **optionnels**. `secrets`
  n'est désactivé que si ni trufflehog ni gitleaks n'existent. **`takeover`** n'est pas désactivé
  sans subzy : il écrit `11_takeover_candidates.txt` et se termine avec une note (seul dnsx est
  requis). Une exception dans un module = `échec` (message dans le récapitulatif, traceback avec
  `-v`) ; les modules indépendants finissent.
- Si **aucune** source de sous-domaines (subfinder, crtsh, amass, `--subdomains`) ne rend d'hôte
  en périmètre, `subdomains` échoue et tout l'aval est ignoré proprement (code retour 1).
- **Timeouts** : `--module-timeout nom=minutes` (répétable, `0` = illimité) fixe le timeout de
  **n'importe quel** module (`--module-timeout katana=30`) et l'emporte sur les options dédiées
  (`--amass-timeout`…). Les timeouts des modules « Réseau » sont des plafonds de module, pas des
  limites par requête.
- **Aucune question pendant l'exécution** : seul le périmètre est demandé, au lancement.

## Presets et précédence des réglages

Les jeux de modules sont des listes simples dans `recon_mano/config.py` (`PRESETS`) :

| Preset | Modules | nuclei |
|---|---|---|
| `fast` | `subfinder`, `subdomains`, `dnsx`, `httpx`, `nuclei1` | `nuclei1` seulement, et seulement avec `-n` |
| `surface` | toute la surface : sources de sous-domaines, `dnsx`, archives, `httpx`, `katana`, `jsluice`, `secrets`, `takeover`, `naabu`, `httpx_ports`, `merge_map`, `httpx2`, `tree`, `arjun` | **aucun**, même avec `-n` (avertissement) |
| `full` | tous les modules | les trois modules nuclei, sous `-n` |

**La CLI utilise `full`.** L'option `--mode fast|surface|full` n'est pas encore branchée : un
commentaire dans `cli.py` marque l'endroit (`preset = "full"` → `preset = mode`), le reste
(`resolve_modules`) gère déjà les trois.

Réglages : `--enable a,b` et `--disable a,b` (noms du registre ; un nom inconnu est une erreur,
code 2). **Précédence, de la plus forte à la plus faible :**

1. une option **par module** donnée explicitement (`--gau` / `--no-gau`, `--revalidate`, `--tree`…) ;
   les `--skip-subfinder|dnsx|urlfinder|httpx|katana` en sont des alias de `--no-…` ;
2. `--enable` / `--disable` ;
3. le **preset** (aujourd'hui `full`).

Règles associées :

- **nuclei exige `-n`.** Activer explicitement un module nuclei sans `-n` (`--enable nuclei2`)
  est une **erreur** (code 2), jamais un oubli silencieux. Listé par un preset mais sans `-n`, il
  reste simplement éteint. `-n` combiné à un jeu sans nuclei (preset `surface`, ou
  `--disable nuclei1,nuclei2,nuclei_ports`) prévient que `-n` est sans effet.
- **Plomberie** : `subdomains` et `merge_map` (ni binaire, ni trafic) sont activés d'office dès
  qu'un module qui lit leur état l'est ; les désactiver explicitement alors est une erreur. Sinon
  l'aval s'ignorerait faute de données. Les autres dépendances restent gérées par le
  repli habituel de chaque module (« katana n'a pas tourné, rien à lire »).

```bash
recon_mano exemple.com sortie --disable amass,naabu,arjun          # full moins trois modules
recon_mano exemple.com sortie --disable gau,waybackurls --gau       # --gau explicite l'emporte : gau tourne
recon_mano exemple.com sortie --enable nuclei2                      # erreur : exige -n
```

## Exécution parallèle

Un module démarre dès que toutes ses dépendances sont *terminées* (réussies, en échec, en
timeout, ignorées ou désactivées : c'est le module qui gère ses entrées manquantes).

- **`--workers N`** (défaut **6**) : modules simultanés au maximum. Le DAG peut en avoir ~7
  d'actifs (archives, katana, nuclei #1, naabu, takeover, httpx ports, jsluice/secrets) ; monter les
  workers n'augmente pas le trafic vers la cible, plafonné par `--max-rps`. **`--sequential`** =
  `--workers 1` (ordre historique, utile pour déboguer ou comparer).
- **`--max-rps N`** (défaut **150**) : budget de débit **global** (req/s) partagé par les modules
  « Réseau ». Il est global parce que la cible encaisse le trafic cumulé : deux modules à 150
  req/s en parallèle font 300 req/s côté serveur, ce qui déclenche WAF et bans. Un module reçoit
  `min(demandé, budget restant)` à son départ ; s'il reste moins de `min(demandé, 10)`, il attend
  qu'un autre libère du budget. `--rate-limit`, `--katana-rate-limit`, `--nuclei-rate-limit`… ne
  sont que des débits *demandés*.
- **Priorité du budget = ordre de déclaration** : `httpx`, `nuclei1`, `katana`, `takeover`,
  `naabu`, `httpx_ports`… Quand deux modules deviennent prêts au même tour, le premier servi
  prend son débit, les suivants le reste ou attendent.

### Arithmétique du budget (défauts, `--max-rps 150`)

| Phase | Modules actifs et débit accordé | Total |
|---|---|---|
| httpx #1 | httpx 150 | 150 |
| crawl, **sans `-n`** | katana **100** + takeover 10 + naabu **40** (100 demandés, il prend le reste) | 150 |
| crawl, **avec `-n`** | nuclei #1 50 + katana **100** ; takeover et naabu **attendent** nuclei #1 | 150 |
| après naabu, sans `-n` | katana 100 + httpx ports 50 | 150 |
| fin | httpx #2 150, puis arjun 20 (+ nuclei #2 150 avec `-n`) | ≤ 150 |

Avant la phase 5, katana demandait 150 (= tout le budget) : sans `-n`, takeover, naabu et httpx
ports attendaient la fin du crawl, l'étape la plus longue (de l'ordre de l'heure). À 100, katana
laisse 50 req/s aux modules qui peuvent travailler en même temps ; avec `-n` rien ne change (50 +
100). Pour faire avancer naabu pendant nuclei #1, monte `--max-rps` **si la cible l'accepte**.
Les durées des modules ne dépendent pas linéairement du débit accordé (naabu à 40 au lieu de 100
sera plus lent) ; le gain vient du chevauchement. Détail de ce qu'on peut mesurer : [ci-dessous](#durées--séquentiel-vs-parallèle-simulation).

### Affichage et fichiers de suivi

- **Board live** : une ligne par module (état, lignes écrites, temps, débit accordé) ; chaque
  module imprime son bloc de détails à sa fin ; récapitulatif final avec le **début** de chaque
  module (décalage depuis le lancement) et la durée réelle face au cumul des modules. Avec `-v`,
  pas de board : flux des outils préfixé `outil │` et heartbeat.
- **`run_stats.json`** : par module, statut, début/fin (décalage en s), durée, résultat, débit
  accordé, note ; plus `wall_clock` (durée réelle), `sum_of_durations` (cumul) et `parallel_gain`.
- **`run_config.json`** : cible, périmètre, codes vivants, preset, modules activés, réglages katana,
  timeouts, workers, `max_rps`, versions.

### Durées : séquentiel vs parallèle (simulation)

> **Ce sont des chiffres de SIMULATION, pas des mesures.** `bench/bench_pipeline.py` lance le vrai
> ordonnanceur sur le vrai DAG de modules, avec de faux outils (aucun binaire, aucun réseau) dont chaque
> module « dure » une durée scénarisée (1 s = 1 min) : subfinder 2, crtsh 1, amass 10, urlfinder 3, gau 4,
> waybackurls 3, dnsx 1, httpx 3, **katana 40**, jsluice 1, secrets 2, takeover 2, **naabu 15**, httpx ports 2,
> httpx #2 4, arjun 10, nuclei #1 20, nuclei #2 15, nuclei ports 5 (minutes simulées). Il valide l'ordre des
> dépendances, le budget de débit et le nombre de workers ; il ne dit rien de la vitesse réelle des outils
> (les durées ne dépendent pas du débit accordé dans la simulation : naabu y dure 15 min même à 40/s).

| Scénario (`--max-rps 150`, 6 workers) | Durée simulée | Gain vs séquentiel |
|---|---|---|
| séquentiel (`--sequential`, ancien comportement) | 103 min | — |
| **parallèle** | **69 min** | ×1,49 (−34 min) |
| séquentiel + `-n` | 143 min | — |
| **parallèle + `-n`** | **84 min** | ×1,70 (−59 min) |

Ce que montre la chronologie du run parallèle sans `-n` : les trois sources de sous-domaines et la chaîne
d'archives tournent ensemble (0 → 10 min) ; dès qu'httpx finit (14 min), katana (100 req/s, jusqu'à
54 min) **ne bloque plus** takeover (10) ni naabu (40) → httpx ports, qui finissent pendant le crawl
(31 min) ; le chemin critique est `amass → dnsx → httpx → katana → jsluice → merge_map → httpx #2 → arjun` (10+1+3+40+1+4+10 = 69 min).
Avec `-n`, nuclei #1 (50 req/s, 14 → 34 min) **chevauche katana** (vérifié par le script), mais comme
50 + 100 = 150 req/s, takeover et naabu attendent la fin de nuclei #1 ; nuclei #2 (15 min) clôt le run.

Relancer : `python -m bench.bench_pipeline --scale 1` (≈ 6 minutes ; `--scale 0.25` va quatre fois plus
vite mais les temps fixes des faux outils faussent un peu les petites durées ; en dessous de 0,1 les
chiffres n'ont plus de sens). Le script sort en erreur si nuclei #1 ne chevauche pas katana.

**Comparer sur ta cible (la vraie mesure).** Lance l'ancienne version et la nouvelle sur la
**même cible autorisée**, dans deux dossiers de sortie, et compare leurs `run_stats.json` :

```bash
git worktree add ../recon_mano_avant master                  # l'ancien code, dans un dossier à part
(cd ../recon_mano_avant && time python -m recon_mano cible.com ../mesure_avant -y [-n])
time python -m recon_mano cible.com mesure_apres -y [-n]     # la branche courante
python -c "import json; s=json.load(open('mesure_apres/run_stats.json', encoding='utf-8')); print(s['wall_clock'], s['sum_of_durations'], s['parallel_gain'])"
```

L'ancien code n'écrit pas de `run_stats.json` : sa durée est celle de `time`. Pour la nouvelle version, `wall_clock` est la durée réelle du run et
`sum_of_durations` ce qu'un run séquentiel du même travail aurait coûté. Pour isoler l'apport du
parallélisme à code constant, lance aussi la nouvelle version avec `--sequential`, puis sans, et compare
leurs `run_stats.json` module par module (`modules[].duration`, `start`, `end`). Les archives (urlfinder, gau, waybackurls)
sont rate-limitées par IP et très variables d'un run à l'autre : refais la mesure plusieurs fois,
ou désactive-les (`--no-gau --no-waybackurls`) des deux côtés pour comparer le reste. Les
modules `merge`/`tree` sont négligeables ; la différence se joue sur katana, naabu et nuclei.

### `recon_mano merge` : rejouer la fusion

```bash
recon_mano merge sortie
```

Reconstruit, **sans lancer aucun outil**, la fin de la chaîne à partir des fichiers présents :
`all_urls.txt` (seeds `urls_live.txt` + `06_katana.txt` + archives `03b_gau.txt` /
`03c_waybackurls.txt` réduites, périmètre strict), `urls_all_final.txt` / `urls_200_final.txt` /
`urls_live_final.txt` (**union** des lignes d'`05_httpx.jsonl` pour les URLs de la carte,
`08_httpx2.jsonl` et `13_httpx_ports.jsonl`) et `urls_tree.html`. Périmètre, codes vivants et
réduction des archives viennent de `run_config.json`. Une URL qu'httpx n'a jamais testée ne peut
pas entrer dans les listes finales : le rejeu ne valide rien, il recombine. Utile après avoir
ajouté une exclusion, édité une liste à la main ou relancé un seul module. Les rejets du rejeu
sont ajoutés à `rejected_scope.tsv` (étape `merge`).

## katana

katana est le module le plus long. Sa configuration par défaut : profondeur 2, `-field-scope rdn`,
`-concurrency 10`, `-filter-similar`, `-max-domain-pages 3000`, `-crawl-duration 10m`,
`-store-response`, pas de headless sauf hôtes JS.

- **Débit** : `--katana-rate-limit` (défaut **100**). Voir l'[arithmétique du budget](#arithmétique-du-budget-défauts---max-rps-150).
- **`-crawl-duration` (`--katana-duration`, 10m) s'applique PAR SEED**, pas à l'ensemble du run
  (vérifié). Un crawl de 300 seeds peut donc durer bien plus de 10 minutes. Pour **borner le
  module entier** : `--module-timeout katana=45` (le crawl est alors tué, les URLs déjà écrites
  sont conservées).
- **Dédoublonnage des hôtes par contenu** (`--katana-dedupe-hosts`, défaut **on**). httpx #1 est
  lancé avec `-hash sha256` (champ JSONL `hash.body_sha256`). Avant le crawl, les seeds vivantes
  sont groupées par hôte (`hôte[:port]`) ; chaque hôte reçoit une empreinte
  `sha256(corps)[:16]/code/taille` calculée sur sa **racine** (sinon sur la première ligne de
  l'hôte). Les hôtes de même empreinte (40 sous-domaines servant la même page « parked », la même
  SPA…) ne sont crawlés qu'**une fois** : seuls les seeds du premier hôte du groupe partent à
  katana. Les autres sont listés dans `06_katana_dedup.tsv` (`hôte_gardé<TAB>hôte_écarté<TAB>empreinte`).
  **Aucun livrable ne perd d'hôte** (`urls_live.txt`, la carte, les listes finales, nuclei #1 les
  gardent) : seule l'entrée du crawl est réduite. Un code ou une taille différente ne regroupe pas ;
  un hôte sans hash, ou à corps vide, n'est jamais écarté. Limite : une page qui change à chaque
  requête (jeton CSRF, horodatage) a un hash différent à chaque fois et n'est pas dédoublonnée
  (le défaut est donc de ne rien perdre). `--no-katana-dedupe-hosts` rétablit la commande httpx
  d'avant (sans `-hash`).
- **Headless ciblé** (`--katana-headless`, défaut **auto**). `auto` : les hôtes dont `httpx
  -tech-detect` annonce un framework JS (React, Next.js, Vue.js, Nuxt.js, Angular, AngularJS, Svelte,
  SvelteKit, Ember.js, Backbone.js, Gatsby, Remix, Preact…, noms exacts, casse et version ignorées —
  liste `JS_FRAMEWORKS` dans `liveness.py`) passent dans un **second crawl** `-headless`, lancé dans
  le même module après le crawl standard, à concurrence réduite (`--katana-headless-concurrency`,
  défaut **3**, contre 10) ; `all` : tous les hôtes en headless ; `off` : jamais. Les sorties sont
  fusionnées dans `06_katana.txt`. Flags (vérifiés dans le code de katana) : `-headless`, et
  `-no-sandbox` quand le processus est **root** (`--katana-no-sandbox auto|on|off`, auto = si
  root, ce qui est le cas sur beaucoup de Kali) ; `-xhr-extraction` n'est **pas** utilisé (il
  n'écrit les requêtes XHR que dans une sortie `-jsonl`, la nôtre est une liste d'URLs).
  Chrome/Chromium doit être installé (`sudo apt install chromium`) ; sinon katana tente de
  télécharger le sien, ce qui exige un accès réseau. **Si le crawl headless échoue** (pas de Chrome,
  code retour ≠ 0), un message clair est affiché, les résultats du crawl standard sont conservés et
  le module se termine en succès avec une note.
- **Pas de réponses stockées en headless.** katana ne gère pas `-store-response` dans ce mode
  (documentation upstream) : les réponses de `responses/katana` viennent du crawl standard
  seulement, donc **jsluice et secrets ne voient pas les hôtes crawlés en headless**. Avec
  `--katana-headless all`, ils n'ont plus rien à analyser. Si les bundles JS des SPA vous intéressent
  pour jsluice/secrets, gardez `auto` ou `off`.
- **Réponses stockées** (`--katana-store`, défaut on) : voir [ci-dessous](#réponses-stockées-par-katana).
- Garde-fous : `--katana-max-pages` (`-mdp`, 3000), `--katana-filter-similar` (`-fsu`, on),
  `--katana-ignore-query` (`-iqp`, off : les paramètres ont de la valeur), `--js-crawl` (`-jc`,
  off : endpoints lus dans le JS, non requêtés donc non validés), `--depth` (2), `--scope` (`rdn`).
- **katana ne crawle que du confirmé vivant** : sans URL vivante après httpx #1, il est *ignoré*.
  Le repli sur les entrées brutes n'existe que pour `--skip-httpx` (alors ni dédoublonnage ni
  headless : aucune donnée httpx).

## Options

Toutes les options ont une aide (`--help`). Groupées par thème ; « défaut » est la valeur sans option.

### Général

| Option | Effet |
|---|---|
| `--check` | Vérifie les outils puis quitte (requis : subfinder, dnsx, httpx, urlfinder, katana) |
| `--clean` | Supprime les anciens fichiers de sortie (y compris `responses/`) avant de lancer |
| `-v`, `--verbose` | Commandes exactes et flux des outils en direct (sans board) |
| `--workers`, `--sequential`, `--max-rps` | Voir [Exécution parallèle](#exécution-parallèle) (6 · off · 150) |
| `--enable`, `--disable` | Voir [Presets](#presets-et-précédence-des-réglages) |
| `--module-timeout nom=minutes` | Timeout d'un module quelconque (répétable, `0` = illimité) |
| `--skip-subfinder` `--skip-dnsx` `--skip-urlfinder` `--skip-httpx` `--skip-katana` | Alias de `--disable` ; l'aval retombe sur l'étape précédente (`--skip-subfinder` ne perd pas une liste `--subdomains`) |
| `--httpx-bin` | Chemin du httpx ProjectDiscovery (auto-détecté) |

### Périmètre

| Option | Effet |
|---|---|
| `--in-scope a.fr,b.com` | Domaines **ajoutés** à la cible dans le périmètre. Sans lui, la question est posée au lancement (terminal) |
| `--exclude h1,h2` | Hôtes/domaines hors périmètre : égaux ou sous-domaines d'une entrée |
| `--no-scope-filter` | Désactive le filtre (comportement historique : tout est gardé) |
| `-y`, `--yes` | Aucune question (périmètre = cible + `--in-scope`) |

### Sous-domaines

| Option | Effet · défaut |
|---|---|
| `--all-sources` / `--no-all-sources` | `subfinder -all` · **on** |
| `--subdomains` | Liste connue (fichier ou virgules) : **remplace subfinder** ; crt.sh et amass s'y ajoutent sauf `--no-crtsh` / `--no-amass` |
| `--crtsh` / `--no-crtsh`, `--crtsh-timeout`, `--crtsh-retries` | crt.sh · on · 60 s · 2 |
| `--amass` / `--no-amass`, `--amass-timeout` | amass passif · on · **15** min (0 = illimité) |
| `--wildcard-filter` / `--no-wildcard-filter` | `dnsx -wd` · on |

### Archives

| Option | Effet · défaut |
|---|---|
| `--urlfinder-all` / `--urlfinder-curated`, `--urlfinder-retries`, `--urlfinder-retry-wait` | toutes les sources · 1 · 30 s (progressif ×n) |
| `--gau` / `--no-gau`, `--gau-timeout`, `--gau-threads` | on · **15** min · 2 |
| `--waybackurls` / `--no-waybackurls`, `--waybackurls-timeout` | on · **15** min |
| `--archive-dedupe` / `--no-archive-dedupe`, `--archive-k` | réduit gau/waybackurls à K URLs par signature avant httpx #2 · on · 3 |

### httpx et vivacité

| Option | Effet · défaut |
|---|---|
| `--rate-limit` | Débit demandé d'httpx #1 et #2 (req/s) · **150** |
| `--threads` | Threads httpx · 50 |
| `--match-codes` | Codes retenus par httpx · large (401/403/500 compris) — pilote les fichiers de triage |
| `--live-codes` | Codes « vivants » · `200,301,302,307,308,401,403` — seules ces URLs alimentent katana, nuclei, naabu… jamais les 404/5xx |
| `--revalidate` / `--no-revalidate` | httpx #2 · on |
| `--tree` / `--no-tree` | `urls_tree.html` · on |

### katana

| Option | Effet · défaut |
|---|---|
| `--katana-rate-limit` | Débit demandé · **100** |
| `--katana-dedupe-hosts` / `--no-katana-dedupe-hosts` | Un hôte par empreinte de contenu · **on** |
| `--katana-headless auto\|off\|all` | Crawl headless des hôtes JS · **auto** |
| `--katana-headless-concurrency` | Concurrence du crawl headless · **3** |
| `--katana-no-sandbox auto\|on\|off` | `-no-sandbox` en headless · **auto** (si root) |
| `--katana-store` / `--no-katana-store` | `-store-response` · **on** (jsluice et secrets en dépendent) |
| `--concurrency` | Concurrence du crawl standard · 10 |
| `--depth`, `--scope`, `--js-crawl` | 2 · `rdn` (`fqdn`, `dn`, regex) · off |
| `--katana-max-pages`, `--katana-duration` | 3000 (`-mdp`, 0 = illimité) · `10m` (`-ct`, **par seed**) |
| `--katana-filter-similar` / `--no-…`, `--katana-ignore-query` | `-fsu` on · `-iqp` off |

### Surface (JS, secrets, takeover, ports, paramètres)

| Option | Effet · défaut |
|---|---|
| `--jsluice` / `--no-jsluice`, `--jsluice-timeout` | on · **10** min |
| `--secrets` / `--no-secrets`, `--secrets-timeout` | on · **10** min — **jamais de vérification** |
| `--takeover` / `--no-takeover`, `--takeover-timeout`, `--takeover-rate`, `--takeover-concurrency` | on · **15** min · **10** req/s · **5** (jamais au-dessus du débit accordé) |
| `--naabu` / `--no-naabu`, `--ports`, `--naabu-allow-full`, `--naabu-timeout`, `--naabu-rate` | on · `top-1000` (`top-100`, liste `80,443,8080-8090` ; `full` et les listes > 5000 ports **refusés** sans `--naabu-allow-full`) · off · **30** min · **100** |
| `--httpx-ports` / `--no-httpx-ports`, `--httpx-ports-rate` | on · **50** |
| `--arjun` / `--no-arjun`, `--arjun-max`, `--arjun-timeout`, `--arjun-rate`, `--arjun-threads`, `--arjun-stable` | on · **30** URLs · **30** min · **20** req/s · 2 · off |

### nuclei (opt-in)

| Option | Effet · défaut |
|---|---|
| `-n`, `--nuclei` | Lance nuclei en deux passes — **opt-in strict**, jamais par défaut |
| `--nuclei-passes` | `1` (par hôte) · `2` (par URL) · `1,2` (défaut). Prioritaire sur `--nuclei-targets` |
| `--nuclei-targets` | Compatibilité : `hosts` → passe 1 · `urls` → les deux |
| `--nuclei-mode` | `auto` (`-as`, défaut) · `curated` · `full` |
| `--nuclei-severity` | `medium,high,critical` (passe 1 et run DAST ; le run exposition n'est pas filtré) |
| `--nuclei-rate-limit` / `--nuclei2-rate-limit` | Débits demandés · **50** / **150** |
| `--nuclei-waf-factor`, `--nuclei-k`, `--nuclei-priority` / `--no-…` | 0.3 · 2 · on |
| `--nuclei-max-host-error`, `--nuclei-timeout`, `--nuclei-concurrency`, `--nuclei-retries` | 10 · 5 s · 25 · 1 |

## Fichiers produits

| Fichier | Contenu |
|---|---|
| `01_subfinder.txt` · `01b_crtsh.txt` · `01c_amass.txt` | Sorties de chaque source de sous-domaines, filtrées au périmètre |
| `01_subdomains.txt` | **Fusion dédoublonnée des trois sources** — entrée de dnsx |
| `02_dnsx.txt` | Sous-domaines résolvant, wildcards filtrés |
| `03_urlfinder.txt` | Chemins historiques (urlfinder) |
| `03b_gau.txt` · `03c_waybackurls.txt` | URLs d'archives (http(s), périmètre) — **non validées** : seulement `merge_map` puis httpx #2 |
| `04_httpx_input.txt` · `05_httpx.jsonl` | Entrée (hôtes + URLs urlfinder) et sortie brute d'httpx #1 (avec `hash` si le dédoublonnage katana est actif) |
| `urls_all.txt` · `urls_200.txt` | Surface vivante annotée / 200 — **avant** crawl |
| `urls_live.txt` | URLs nues dont le code est dans `--live-codes` — **seeds de katana** |
| `06_katana.txt` | Crawl (URLs découvertes, sans code HTTP) — standard + headless fusionnés |
| `06_katana_seeds.txt` · `06_katana_headless_seeds.txt` | Seeds du crawl standard / headless (écrits seulement s'il y a dédoublonnage ou headless) |
| **`06_katana_dedup.tsv`** | Hôtes écartés du crawl car de même contenu : `hôte_gardé<TAB>hôte_écarté<TAB>empreinte` |
| `responses/katana/` | **Réponses brutes** stockées (`index.txt` + un fichier par réponse) — lues par jsluice et secrets, supprimées par `--clean` |
| `09_jsluice_urls.txt` | Endpoints du JS, résolus, en périmètre — **non validés** (httpx #2 les teste) |
| `09_jsluice_secrets.jsonl` · `10_secrets.jsonl` | Sorties brutes de jsluice / trufflehog / gitleaks — **secrets en clair, fichiers sensibles : ne pas partager ni versionner** |
| **`10_secrets.txt`** | **Résumé masqué** : `[détecteur] URL (outil, fichier:ligne) 4 premiers caractères…` |
| `11_dnsx_cname.jsonl` · `11_takeover_candidates.txt` | CNAME des hôtes vivants · hôtes dont un CNAME sort du périmètre (écrit même sans subzy) |
| **`11_takeover.jsonl`** / `11_takeover.txt` | Résultats subzy **vulnérables seulement** (brut / lisible) |
| `12_naabu.jsonl` · **`12_ports.txt`** | Ports ouverts (sortie naabu / `hôte:port`), en périmètre |
| `13_httpx_ports_input.txt` · `13_httpx_ports.jsonl` | `hôte:port` hors 80/443 envoyés à httpx / sortie brute |
| **`urls_live_ports.txt`** | Services web hors 80/443 vivants — entrée de nuclei ports ; aussi dans les listes finales et l'arbre |
| `14_arjun_input.txt` · `14_arjun.json` · **`14_arjun_params.txt`** | URLs confiées à arjun · sortie brute · une URL par jeu de paramètres trouvé (`?a=1&b=1`) |
| `all_urls.txt` | Carte (seeds + crawl + archives/JS réduits, périmètre strict) |
| `08_httpx2_input.txt` · `08_httpx2.jsonl` | Ce qu'httpx #2 a reçu (URLs de la carte absentes d'`05_httpx.jsonl`) / **nouvelles lignes seulement** |
| **`urls_all_final.txt`** | **Triage manuel** — surface vivante complète annotée (union des lignes httpx #1, #2 et ports) |
| **`urls_200_final.txt`** | **Tous les endpoints 200** (toutes sources, validés) |
| `urls_live_final.txt` | Liste live après httpx #2 — source de la passe 2 de nuclei et d'arjun |
| `07_nuclei1_input*.txt` · `07_nuclei2_*.txt` · `07_nuclei_ports_input.txt` | Entrées nuclei (`-n` seulement) : hôtes (+ lots normal/WAF) · URLs représentantes, avec paramètres, prioritaires · services hors 80/443 |
| `nuclei_pass1.jsonl` · `nuclei_pass2.jsonl` · `nuclei_ports.jsonl` | Findings bruts — source de vérité |
| `nuclei.txt` | Vue lisible fusionnée : `[sévérité] template-id URL`, du plus grave au moins grave |
| **`urls_tree.html`** | **Arbre interactif repliable des 200** (à ouvrir au navigateur) |
| `rejected_scope.tsv` | Entrées écartées par le périmètre (`étape<TAB>hôte<TAB>ligne`), remis à zéro à chaque run |
| `run_config.json` · `run_stats.json` | Config du run (relue par `merge`) · statuts, durées et débits par module |

Un `403` est un endpoint qui existe mais qui est protégé — c'est souvent *le* bug. Un `401` marque
la surface d'API authentifiée, un `500` un point de crash, et beaucoup d'applis rendent `200` sur
un soft-404 : « 200 » n'est pas un filtre fiable pour « ça existe ». D'où `urls_all_final.txt`.

`urls_tree.html` groupe les 200 par hôte puis par chemin, sépare pages / assets, flague les endpoints
à fort signal (admin, api, `.php`…) et les URLs à paramètres, avec recherche live. Régénérable :

```bash
recon_mano report sortie                      # → sortie/urls_tree.html
recon_mano report sortie/urls_all_final.txt   # arbre tous codes (401/403/500)
```

## Périmètre et vivacité

Le **périmètre** est appliqué strictement après chaque étape qui produit des hôtes ou des URLs
(subfinder, crtsh, amass, subdomains, dnsx, urlfinder, gau, waybackurls, katana, jsluice, secrets,
naabu, httpx ports, arjun, carte finale, cibles nuclei) : un hôte doit être la cible, un domaine de
`--in-scope` ou un de leurs sous-domaines, et ne pas être dans `--exclude`. Ce qui est écarté est
journalisé dans `rejected_scope.tsv`. Un CNAME vers un hôte exclu n'est pas un candidat takeover.

La **vivacité** : `--match-codes` (httpx `-mc`) reste large pour le triage, mais seules les URLs
dont le code est dans `--live-codes` (défaut `200,301,302,307,308,401,403`) alimentent katana,
nuclei, naabu, arjun. httpx n'écrit jamais les timeouts et connexions refusées : ils n'apparaissent
dans aucune liste live. katana ne crawle jamais de cible non confirmée.

## nuclei en deux passes

nuclei est une **attaque** (templates actifs, payloads). Il ne démarre que sur `-n`, uniquement sur
des cibles **vivantes** et **dans le périmètre** (étapes `nuclei1`, `nuclei_ports`, `nuclei2`). Sans
`-n`, aucun module nuclei n'existe : même commande httpx (pas de `-cdn`), aucun fichier nuclei, aucun
budget réservé.

| | Passe 1 — `nuclei #1` | Passe 2 — `nuclei #2` |
|---|---|---|
| Granularité | par **hôte** (`scheme://hôte[:port]`) | par **URL représentante** |
| Quand | dès qu'httpx #1 a fini, **pendant** le crawl | en fin de pipeline, après httpx #2 et arjun |
| Source | `urls_live.txt` | `urls_live_final.txt` (repli : `urls_live.txt`) + `14_arjun_params.txt` |
| Templates | `--nuclei-mode` (`auto` = `-as`) + `-etags fuzz,dos,intrusive`, jamais `-dast` | run A : `-dast` · run B : `-tags exposure,misconfig` |
| Sévérité | `--nuclei-severity` | A : `--nuclei-severity` · B : aucun filtre |
| Débit demandé | `--nuclei-rate-limit` (**50**) | `--nuclei2-rate-limit` (**150**) |

**Pourquoi 50 pour la passe 1** : elle tourne avec katana et le budget est partagé (`nuclei1` est
déclaré avant `katana` : à `--max-rps 150`, nuclei 50 + katana 100). La passe 2 tourne presque
seule, d'où 150. **nuclei ports** applique les réglages de la passe 1 aux racines `scheme://hôte:port`
de `urls_live_ports.txt` (suit `--nuclei-passes`).

**WAF / CDN.** Avec `-n`, httpx #1 ajoute `-cdn`. Les hôtes derrière un WAF/CDN (`cdn_type` `waf` ou
`cdn`) sont scannés dans un second lot, après les autres, à `max(1, int(débit accordé ×
--nuclei-waf-factor))`. Un simple hébergement cloud compte comme hôte normal.

**Signatures et K (passe 2).** Tester `/produit/1` … `/produit/9000` n'apprend rien de plus que d'en
tester deux. Les URLs vivantes non statiques sont groupées par **signature** : `hôte[:port]` + chemin
dont les segments variables sont remplacés (`{n}`, `{uuid}`, `{hash}`, `{date}`, `{tok}`) + noms de
paramètres triés. On garde les **K premières** (`--nuclei-k`, 2). Le résultat : `07_nuclei2_input.txt`.

**Les deux runs de la passe 2.** A — DAST : `-dast` sur les représentantes **avec paramètres**
(`07_nuclei2_params.txt`, auxquelles s'ajoutent celles d'arjun), `-etags dos,intrusive`. B — exposition :
`-tags exposure,misconfig` sur la **liste prioritaire** (`07_nuclei2_priority.txt`), **sans filtre de
sévérité** (les `.env`, `.git`, phpinfo « info/low » sont la cible), désactivable (`--no-nuclei-priority`).
Une URL est prioritaire si son chemin contient `admin`, `api`, `upload`, `config`, `debug`, `graphql`,
`swagger`, `actuator`, `internal` ou `backup` (mots entiers ou préfixes de mots longs), ou si
[`gf`](https://github.com/tomnomnom/gf) (optionnel) la reconnaît ; sans `gf`, repli sur une liste interne de
noms de paramètres suspects.

**Sorties.** Chaque passe écrit son JSONL ; `nuclei.txt` en est la vue fusionnée et une ligne de
synthèse donne le décompte par sévérité. Seules les passes terminées dans **ce** run y entrent.

## Détail des modules

### Sources de sous-domaines

Trois sources sans dépendance tournent en parallèle, puis `subdomains` les fusionne. Seules celles qui
ont produit leur fichier dans **ce** run comptent.

- **subfinder** : `-all` par défaut ; un `-d` par apex du périmètre.
- **crt.sh** : `urllib` pur, une requête `https://crt.sh/?q=%25.<apex>&output=json` par apex ; `*.`
  retirés, noms invalides écartés ; souvent lent : 60 s par requête, jusqu'à 2 nouveaux essais (5 s puis
  10 s) sur erreur, timeout, 5xx/429 ou JSON tronqué. Un apex en échec n'empêche pas les autres.
- **amass** : `enum` **passif** uniquement (jamais `-active`), 15 min max ; les noms trouvés avant
  l'échéance sont quand même relus (`amass subs -names`). Invocation en deux temps, identique en v4 et v5.
  `-silent` n'est jamais passé (il coupe la sortie).
- **`--subdomains <liste>`** remplace subfinder ; crt.sh et amass s'y ajoutent (`--no-crtsh --no-amass`
  pour ne partir que de la liste).

**Compromis** : `subdomains` attend ses trois sources, donc amass (jusqu'à 15 min) retarde dnsx et
httpx ; `--no-amass` ou `--amass-timeout 5` rend la vitesse d'avant.

### Archives (urlfinder → gau → waybackurls)

Les trois interrogent les **mêmes** archives publiques, déjà rate-limitées par IP : elles sont
**sérialisées** (`gau` après urlfinder, `waybackurls` après gau) mais tournent en parallèle de tout le
reste, sans envoyer de requête à la cible. gau et waybackurls utilisent tous les apex du périmètre.
**Leurs URLs ne sont jamais testées avant `merge_map`**, qui les ajoute à la carte après périmètre →
exclusion des statiques → réduction à `--archive-k` (3) URLs par signature ; httpx #2 les valide ensuite.
**Compromis** : httpx #2 attend la fin de la chaîne (au pire l'écart, borné par les timeouts de 15 min) ;
`--no-gau --no-waybackurls` ou des timeouts plus bas évitent l'attente.

**urlfinder qui rend peu ou 0.** Les archives sont rate-limitées par IP : un run peut rendre 19000 URLs
et le suivant 30. Cause fréquente : page **vide en HTTP 200** quand le quota est épuisé (pas d'erreur
429), que urlfinder enregistre comme un succès. Le pipeline passe `-all` (sinon sous-ensemble curé),
`-v` (sortie par source capturée : récap `Found N urls`, `[WRN]`, avertissement de throttling silencieux
quand le résultat est bas sans erreur), aucun timeout, et réessaie sur résultat vide (`--urlfinder-retries`,
délai progressif). Lecture du chrono : `0 entrées · 5s` = coupé net · `69 entrées · 36s` = dégradé ·
`19000 · 2m` = sain. Pour du volume : laisser reposer la fenêtre de quota (quelques heures) ou changer
d'IP ; une clé d'API dans `~/.config/urlfinder/provider-config.yaml` ajoute *d'autres* sources mais ne
dé-throttle pas Wayback. Si katana traîne sur un gros volume, passer la liste dans
[`uro`](https://github.com/s0md3v/uro) avant.

### httpx #2 sur les seules URLs inédites

httpx #2 lit `05_httpx.jsonl` (champs `url` et `input`), écrit dans `08_httpx2_input.txt` les URLs de la
carte qui n'y figurent pas et ne lance httpx que sur celles-là (rien s'il n'y en a pas). `08_httpx2.jsonl`
ne contient donc que les **nouvelles** lignes ; les listes `urls_*_final.txt` sont construites sur l'union
des lignes d'httpx #1 (pour les URLs de la carte), d'httpx #2 et d'httpx ports — mêmes listes qu'avant
(un test le prouve avec un faux httpx), pour beaucoup moins de requêtes. Un `05_httpx.jsonl` d'un run
précédent n'est jamais pris en compte. Limite : une URL qu'httpx #1 a testée mais écartée par
`--match-codes` est retestée.

### Réponses stockées par katana

`-store-response -store-response-dir <sortie>/responses/katana` (`--no-katana-store` pour couper : jsluice
et secrets sont alors ignorés). Format (vérifié dans le code de katana) : `responses/katana/<hôte, « : »
remplacé par « _ »>/<sha1 de l'URL>.txt` contenant l'URL, la requête brute puis la réponse brute ;
`index.txt` liste `<fichier> <URL> (<statut>)`. Le dossier est vidé au début de chaque run de katana et
supprimé par `--clean` ; un dossier d'un run précédent n'est jamais relu. **Espace disque** : de
quelques dizaines à plusieurs centaines de Mo (borné par `--katana-max-pages` et le temps) ; ces fichiers
contiennent des en-têtes (`Set-Cookie`…) et des corps réels : à traiter comme sensibles. Pas de
stockage pour les hôtes crawlés en headless (voir [katana](#katana)).

### jsluice

Pour chaque réponse **2xx** en périmètre dont l'URL se termine en `.js`/`.mjs`/`.cjs` ou dont le
content-type est javascript (jamais du HTML), le corps est extrait (`responses/js/`, supprimé ensuite ;
> 5 Mo ignoré) et passé à `jsluice urls` puis `jsluice secrets`. Les chemins sont lus sur l'entrée
standard. **Aucune requête.** Les endpoints relatifs sont résolus contre l'URL du JS qui les contient ;
seuls http(s) en périmètre restent, statiques exclus. **Non validés** : ils entrent dans la carte
(réduction `--archive-k`), httpx #2 les teste, seuls ceux qui répondent servent ensuite.

### secrets

trufflehog si installé, sinon gitleaks, sur tout `responses/katana` ; les secrets de `jsluice secrets`
sont fusionnés au résumé. trufflehog : `filesystem <dossier> --no-verification --json --no-update
--no-color` — **`--no-verification` est toujours passé** (`--only-verified` jamais) : vérifier un secret,
c'est l'essayer chez son fournisseur, donc utiliser un identifiant tiers trouvé, hors périmètre.
gitleaks : `dir <dossier> … --exit-code 0` (v8.19+), repli sur `detect --no-git --source`. Une découverte
dont l'URL d'origine est hors périmètre est écartée. Console et `10_secrets.txt` n'affichent que le
début masqué ; la preuve reste dans `10_secrets.jsonl`.

### takeover

1. `dnsx -l 02_dnsx.txt -cname -resp -json` (résolveurs, pas la cible) → `11_dnsx_cname.jsonl`.
2. **Candidats** = hôtes dont un CNAME pointe **hors périmètre** (Heroku, S3, GitHub Pages…) → `11_takeover_candidates.txt`.
3. `subzy run --targets … --concurrency 5 --timeout 10 --hide_fails --https --output …` sur ces seuls
   candidats (concurrence jamais au-dessus du débit accordé ; jamais `--verify_ssl`). Seuls les
   **vulnérables** sont gardés.

Sans subzy, le module se termine quand même avec la liste de candidats. Avec `-n`, nuclei #1 couvre déjà
le tag `takeover` ; subzy tourne malgré tout (empreintes différentes).

### Ports (naabu → httpx ports → nuclei ports)

**naabu** scanne les seuls hôtes vivants (`02_dnsx.txt`) : `-top-ports 1000 -rate <accordé> -retries 1
-exclude-cdn -json` (derrière un CDN/WAF, seuls 80/443). Type de scan laissé à naabu (CONNECT sans root,
SYN avec). Un timeout garde les ports déjà trouvés. **httpx ports** teste les `hôte:port` hors 80/443 →
`urls_live_ports.txt` ; ces services **rejoignent les listes finales et l'arbre** via httpx #2 (qui
attend donc httpx ports, au plus le timeout de naabu) mais pas la carte `all_urls.txt` (ce n'est pas
du crawl).

### arjun

Cherche des paramètres cachés sur peu d'URLs (des centaines de requêtes par URL) : `urls_live_final.txt`
→ une URL par signature, statiques exclues, **prioritaires d'abord**, plafonnées à `--arjun-max` (30).
`arjun -i … -oJ 14_arjun.json -m GET -t 2 -T 15 --rate-limit <débit accordé>`. `14_arjun_params.txt` =
une URL par jeu de paramètres, valeurs factices `=1`. `--stable` (1 thread et 3 à 9 s de pause par
requête) est **off** par défaut : il rendrait le module inutilisable ; la prudence vient du débit.
Avec `-n`, **nuclei #2 attend arjun** et ajoute ses URLs à son run DAST.

## Installation

### Installation en une commande (Kali / Debian)

```bash
git clone <url-du-depot> Recon_mano && cd Recon_mano
./install.sh
source ~/.zshrc            # ou ouvre un nouveau terminal
recon_mano cible.com -y
```

**Mettre à jour** : `git pull && ./install.sh`. Le script est idempotent, il réinstalle le code
(`pipx install --force .`) et recompile les outils Go en `@latest`.

Ce qu'il fait, dans l'ordre :

1. apt (un `update`, puis `git pipx libpcap-dev chromium` et les outils de compilation ; `amass`,
   `arjun`, `trufflehog`, `gitleaks` un par un, un paquet absent du dépôt est toléré) ;
2. vérifie Go (>= 1.26, exigé par nuclei/katana/httpx/subfinder) ; sinon propose le Go officiel
   (go.dev, sha256 vérifié, `/usr/local/go`) ;
3. `go install …@latest` : subfinder, dnsx, httpx, urlfinder, katana, naabu, nuclei (de base, un échec
   fait échouer le script à la fin) puis gau, waybackurls, jsluice, subzy, gf (optionnels) ;
   repli pour amass / trufflehog / gitleaks (build Go) et arjun (`pipx`) si apt ne les a pas ;
4. `nuclei -update-templates` ;
5. installe la CLI avec `pipx` ; ajoute `~/go/bin` et `~/.local/bin` au `PATH` de `~/.zshrc` et
   `~/.bashrc` (une seule fois, repère `# recon_mano`) ;
6. lance `recon_mano --check` et affiche un tableau installé / échec / sauté.

| Option | Effet |
|---|---|
| `--core` | outils de base seulement (saute les optionnels) |
| `--install-go` | installe le Go officiel sans poser la question (sinon : question si terminal interactif, échec avec la marche à suivre sinon) |
| `--no-apt` | saute apt (machine sans sudo ; installe `git golang-go pipx libpcap-dev` toi-même) |
| `--dry-run` | affiche chaque commande sans rien exécuter |
| `--verbose` | affiche toute la sortie des commandes |

Root fonctionne (pas de `sudo`, `HOME=/root`). Le script ne touche pas à `httpx` côté Python : seul le
`httpx` de ProjectDiscovery est installé.

<details>
<summary>Installation manuelle (référence)</summary>

#### Dépendances Python

```bash
pipx install .           # commande courte `recon_mano` (Kali : Python « externally-managed », PEP 668)
python3 -m venv .venv && .venv/bin/pip install -e .      # alternative
python -m pip install -r requirements.txt                # sans installer le paquet : `python -m recon_mano …`
```

#### Outils externes (dans le `PATH`)

Requis :

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

Optionnels (module concerné entre parenthèses) :

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest          # nuclei (-n)
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest         # naabu, httpx ports, nuclei ports (libpcap-dev requis pour compiler)
go install github.com/lc/gau/v2/cmd/gau@latest                              # gau
go install github.com/tomnomnom/waybackurls@latest                          # waybackurls
go install github.com/tomnomnom/gf@latest                                   # passe 2 de nuclei (liste prioritaire)
go install github.com/BishopFox/jsluice/cmd/jsluice@latest                  # jsluice
go install github.com/PentestPad/subzy@latest                               # takeover
go install github.com/owasp-amass/amass/v5/cmd/amass@main                   # amass (ou sudo apt install amass)
pipx install arjun                                                          # arjun (ou sudo apt install arjun)
sudo apt install chromium trufflehog gitleaks                               # katana --katana-headless ; secrets
```

trufflehog et gitleaks se compilent depuis un clone (`git clone --depth 1 <dépôt> && cd <dépôt> && go build -o ~/go/bin/<nom> .`) :
le `go.mod` de trufflehog contient des `replace`, incompatibles avec `go install …@latest`.

</details>

> **Piège `httpx`.** Le client HTTP Python s'installe aussi sous le nom `httpx` dans le PATH et n'a
> aucun des flags attendus. `--check` distingue les deux via `httpx -version` ; si le mauvais binaire
> l'emporte, passe le bon chemin avec `--httpx-bin`. Le dédoublonnage de katana utilise `httpx -hash
> sha256` (httpx récent) ; sans lui l'hôte n'est simplement pas dédoublonné.

`recon_mano --check` liste les outils trouvés (requis / optionnels, avec le module concerné).

## Tests et benchmark

```bash
python -m pytest -q                        # faux outils uniquement : aucun outil réel, aucun réseau
python -m bench.bench_pipeline --scale 1   # simulation séquentiel vs parallèle (voir plus haut)
```

`tests/conftest.py` bloque tout accès réseau Python ; les tests de DAG remplacent
`runner.run_command` par de faux outils qui écrivent des sorties plausibles. `bench/bench_pipeline.py`
réutilise ces faux outils avec des durées scénarisées : c'est une simulation de l'ordonnancement, pas
une mesure d'outils.
