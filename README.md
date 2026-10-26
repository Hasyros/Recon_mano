# Recon Mano

Pipeline Python de découverte et reconnaissance de sous-domaines, orchestrant
`subfinder`, `crt.sh` (module Python), `amass` (passif), `dnsx`, `urlfinder`, `gau`,
`waybackurls`, `httpx`, `katana`, `jsluice`, `trufflehog`/`gitleaks`, `subzy`, `naabu`,
`arjun` et (en option, jamais par défaut) `nuclei` en deux passes. **Tout est actif par
défaut** (mode « full ») et chaque module se coupe individuellement ; seul nuclei (passes 1
et 2, et son pendant sur les ports) est opt-in (`-n`).

> À n'utiliser que sur des cibles pour lesquelles tu disposes d'une autorisation
> explicite : programme de bug bounty dans son périmètre, mission de pentest, ou
> infrastructure t'appartenant.

## Workflow

```
cible ─┬─ subfinder (-all) ─┐
       ├─ crt.sh ───────────┼─ subdomains → dnsx (-wd) ── hôtes ──┐
       ├─ amass (passif) ───┘                                       ├─ merge → httpx ─┬─ urls_all.txt
       └─ urlfinder (-d apex) ───────────── URLs ──────────────────┘                 └─ urls_200.txt → katana
              └─ gau → waybackurls  (archives sérialisées)                                       │
                              │                                                                   │
                              └──────── carte = seeds + crawl + archives réduites ───────────────┘
                                                     │
                       httpx #2 (URLs inédites seulement) → urls_200_final.txt · urls_tree.html
                                                     │
                                               [--nuclei] (opt-in)
                              (passe 1 par hôte ‖ katana · passe 2 par URL en fin de run)

phase 4b, branches ajoutées :
  katana ─ réponses stockées ─┬─ jsluice (endpoints → carte, secrets)      aucune requête
                              └─ secrets (trufflehog sans vérification)    aucune requête
  dnsx ─┬─ takeover (CNAME hors périmètre → subzy)
        └─ naabu ─ httpx ports (hors 80/443) ─ listes finales · nuclei ports (opt-in)
  httpx #2 ─ arjun (≤ 30 URLs représentatives) ─ run DAST de nuclei #2 (opt-in)
```

Les étapes s'exécutent en parallèle quand leurs dépendances le permettent (voir
[Exécution parallèle](#exécution-parallèle)).

**httpx #2** est essentiel : katana découvre des URLs par crawl et gau/waybackurls
rendent des URLs d'archive, mais personne ne connaît leur code HTTP. La revalidation
donne les statuts réels et **`urls_200_final.txt`** = tous les 200 (archives *et*
découvertes katana). L'arbre `urls_tree.html` est généré depuis cette liste.
**httpx #2 ne teste que les URLs de la carte absentes de `05_httpx.jsonl`** : les
seeds qu'httpx #1 a déjà validées ne sont pas re-testées, leurs lignes sont reprises
telles quelles (voir [httpx #2 sur les seules URLs inédites](#httpx-2-sur-les-seules-urls-inédites)).

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
subfinder ─┐
crtsh ─────┼─ subdomains ── dnsx ─┬─ takeover
amass ─────┘                      ├─ naabu ── httpx ports ─┬─ nuclei ports (opt-in)
urlfinder ──────────────────┐     │                        │
   └─ gau ── waybackurls ─┐ └─────┴─ httpx ─┬─ katana ─┬─ jsluice ─┬─ secrets
                          │                 └─ nuclei #1        │
                          │                    (opt-in, ‖ katana)
                          └──────────────── merge_map ◄── (katana, jsluice, archives)
                                               │
              httpx #2 (attend aussi httpx ports) ─┬─ tree
                                                   └─ arjun ── nuclei #2 (opt-in)
```

| Module | Dépend de | Binaire | Option | Timeout / débit par défaut | Rôle |
|---|---|---|---|---|---|
| `subfinder` | — | subfinder | `--skip-subfinder`, `--no-all-sources` | illimité | Sous-domaines, **`-all` par défaut** (ou liste `--subdomains`) |
| `crtsh` | — | **aucun** (Python, `urllib`) | `--no-crtsh` | 10 min de module · 60 s/requête · 2 nouveaux essais | Sous-domaines des certificats (crt.sh), un appel par apex du périmètre |
| `amass` | — | amass (optionnel) | `--no-amass`, `--amass-timeout` | **15 min** | `amass enum` **passif** |
| `subdomains` | subfinder, crtsh, amass | — | — | — | Fusion + dédoublonnage + périmètre → `01_subdomains.txt` |
| `dnsx` | subdomains | dnsx | `--skip-dnsx` | illimité | Résolution DNS, wildcards filtrés |
| `urlfinder` | — | urlfinder | `--skip-urlfinder` | illimité | Archives, depuis l'apex seul : tourne **en parallèle** des sous-domaines |
| `gau` | urlfinder | gau (optionnel) | `--no-gau`, `--gau-timeout`, `--gau-threads` | **15 min** · 2 threads | URLs d'archives (Wayback, CommonCrawl, OTX, urlscan) |
| `waybackurls` | gau | waybackurls (optionnel) | `--no-waybackurls`, `--waybackurls-timeout` | **15 min** | URLs de la Wayback Machine |
| `httpx` | dnsx, urlfinder | httpx | `--skip-httpx` | 150 req/s | Fusion des hôtes et des URLs urlfinder, une passe |
| `nuclei1` | httpx | nuclei | `-n` | 50 req/s | Opt-in : nuclei **par hôte**, pendant le crawl katana (voir [nuclei en deux passes](#nuclei-en-deux-passes)) |
| `katana` | httpx | katana | `--skip-katana`, `--no-katana-store` | 150 req/s | Crawl des seeds vivantes ; **stocke les réponses** dans `responses/katana` (`-store-response`) |
| `takeover` | dnsx | dnsx · subzy (optionnel) | `--no-takeover`, `--takeover-timeout`, `--takeover-rate`, `--takeover-concurrency` | **10 req/s** · **15 min** · concurrence 5 | `dnsx -cname` ; subzy sur les seuls hôtes dont un CNAME sort du périmètre (voir [takeover](#takeover)) |
| `naabu` | dnsx | naabu (optionnel) | `--no-naabu`, `--ports`, `--naabu-allow-full`, `--naabu-timeout`, `--naabu-rate` | **100 sondes/s** · **30 min** · `top-1000` | Ports ouverts des hôtes vivants, `-exclude-cdn` (voir [ports](#ports-naabu--httpx-ports--nuclei-ports)) |
| `httpx_ports` | naabu | httpx | `--no-httpx-ports`, `--httpx-ports-rate` | **50 req/s** · **15 min** | httpx sur les `hôte:port` hors 80/443 ; ces services rejoignent les listes finales |
| `nuclei_ports` | httpx_ports | nuclei | `-n` (suit `--nuclei-passes`) | `--nuclei-rate-limit` (50 req/s) · **30 min** | Opt-in : réglages de la passe 1 sur les services hors 80/443 |
| `jsluice` | katana | jsluice (optionnel) | `--no-jsluice`, `--jsluice-timeout` | aucune requête · **10 min** | Endpoints (→ carte, validés par httpx #2) et secrets des JS stockés par katana |
| `secrets` | katana, jsluice | trufflehog **ou** gitleaks (optionnel) | `--no-secrets`, `--secrets-timeout` | aucune requête · **10 min** | Secrets des réponses stockées, **sans vérification** → `10_secrets.txt` (masqué) |
| `merge_map` | katana, gau, waybackurls, jsluice | — | `--no-archive-dedupe`, `--archive-k` | — | `all_urls.txt` = seeds vivantes + crawl + archives et endpoints JS réduits, périmètre strict (léger, sans réseau) |
| `httpx2` | merge_map, httpx_ports | httpx | `--no-revalidate` | 150 req/s | Validation des URLs de la carte **absentes d'httpx #1** ; reprend les services hors 80/443 dans les listes finales |
| `tree` | httpx2 | — | `--no-tree` | — | `urls_tree.html` |
| `arjun` | httpx2 | arjun (optionnel) | `--no-arjun`, `--arjun-max`, `--arjun-timeout`, `--arjun-rate`, `--arjun-threads`, `--arjun-stable` | **20 req/s** · **30 min** · ≤ **30** URLs | Paramètres cachés des URLs représentatives → `14_arjun_params.txt` (voir [arjun](#arjun)) |
| `nuclei2` | httpx2, arjun | nuclei | `-n` | 150 req/s | Opt-in : nuclei **par URL représentative** (DAST + exposition, + URLs d'arjun), fin de pipeline |

Les valeurs par défaut (module actif ou non, débit, timeout, paramètres) vivent dans
une seule table, `recon_mano/config.py` (`MODULE_DEFAULTS`) ; les options de la CLI les
surchargent. `--module-timeout nom=minutes` (répétable, `0` = illimité) fixe le
timeout de **n'importe quel** module, par ex. `--module-timeout katana=30`, et l'emporte
sur les options dédiées (`--amass-timeout`…). `PRESETS` contient pour l'instant le seul
preset `full` (tous les modules) ; les presets rapides viendront plus tard, il n'y a pas
encore d'option `--mode`.

- **`--workers N`** (défaut **6**, était 4) : nombre maximum de modules simultanés. Le DAG de la
  phase 4b peut en avoir ~7 d'actifs (chaîne d'archives, katana, nuclei #1, naabu, takeover,
  httpx ports, jsluice/secrets) ; à 4, des modules légers ou en attente d'un service public
  (archives, amass : jusqu'à 15 min) en bloqueraient d'autres, plus utiles. Monter les workers
  n'augmente pas le trafic vers la cible : celui-ci est plafonné par `--max-rps`.
  **`--sequential`** = `--workers 1` (un seul module à la fois, ordre historique) —
  pratique pour déboguer ou comparer.
- **`--max-rps N`** (défaut 150) : budget de débit **global**. `--rate-limit`,
  `--nuclei-rate-limit` et `--nuclei2-rate-limit` ne sont plus que des débits
  *demandés* ; la somme des débits accordés aux modules qui frappent la cible
  (httpx, katana, takeover, naabu, httpx ports, httpx #2, arjun, nuclei #1/ports/#2) ne dépasse
  jamais `--max-rps`. Dans l'ordre des modules, `nuclei1` puis `katana` sont servis avant `takeover`
  et `naabu` : à budget égal le crawl garde la priorité et ces deux-là prennent le reste ou
  attendent (sans `-n`, katana à 150 req/s sur `--max-rps 150` fait attendre naabu jusqu'à la fin
  du crawl ; baisser `--rate-limit` ou monter `--max-rps` les fait avancer ensemble). Le budget est global parce que c'est la cible qui encaisse
  le trafic cumulé, pas chaque outil : deux modules à 150 req/s en parallèle font
  300 req/s côté serveur, ce qui déclenche WAF et bans. Un module reçoit
  `min(demandé, budget restant)` au démarrage ; s'il reste moins de
  `min(demandé, 10)`, il attend qu'un autre module libère du budget. Les modules
  qui n'attaquent pas la cible (subfinder, crtsh, amass, subdomains, dnsx, urlfinder, gau,
  waybackurls, jsluice, secrets, merge_map, tree) n'en consomment pas : crt.sh et les archives sont des
  services publics, pas la cible. Pour dépasser 150 req/s, relever `--max-rps` en même temps que
  `--rate-limit`.
- **Binaire manquant** : le module est `désactivé` (« binaire X introuvable »), le
  reste du pipeline continue avec ses replis (ex. sans dnsx, httpx part de la
  liste `01_subdomains.txt`). amass, gau, waybackurls, jsluice, naabu, arjun, trufflehog et
  gitleaks sont **optionnels** : sans eux les autres sources font le travail. `secrets` est
  désactivé seulement si ni trufflehog ni gitleaks n'existent (trufflehog d'abord, sinon
  gitleaks). **Exception : `takeover`** n'est pas désactivé sans subzy — il écrit quand même
  `11_takeover_candidates.txt` (utile en soi) et se termine avec une note ; seul dnsx est requis. **Exception dans un module** : `échec`, message
  dans le récapitulatif (traceback complet avec `-v`), les modules indépendants finissent
  (crt.sh injoignable ne bloque rien).
  Si **aucune** source (subfinder, crtsh, amass, `--subdomains`) ne rend d'hôte en
  périmètre, `subdomains` est en échec et tout l'aval est ignoré proprement (code
  retour 1) ; un subfinder vide seul n'est plus fatal.
- **katana ne crawle que du confirmé vivant** : si httpx n'a trouvé aucune URL
  vivante, katana est *ignoré* (jamais de crawl de cibles non confirmées). Le repli
  sur les entrées brutes fusionnées n'existe que pour `--skip-httpx`.
- **Aucune question pendant l'exécution** : seul le périmètre est demandé, au
  lancement ; `-y` et `--in-scope` évitent la question. (nuclei ne pose plus de
  question : la passe 1 est par hôte, la passe 2 par URL, voir plus bas.)
- **Affichage** : un board live (une ligne par module : état, lignes écrites, temps,
  débit accordé) ; chaque module imprime son bloc de détails à sa fin, puis un
  récapitulatif final avec une ligne par module (✓ terminé · ✗ échec · ⏱ timeout ·
  – ignoré · ⊘ désactivé), le **début** de chaque module (décalage depuis le lancement :
  on y voit nuclei #1 démarrer pendant le crawl katana) et la durée réelle face au
  cumul des modules. Avec `-v`,
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
fichiers déjà présents : `all_urls.txt` (seeds `urls_live.txt` + `06_katana.txt` +
archives `03b_gau.txt` / `03c_waybackurls.txt` réduites, périmètre strict),
`urls_all_final.txt` / `urls_200_final.txt` / `urls_live_final.txt` (**union** des lignes
d'`05_httpx.jsonl` pour les URLs de la carte et de `08_httpx2.jsonl` ; `05_httpx.jsonl`
seul si `08_httpx2.jsonl` est absent) et `urls_tree.html`. Le périmètre, les codes
vivants et la réduction des archives (`archive.dedupe`, `archive.k`) viennent de
`run_config.json` (à défaut : périmètre déduit du nom du dossier, codes par défaut,
réduction K=3). Une URL d'archive que httpx n'a jamais testée ne peut pas entrer dans les
listes finales : le rejeu ne valide rien, il ne fait que recombiner. Utile après
avoir ajouté une exclusion à `run_config.json`, édité une liste à la main ou
relancé un seul module. Les rejets du rejeu sont ajoutés à `rejected_scope.tsv`
sous l'étape `merge`.

## Sorties

| Fichier | Contenu |
|---|---|
| `01_subfinder.txt` | Sortie de subfinder (ou liste `--subdomains`), filtrée au périmètre |
| `01b_crtsh.txt` | Sous-domaines vus dans les certificats (crt.sh), filtrés au périmètre |
| `01c_amass.txt` | Sous-domaines d'amass passif, filtrés au périmètre |
| `01_subdomains.txt` | **Fusion dédoublonnée des trois sources**, périmètre appliqué — entrée de dnsx |
| `02_dnsx.txt` | Sous-domaines résolvant, wildcards filtrés |
| `03_urlfinder.txt` | Chemins historiques issus des archives (urlfinder) |
| `03b_gau.txt` / `03c_waybackurls.txt` | URLs d'archives de gau / waybackurls (http(s) seulement, périmètre appliqué) — **non validées** : elles ne passent que par `merge_map` puis httpx #2 |
| `04_httpx_input.txt` | Fusion des deux branches (entrée httpx) |
| `05_httpx.jsonl` | Sortie httpx brute |
| `urls_all.txt` / `urls_200.txt` | Surface vivante annotée / 200 — **avant** crawl |
| `urls_live.txt` | URLs nues dont le code est dans `--live-codes` — **seeds de katana** |
| `06_katana.txt` | Crawl actif (URLs découvertes, sans code HTTP) |
| `all_urls.txt` | Carte (seeds + crawl + archives réduites, périmètre strict) |
| `responses/katana/` | **Réponses brutes** stockées par katana (`index.txt` + un fichier par réponse, voir [Réponses stockées](#réponses-stockées-par-katana)) — lues par jsluice et secrets, supprimées par `--clean` |
| `09_jsluice_urls.txt` | Endpoints extraits du JS, résolus, en périmètre, statiques exclues — **non validés** (entrent dans la carte, httpx #2 les teste) |
| `09_jsluice_secrets.jsonl` | Sortie brute de `jsluice secrets` — **secrets en clair, fichier sensible** |
| `10_secrets.jsonl` | Sorties brutes de trufflehog / gitleaks / jsluice — **secrets en clair, fichier sensible : ne pas partager ni versionner** |
| **`10_secrets.txt`** | **Résumé lisible et masqué** : `[détecteur] URL d'origine (outil, fichier:ligne) 4 premiers caractères…` |
| `11_dnsx_cname.jsonl` | `dnsx -cname -resp -json` sur les hôtes vivants |
| `11_takeover_candidates.txt` | Hôtes dont un CNAME sort du périmètre (écrit même sans subzy) |
| **`11_takeover.jsonl`** / `11_takeover.txt` | Résultats subzy **vulnérables seulement** (brut / lisible) |
| `12_naabu.jsonl` / **`12_ports.txt`** | Ports ouverts (sortie naabu / `hôte:port`), en périmètre |
| `13_httpx_ports_input.txt` / `13_httpx_ports.jsonl` | `hôte:port` hors 80/443 envoyés à httpx / sortie brute |
| **`urls_live_ports.txt`** | Services web hors 80/443 vivants — **entrée de nuclei ports** ; ils sont aussi dans `urls_*_final.txt` et l'arbre |
| `07_nuclei_ports_input.txt` / `nuclei_ports.jsonl` | `-n` seulement : racines `scheme://hôte:port` envoyées à nuclei / findings bruts |
| `14_arjun_input.txt` / `14_arjun.json` | URLs confiées à arjun (≤ `--arjun-max`) / sortie brute (`{url: {params, method, headers}}`) |
| **`14_arjun_params.txt`** | Une URL par jeu de paramètres découvert (`https://h/p?a=1&b=1`, existants conservés), en périmètre |
| `08_httpx2_input.txt` | Ce qui a réellement été envoyé à httpx #2 : URLs de la carte absentes d'`05_httpx.jsonl` |
| `08_httpx2.jsonl` | httpx #2 brut — **uniquement les nouvelles lignes** (les seeds d'httpx #1 ne sont pas re-testées) |
| **`urls_all_final.txt`** | **Triage manuel** — surface vivante complète, annotée (seeds + katana + gau + waybackurls), union des lignes httpx #1 et #2 |
| **`urls_200_final.txt`** | **Tous les endpoints 200** (toutes sources, validés) |
| `urls_live_final.txt` | Liste live après httpx #2 (404, 5xx et timeouts écartés) — **source de la passe 2 de nuclei et d'arjun** (la passe 1 part de `urls_live.txt`) |
| `rejected_scope.tsv` | Entrées écartées par le filtre de périmètre (`étape<TAB>hôte<TAB>ligne`), remis à zéro à chaque run |
| `07_nuclei1_input.txt` | Passe 1 : hôtes (`scheme://hôte[:port]`) envoyés à nuclei (+ `07_nuclei1_input_normal.txt` / `_waf.txt` si des hôtes sont derrière un WAF/CDN) |
| `07_nuclei2_input.txt` | Passe 2 : URLs représentantes (K par signature, statiques exclues) |
| `07_nuclei2_params.txt` | Passe 2 : représentantes avec paramètres → run DAST |
| `07_nuclei2_priority.txt` | Passe 2 : représentantes prioritaires → run exposition |
| `nuclei_pass1.jsonl` / `nuclei_pass2.jsonl` | Findings bruts de chaque passe (JSONL, une ligne = un finding) — source de vérité |
| `nuclei.txt` | Vue lisible fusionnée des deux passes **et de nuclei ports** : `[sévérité] template-id URL`, triée du plus grave au moins grave |
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
go install -v github.com/owasp-amass/amass/v5/cmd/amass@main          # optionnel (module amass)
go install github.com/lc/gau/v2/cmd/gau@latest                        # optionnel (module gau)
go install github.com/tomnomnom/waybackurls@latest                    # optionnel (module waybackurls)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest   # optionnel
go install github.com/tomnomnom/gf@latest                              # optionnel (passe 2 de nuclei)
go install github.com/BishopFox/jsluice/cmd/jsluice@latest            # optionnel (module jsluice)
go install github.com/PentestPad/subzy@latest                         # optionnel (module takeover)
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest  # optionnel (naabu, httpx ports, nuclei ports)
go install github.com/trufflesecurity/trufflehog/v3@latest            # optionnel (module secrets, de préférence)
go install github.com/gitleaks/gitleaks/v8@latest                     # optionnel (module secrets, repli)
python -m pip install arjun                                           # optionnel (module arjun)
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
| `--check` | Vérifie la présence des outils puis quitte (requis : subfinder, dnsx, httpx, urlfinder, katana ; optionnels : amass, gau, waybackurls, jsluice, trufflehog, gitleaks, subzy, naabu, arjun, nuclei, gf — crt.sh n'a besoin d'aucun binaire) |
| `--all-sources` / `--no-all-sources` | `subfinder -all` : **défaut on** (toutes les sources, plus lent mais plus complet) ; `--no-all-sources` pour le mode rapide |
| `--subdomains` | Sous-domaines déjà connus (fichier ou liste virgulée, ex: trouvés via `ffuf`) : **remplace subfinder** ; crt.sh et amass s'y ajoutent sauf `--no-crtsh` / `--no-amass` (voir [Sources de sous-domaines](#sources-de-sous-domaines)) |
| `--crtsh` / `--no-crtsh` | Sous-domaines depuis crt.sh (défaut on, sans binaire) |
| `--crtsh-timeout` / `--crtsh-retries` | crt.sh : délai par requête en secondes (défaut 60) · nouveaux essais sur erreur/5xx/timeout (défaut 2, délai 5 s puis 10 s) |
| `--amass` / `--no-amass` | `amass enum` passif (défaut on ; module désactivé si le binaire manque) |
| `--amass-timeout` | Durée max du module amass, en minutes (défaut **15** ; `0` = illimité) |
| `--gau` / `--no-gau`, `--gau-timeout`, `--gau-threads` | URLs d'archives via gau (défaut on) · durée max en minutes (défaut **15**) · `--threads` (défaut 2) |
| `--waybackurls` / `--no-waybackurls`, `--waybackurls-timeout` | URLs de la Wayback Machine (défaut on) · durée max en minutes (défaut **15**) |
| `--archive-dedupe` / `--no-archive-dedupe`, `--archive-k` | Réduit les URLs gau/waybackurls à K par signature avant httpx #2 (défaut on, K=3) — voir [Archives](#archives-urlfinder--gau--waybackurls) |
| `--katana-store` / `--no-katana-store` | `katana -store-response` : réponses brutes dans `<sortie>/responses/katana` (défaut **on** ; jsluice et secrets en dépendent et sont ignorés sans) — voir [Réponses stockées](#réponses-stockées-par-katana) |
| `--jsluice` / `--no-jsluice`, `--jsluice-timeout` | Endpoints et secrets des JS stockés (défaut on) · durée max en minutes (défaut **10**) |
| `--secrets` / `--no-secrets`, `--secrets-timeout` | Recherche de secrets, **jamais de vérification** (défaut on) · durée max en minutes (défaut **10**) |
| `--takeover` / `--no-takeover`, `--takeover-timeout`, `--takeover-rate`, `--takeover-concurrency` | CNAME hors périmètre + subzy (défaut on) · durée max en minutes (défaut **15**) · débit demandé (**10**) · `--concurrency` de subzy (défaut **5**, jamais au-dessus du débit accordé) |
| `--naabu` / `--no-naabu`, `--ports`, `--naabu-allow-full`, `--naabu-timeout`, `--naabu-rate` | Scan de ports (défaut on) · `top-100` \| `top-1000` (défaut) \| liste `80,443,8080-8090` ; `full` et les listes de plus de 5000 ports sont **refusés** sauf `--naabu-allow-full` · durée max en minutes (défaut **30**) · débit demandé en sondes/s (défaut **100**) |
| `--httpx-ports` / `--no-httpx-ports`, `--httpx-ports-rate` | httpx sur les services hors 80/443 (défaut on) · débit demandé (**50**) |
| `--arjun` / `--no-arjun`, `--arjun-max`, `--arjun-timeout`, `--arjun-rate`, `--arjun-threads`, `--arjun-stable` | arjun (défaut on) · URLs max (défaut **30**) · durée max en minutes (défaut **30**) · `--rate-limit` demandé (**20**) · `-t` (défaut **2**) · `--stable` (défaut **off**, voir [arjun](#arjun)) |
| `--module-timeout nom=minutes` | Timeout d'un module quelconque (répétable, `0` = illimité) ; prioritaire sur les options dédiées |
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
| `--max-rps` | Budget de débit **global** en req/s partagé par httpx, katana, takeover, naabu, httpx ports, arjun et nuclei (défaut 150) — voir [Exécution parallèle](#exécution-parallèle) |
| `--workers` | Modules exécutés en parallèle au maximum (défaut **6**) |
| `--sequential` | Un module à la fois (= `--workers 1`), pour déboguer ou comparer |
| `--revalidate` / `--no-revalidate` | Passe httpx #2 sur les URLs inédites de la carte (katana, gau, waybackurls) → `urls_200_final.txt` (tous les 200). Défaut on |
| `--tree` / `--no-tree` | Génère `urls_tree.html` (arbre interactif des 200). Défaut on |
| `--in-scope` | Domaines **ajoutés à la cible** dans le périmètre (liste virgulée, ex: `devinci.fr,esilv.fr`). Sans lui, la question est posée au lancement (terminal) |
| `--exclude` | Hôtes/domaines hors périmètre (liste virgulée) : égaux ou sous-domaines d'une entrée |
| `--no-scope-filter` | Désactive le filtre de périmètre (comportement historique : tout est gardé) |
| `-y`, `--yes` | Ne pose aucune question au lancement (périmètre = cible + `--in-scope`) |
| `-n`, `--nuclei` | Lance nuclei en deux passes sur les hôtes/URLs **vivants** — **opt-in strict**, désactivé par défaut |
| `--nuclei-passes` | `1` (par hôte) · `2` (par URL représentante) · `1,2` (défaut). Prioritaire sur `--nuclei-targets` |
| `--nuclei-targets` | Compatibilité : `hosts` → passe 1 seule · `urls` → les deux passes (défaut si absent). Plus aucune question au lancement |
| `--nuclei-mode` | Templates de la passe 1 : `auto` (`-as` tech-aware, défaut) · `curated` · `full` |
| `--nuclei-severity` | Sévérités de la passe 1 et du run DAST de la passe 2 (défaut `medium,high,critical`) ; le run exposition de la passe 2 n'est pas filtré |
| `--nuclei-rate-limit` | Débit **demandé** de la passe 1 (défaut **50**, plafonné par `--max-rps`) : elle partage le budget avec katana |
| `--nuclei2-rate-limit` | Débit demandé de la passe 2 (défaut **150**, plafonné par `--max-rps`) : elle tourne en fin de pipeline, presque seule |
| `--nuclei-waf-factor` | Passe 1 : débit des hôtes derrière un WAF/CDN = débit accordé × ce facteur (défaut 0.3, entre 0.01 et 1) |
| `--nuclei-k` | Passe 2 : URLs gardées par signature (défaut 2) |
| `--nuclei-priority` / `--no-nuclei-priority` | Passe 2 : run exposition/misconfig sur les chemins sensibles (défaut on) |
| `--nuclei-max-host-error` | nuclei `-mhe` : abandon d'un hôte après N erreurs, les deux passes (défaut 10) |
| `--nuclei-timeout` / `--nuclei-concurrency` / `--nuclei-retries` | Vitesse : timeout par requête · templates parallèles · retries, les deux passes (défaut 5 / 25 / 1) |
| `--skip-*` | `subfinder`, `dnsx`, `urlfinder`, `httpx`, `katana` — le module est ignoré, l'aval retombe sur l'étape précédente (`--skip-subfinder` ne perd pas une liste `--subdomains`) |

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

`nuclei` (et `nuclei ports`) sont désactivés par défaut : ce sont les seules étapes qui envoient des
payloads, elle ne doit jamais partir sans geste explicite (`-n`). Sans `-n`,
ni la passe 1 ni la passe 2 n'existent : le pipeline se comporte exactement comme
sans nuclei (même commande httpx, katana garde tout le budget, aucun fichier nuclei).

### nuclei en deux passes

nuclei est une **attaque** (templates actifs, payloads). Il ne démarre donc que
sur `-n`, uniquement sur des cibles **confirmées vivantes** (`--live-codes`) et
**dans le périmètre** (filtre appliqué aux étapes `nuclei1` et `nuclei2`, rejets
dans `rejected_scope.tsv`). Il tourne en deux passes aux rôles distincts :

| | Passe 1 — `nuclei #1` | Passe 2 — `nuclei #2` |
|---|---|---|
| Granularité | par **hôte** (`scheme://hôte[:port]`, sans chemin) | par **URL représentante** |
| Quand | dès qu'httpx #1 a confirmé les hôtes, **pendant** le crawl katana | en fin de pipeline, après httpx #2 |
| Source | `urls_live.txt` | `urls_live_final.txt` (repli : `urls_live.txt`) |
| Templates | `--nuclei-mode` (`auto` = `-as`) + `-etags fuzz,dos,intrusive`, jamais `-dast` | run A : `-dast` · run B : `-tags exposure,misconfig` |
| Sévérité | `--nuclei-severity` | A : `--nuclei-severity` · B : aucun filtre |
| Débit demandé | `--nuclei-rate-limit` (**50**) | `--nuclei2-rate-limit` (**150**) |
| Sortie | `nuclei_pass1.jsonl` | `nuclei_pass2.jsonl` |

`--nuclei-passes 1`, `2` ou `1,2` choisit les passes (`--nuclei-targets hosts` =
passe 1 seule, `urls` = les deux, conservé pour compatibilité ; `--nuclei-passes`
l'emporte). Les deux passes passent par le budget global `--max-rps`.

**Pourquoi 50 pour la passe 1.** Elle tourne en même temps que katana, et le budget
est partagé. Dans la liste des modules `nuclei1` est déclaré *avant* `katana` : quand
les deux deviennent prêts dans le même tour, nuclei obtient d'abord ses 50 req/s et
katana reçoit le reste — avec `--max-rps 150` : nuclei 50 + katana 100. La passe 2
tourne presque seule, d'où 150. (Un même hôte sur deux ports = deux cibles.)

**WAF / CDN.** Quand nuclei est actif, httpx #1 est lancé avec `-cdn` (sans `-n`, sa
commande ne change pas) et ajoute `cdn`, `cdn_name`, `cdn_type` à son JSONL. Les
hôtes derrière un WAF/CDN (`cdn_type` `waf` ou `cdn`) sont scannés dans un **second
lot, après les autres**, aux mêmes templates mais à `max(1, int(débit accordé ×
--nuclei-waf-factor))` (0.3 par défaut) : un débit bas derrière un WAF évite bans et
bruit. Un simple hébergement cloud (`cdn_type: cloud`) compte comme hôte normal.

**Signatures et K (passe 2).** Tester `/produit/1` … `/produit/9000` n'apprend rien
de plus que d'en tester deux. Les URLs vivantes non statiques (images, CSS, JS,
polices, médias, archives, pdf/bureautique exclus) sont groupées par **signature** :
`hôte[:port]` + chemin dont les segments variables sont remplacés (`{n}` nombre,
`{uuid}`, `{hash}` hex ≥ 16, `{date}` ISO, `{tok}` jeton aléatoire ≥ 24) + noms de
paramètres triés sans valeurs (`?a&b`). On garde les **K premières** de chaque
signature (`--nuclei-k`, défaut 2), ordre conservé. Le schéma est ignoré
(`http`/`https` = même appli) mais le port est gardé. Le résultat est écrit dans
`07_nuclei2_input.txt`.

**Les deux runs de la passe 2.**

- **A — DAST** : `nuclei -dast` sur les représentantes **avec paramètres**
  (`07_nuclei2_params.txt`), sévérité `--nuclei-severity`, `-etags dos,intrusive`.
  Ignoré avec une note s'il n'y en a pas.
- **B — exposition** : `-tags exposure,misconfig` sur la **liste prioritaire**
  (`07_nuclei2_priority.txt`), **sans filtre de sévérité** (les fichiers exposés
  « info/low » — `.env`, `.git`, phpinfo — sont justement la cible), `-etags
  dos,intrusive`. Désactivable : `--no-nuclei-priority`.

**Liste prioritaire.** Une représentante est prioritaire si son **chemin** contient
un mot `admin`, `api`, `upload`, `config`, `debug`, `graphql`, `swagger`,
`actuator`, `internal` ou `backup` (casse ignorée). Le chemin est découpé en mots
(`/`, `-`, `_`, `.`…) : un mot court (`api`) doit être exact (ou `apis`, `apiv2`), un
mot long accepte un préfixe (`administrator`, `uploads`, `configuration`) — une
simple sous-chaîne matcherait `/capital-markets`. Si [`gf`](https://github.com/tomnomnom/gf)
est installé (optionnel), on y ajoute les URLs que `gf xss|sqli|ssrf|redirect|lfi|rce|idor`
reconnaît (motifs absents de `~/.gf` ignorés). Sans `gf`, repli sur une liste interne
de noms de paramètres suspects (`id`, `url`, `redirect`, `next`, `file`, `path`,
`page`, `q`, `search`, `cmd`, `exec`, `callback`, `return`, `dest`, `template`,
`include`…).

**Sorties.** Chaque passe écrit son JSONL ; à la fin du run, `nuclei.txt` en est la
vue lisible fusionnée (`[sévérité] template-id URL`, du plus grave au moins grave,
dédoublonnée) et une ligne de synthèse donne le décompte par sévérité. Seules les
passes terminées dans **ce** run alimentent `nuclei.txt` : un JSONL périmé d'un
run précédent est ignoré.

### Réponses stockées par katana

katana tourne avec `-store-response -store-response-dir <sortie>/responses/katana` (désactivable :
`--no-katana-store`, mais jsluice et secrets sont alors ignorés avec une note). Format (vérifié
dans le code de katana) : un fichier par réponse, `responses/katana/<hôte, « : » remplacé par « _ »>/<sha1 de l'URL>.txt`,
contenant l'URL, la requête brute puis la réponse brute (en-têtes et corps) ; `index.txt` liste une
ligne `<chemin du fichier> <URL> (<statut>)` par réponse. Le dossier est vidé au début de chaque
run de katana (l'index est écrit en ajout) et supprimé par `--clean` ; un dossier laissé par un
run précédent n'est jamais relu.

**Espace disque.** Chaque page et chaque JS crawlés sont gardés en entier : prévoir de quelques
dizaines de Mo à plusieurs centaines de Mo (le plafond `--katana-max-pages`, 3000 pages par
domaine, et la durée `--katana-duration` bornent le crawl). Le volume écrit est affiché dans la
note de katana (« N réponses stockées (X Mo) »). Ces fichiers contiennent des en-têtes
(`Set-Cookie`…) et des corps réels : les traiter comme sensibles.

### jsluice

Pour chaque réponse **2xx** en périmètre dont l'URL se termine en `.js`/`.mjs`/`.cjs` ou dont le
content-type est javascript/ecmascript (jamais du HTML, même sous une URL en `.js`), le corps est
extrait (`responses/js/`, supprimé ensuite ; au-delà de 5 Mo le fichier est ignoré) et passé à
`jsluice urls` puis `jsluice secrets`. jsluice lit les chemins sur son entrée standard : aucune
limite de longueur de commande. Il n'envoie **aucune requête**. Les endpoints relatifs
(`/api/x`, `../y`, `//cdn…`) sont résolus avec `urljoin` contre l'URL du JS qui les contient ; seuls
http(s) restent ; une expression dynamique (`EXPR`) dans l'hôte ou le chemin écarte l'URL, dans la
requête elle devient `1` ; les ressources statiques sont exclues, puis le périmètre est appliqué
(étape `jsluice`). Résultat : `09_jsluice_urls.txt`. **Ces endpoints ne sont pas validés** : ils
entrent dans la carte (`merge_map`, réduction `--archive-k` comme les archives), httpx #2 les
teste, et seuls ceux qui répondent servent ensuite (nuclei #2, arjun, listes finales).
`09_jsluice_secrets.jsonl` est la sortie brute de `jsluice secrets`.

### secrets

trufflehog si installé, sinon gitleaks, sur tout `responses/katana` ; les secrets de
`jsluice secrets` sont fusionnés au résumé.

- trufflehog : `trufflehog filesystem <dossier> --no-verification --json --no-update --no-color`.
  **`--no-verification` est toujours passé** et `--only-verified` / `--results=verified` ne le
  sont jamais : vérifier un secret, c'est l'essayer chez son fournisseur, donc utiliser un
  identifiant tiers trouvé — hors périmètre.
- gitleaks : `gitleaks dir <dossier> --report-format json --report-path … --exit-code 0` (v8.19+) ;
  si cette commande échoue sans rapport, repli sur l'ancien `gitleaks detect --no-git --source`.
- Une découverte dont l'URL d'origine (index katana) est hors périmètre est écartée.

`10_secrets.txt` = `[détecteur] URL d'origine (outil, fichier:ligne) début-du-secret…` (4 premiers
caractères, moins pour un secret court) ; c'est tout ce que montrent la console et ce fichier.
`10_secrets.jsonl` et `09_jsluice_secrets.jsonl` gardent les **secrets en clair** (la preuve) :
fichiers sensibles, à ne pas partager ni versionner.

### takeover

1. `dnsx -l 02_dnsx.txt -cname -resp -json` (interroge les résolveurs, pas la cible) →
   `11_dnsx_cname.jsonl`.
2. **Candidats** = hôtes dont au moins un CNAME pointe **hors du périmètre** (service tiers :
   Heroku, S3, GitHub Pages…). Un CNAME interne n'est pas un candidat ; un CNAME vers un hôte exclu
   (`--exclude`) non plus. Liste : `11_takeover_candidates.txt`.
3. `subzy run --targets … --concurrency 5 --timeout 10 --hide_fails --https --output …` sur ces
   seuls candidats (subzy récupère les hôtes : le module consomme le budget de débit ; la
   concurrence ne dépasse jamais le débit accordé). Jamais `--verify_ssl`. Seuls les résultats
   **vulnérables** sont gardés (`11_takeover.jsonl`, `11_takeover.txt`).

Sans subzy, le module se termine quand même avec la liste de candidats. Avec `-n`, la passe 1 de
nuclei couvre déjà le tag `takeover` ; subzy tourne malgré tout (empreintes différentes).

### Ports (naabu → httpx ports → nuclei ports)

- **naabu** scanne les seuls hôtes vivants (`02_dnsx.txt`) : `naabu -list … -top-ports 1000 -rate <accordé>
  -retries 1 -exclude-cdn -json`. `-exclude-cdn` limite les hôtes derrière un CDN/WAF à 80/443.
  Le type de scan est laissé à naabu (CONNECT sans root, SYN avec). `--ports` : `top-100`,
  `top-1000` (défaut) ou une liste ; `full` est refusé sauf `--naabu-allow-full`. Un timeout de
  module garde les ports déjà trouvés. Sorties filtrées au périmètre : `12_naabu.jsonl`, `12_ports.txt`.
- **httpx ports** teste les `hôte:port` **hors 80/443** (déjà vus par httpx #1) → `13_httpx_ports.jsonl`
  et `urls_live_ports.txt` (codes `--live-codes`, périmètre). **Ces services rejoignent les listes
  finales** : httpx #2 (qui attend donc httpx ports) reprend leurs lignes dans `urls_all_final.txt`,
  `urls_200_final.txt`, `urls_live_final.txt` et l'arbre HTML ; `recon_mano merge` les reprend aussi depuis
  `13_httpx_ports.jsonl`. Ils n'entrent pas dans la carte `all_urls.txt` (ce n'est pas du crawl). Comme pour
  les archives, si naabu est lent, httpx #2 attend au plus son timeout (`--naabu-timeout`).
- **nuclei ports** (`-n` seulement, et seulement si la passe 1 est active : `--nuclei-passes`) :
  racines `scheme://hôte:port` de `urls_live_ports.txt`, réglages de la passe 1 (`-as` selon
  `--nuclei-mode`, `-etags fuzz,dos,intrusive`, jamais `-dast`) → `nuclei_ports.jsonl`, repris dans
  `nuclei.txt` et le décompte par sévérité.

### arjun

Cherche des paramètres cachés, sur quelques URLs seulement car il envoie des centaines de requêtes
par URL : `urls_live_final.txt` → une URL par signature (`signatures.representatives(k=1)`), statiques
exclues, **prioritaires d'abord** (`admin`, `api`, `upload`…), plafonnées à `--arjun-max` (30).
Commande : `arjun -i … -oJ 14_arjun.json -m GET -t 2 -T 15 --rate-limit <débit accordé>`.
`14_arjun_params.txt` = une URL par jeu de paramètres trouvé, valeurs factices `=1`, paramètres déjà
présents conservés, en périmètre.

`--stable` d'arjun (1 thread **et 3 à 9 s de pause par requête**) est **désactivé par défaut** : avec
des centaines de requêtes par URL il rendrait le module inutilisable ; la prudence vient du débit
(`--rate-limit`, plafonné par `--max-rps`) et des 2 threads. `--arjun-stable` le réactive.
Sans `-n`, arjun reste un livrable de surface ; avec `-n`, **nuclei #2 attend arjun** et ajoute
`14_arjun_params.txt` à la liste de son run DAST, *après* la réduction par signature.

### Sources de sous-domaines

Trois sources sans dépendance tournent **en parallèle**, puis `subdomains` les fusionne
(`01_subdomains.txt`, lu par dnsx). Chacune est filtrée au périmètre (étapes `subfinder`,
`crtsh`, `amass`, puis `subdomains` dans `rejected_scope.tsv`). Seules les sources qui ont
produit leur fichier dans **ce** run comptent : un `01b_crtsh.txt` périmé est ignoré.

- **subfinder** : `-all` par défaut ; un `-d` par apex du périmètre (cible + `--in-scope`).
  Un résultat vide n'est plus fatal à lui seul.
- **crt.sh** (`crtsh`) : module Python pur (`urllib.request`, aucune dépendance). Une requête
  `https://crt.sh/?q=%25.<apex>&output=json` par apex du périmètre ; `name_value` est
  découpé sur les retours à la ligne, les `*.` sont retirés, les noms sont mis en minuscules,
  les adresses e-mail, IP et noms invalides écartés. crt.sh est souvent lent : 60 s par
  requête (`--crtsh-timeout`), jusqu'à 2 nouveaux essais avec délai croissant (5 s puis 10 s)
  sur erreur réseau, timeout, 5xx/429 ou JSON tronqué (`--crtsh-retries`). Un apex en échec
  n'empêche pas les autres ; tous en échec = module en échec, le pipeline continue.
- **amass** : `amass enum` **passif** uniquement (jamais `-active`, donc aucun trafic vers la
  cible), durée max 15 min (`--amass-timeout`) car le passif peut durer très longtemps. À la
  fin, les noms trouvés avant l'échéance sont quand même relus. Invocation en deux temps,
  identique en v4 et v5 : `amass enum -passive -d a,b -timeout N -nocolor` puis
  `amass subs -names -d a,b -nocolor` dont la sortie standard est capturée. Raison : en v5,
  `enum` n'a plus de `-o` (les résultats vont sur la sortie standard), `-passive` est
  « déprécié car passif par défaut » (toujours accepté) et `-timeout` y est un délai *sans
  progrès* (en v4, la durée totale) — le vrai plafond est donc l'échéance du module.
  `-silent` n'est jamais passé (il coupe la sortie). amass garde une base locale
  (`~/.config/amass`) : les noms déjà connus des runs précédents pour ces domaines
  ressortent aussi, ils restent filtrés par le périmètre. En v5 `enum` démarre un moteur
  `amass engine` en arrière-plan, comme le prévoit l'outil.
- **`--subdomains <liste>`** : la liste **remplace subfinder** (comme avant), mais crt.sh et
  amass s'y **ajoutent** tant que `--no-crtsh` / `--no-amass` ne sont pas passés : ces
  sources passives sont inoffensives pour une liste venue de ffuf. Pour ne partir que de la
  liste : `--subdomains liste.txt --no-crtsh --no-amass`.

Si **aucune** source ne rend d'hôte en périmètre, `subdomains` échoue (« Aucun sous-domaine
… arrêt ») et tout l'aval est ignoré.

**Compromis de vitesse.** `subdomains` attend ses trois sources : amass (jusqu'à 15 min)
retarde donc dnsx et httpx. Avec `--no-amass`, ou `--amass-timeout 5`, le pipeline reprend
sa vitesse d'avant.

### Archives (urlfinder → gau → waybackurls)

urlfinder, gau et waybackurls interrogent les **mêmes** archives publiques (Wayback Machine,
CommonCrawl…), déjà rate-limitées par IP. Pour ne pas les marteler ensemble, les trois sont
**sérialisées** : `gau` démarre quand urlfinder est terminé, `waybackurls` quand gau l'est
(`--no-gau` ne bloque pas waybackurls : il attend simplement urlfinder). Toute la chaîne tourne
en parallèle de dnsx, httpx et katana, et n'envoie aucune requête à la cible (`network=False`,
hors du budget `--max-rps`). gau et waybackurls utilisent tous les apex du périmètre
(urlfinder, lui, reste sur l'apex de la cible) ; leurs sorties sont des fichiers à part
(`03b_gau.txt`, `03c_waybackurls.txt`), http(s) seulement, filtrés au périmètre. gau prend
les domaines en arguments, `--subs --threads 2 --timeout 45 --blacklist <extensions
statiques courantes>`, et sa sortie standard est capturée (son `--o` *ajoute* à un fichier
existant) ; waybackurls lit les domaines sur l'entrée standard (avec un argument il n'en
traiterait qu'un), sous-domaines inclus.

**Ces URLs ne sont jamais testées avant `merge_map`** et n'alimentent ni katana (seeds =
`urls_live.txt`) ni nuclei #1 (hôtes d'`urls_live.txt`) en direct. `merge_map` (qui attend
katana **et** la chaîne d'archives) les ajoute à la carte après : périmètre → exclusion des
ressources statiques (`signatures.is_static`) → réduction à `--archive-k` (défaut 3) URLs par
signature (`signatures.representatives` : hôte + chemin templaté + noms de paramètres), car
gau peut rendre 100k+ URLs (`--no-archive-dedupe` pour tout garder, statiques toujours
exclues). httpx #2 les valide ensuite : 404, 5xx et timeouts n'entrent dans aucune liste live.
Si httpx #2 ne tourne pas (`--skip-httpx`, `--no-revalidate`, binaire absent), ces URLs
restent dans `all_urls.txt` mais nuclei #2 ne les reçoit pas.

**Compromis.** `merge_map`, donc httpx #2, attend maintenant la fin des archives en plus de
katana. Dans un run typique (urlfinder ≈ quelques minutes, gau et waybackurls démarrés pendant
dnsx/httpx, katana ensuite long), la chaîne finit avant katana et ne coûte rien. Si les archives
sont plus lentes que katana, httpx #2 attend la fin de la chaîne — au pire la durée de
l'écart, borné par les timeouts de module (15 min chacun). Pour ne pas attendre :
`--no-gau --no-waybackurls`, ou `--gau-timeout` / `--waybackurls-timeout` plus bas.

### httpx #2 sur les seules URLs inédites

httpx #2 ne reteste pas ce qu'httpx #1 a déjà validé. Il lit `05_httpx.jsonl` (champs `url` et
`input`), écrit dans `08_httpx2_input.txt` les URLs de la carte qui n'y figurent pas et ne
lance httpx que sur celles-là (rien du tout s'il n'y en a pas). `08_httpx2.jsonl` ne contient
donc que les **nouvelles** lignes. Les listes `urls_*_final.txt` sont ensuite construites sur
l'union des lignes d'httpx #1 (pour les URLs de la carte) et d'httpx #2 : mêmes lignes
qu'avant (un test le prouve avec un faux httpx), pour beaucoup moins de requêtes. Un
`05_httpx.jsonl` d'un run précédent n'est jamais pris en compte. Limite : une URL qu'httpx #1 a
testée mais écartée par `--match-codes` (absente du JSONL) est retestée par httpx #2.

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
