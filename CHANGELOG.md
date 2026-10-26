# Changelog

## Branche `feature/modular-pipeline` (phases 1 à 5)

Vue d'ensemble : la chaîne séquentielle de six étapes devient un **graphe de modules**
exécuté en parallèle, avec périmètre strict, budget de débit global et de nombreuses sources
de surface en plus. Tout est actif par défaut ; **nuclei (`nuclei1`, `nuclei_ports`, `nuclei2`)
est la seule famille opt-in (`-n`)**, parce que c'est une attaque.

### Phase 1 — périmètre strict et vivacité (`787f075`)

- `scope.py` : une seule fonction `in_scope()` (égalité ou suffixe `.apex`, exclusions) ;
  `ScopeFilter` appliqué après **chaque** étape (subfinder, dnsx, urlfinder, katana, carte, cibles
  nuclei) ; rejets dans `rejected_scope.tsv`. Options `--in-scope`, `--exclude`,
  `--no-scope-filter`, `-y`. Défaut : cible + `--in-scope`.
- `liveness.py` : `--live-codes` (défaut `200,301,302,307,308,401,403`) ; katana et nuclei ne
  reçoivent que les URLs vivantes, jamais 404/5xx.

### Phase 2 — pipeline modulaire (`2680c3d`)

- `pipeline.py` : `Module`, `Context`, `Scheduler` ; un module démarre dès que ses dépendances
  sont terminées ; panne, timeout, binaire absent ou désactivation n'arrêtent pas le pipeline.
- Budget de débit global `--max-rps` (**150**), `--workers` (**6**, était 4 puis monté en phase 4b),
  `--sequential`. `run_stats.json` (durées, gain parallèle), `run_config.json`, `recon_mano merge`.
- `modules.py` : étapes historiques portées à l'identique (golden : 112 fichiers, 0 diff).

### Phase 3 — nuclei en deux passes (`15611ee`)

- Passe 1 par hôte pendant le crawl (**50 req/s**), passe 2 par URL représentante en fin de
  pipeline (**150 req/s**) ; WAF/CDN via `httpx -cdn` à débit × `--nuclei-waf-factor` (**0.3**) ;
  K représentants par signature (`--nuclei-k`, **2**) ; `nuclei.txt` fusionné.

### Phase 4a — sources de surface (`bfef7b0`)

- Sous-domaines : subfinder `-all` (défaut), crt.sh (Python), amass passif (**15 min**).
- Archives : urlfinder → gau (**15 min**, 2 threads) → waybackurls (**15 min**), sérialisées ;
  réduction `--archive-k` (**3**) avant httpx #2 ; httpx #2 ne reteste que les URLs inédites.
- `config.py` : registre `MODULE_DEFAULTS`, `--module-timeout`.

### Phase 4b — JS, secrets, takeover, ports, paramètres

- katana stocke les réponses (`responses/katana`) ; jsluice (endpoints → carte, secrets) et secrets
  (trufflehog `--no-verification`, sinon gitleaks) les lisent hors ligne.
- takeover (CNAME hors périmètre → subzy, **10 req/s**, **15 min**), naabu (`top-1000`, `-exclude-cdn`,
  **100/s**, **30 min**, `full` refusé sans `--naabu-allow-full`) → httpx ports (**50/s**) → nuclei ports ;
  arjun (≤ **30** URLs, **20/s**, **30 min**, `--stable` off).

### Phase 5 — réglage de katana, presets, benchmark, docs

**katana** (`modules.py`, `liveness.py`, `config.py`, `cli.py`)

| Réglage | Défaut | Rôle |
|---|---|---|
| `--katana-rate-limit` | **100** | katana ne prend plus tout le budget (150) : 50 req/s restent pour takeover / naabu / httpx ports *pendant* le crawl. Avec `-n` : nuclei #1 50 + katana 100 (inchangé). `--rate-limit` (150) ne concerne plus qu'httpx |
| `--katana-dedupe-hosts` / `--no-…` | **on** | httpx #1 passe `-hash sha256` ; les hôtes dont la racine a la même empreinte (hash du corps + code + taille) ne sont crawlés qu'une fois ; écartés → `06_katana_dedup.tsv` (`hôte_gardé<TAB>hôte_écarté<TAB>empreinte`). Livrables inchangés |
| `--katana-headless auto\|off\|all` | **auto** | second crawl `-headless` pour les hôtes à framework JS (React, Next.js, Vue.js, Nuxt.js, Angular, AngularJS, Svelte, Ember.js, Backbone.js, Gatsby, Remix…), après le crawl standard ; échec (pas de Chrome) = crawl standard conservé |
| `--katana-headless-concurrency` | **3** | concurrence du crawl headless (standard : 10) |
| `--katana-no-sandbox auto\|on\|off` | **auto** | `-no-sandbox` en headless si le processus est root |

- `-crawl-duration` (`--katana-duration`, 10m) reste **par seed** ; le module entier se borne avec
  `--module-timeout katana=…`.
- katana ne stocke pas les réponses en headless : jsluice et secrets ne voient que le crawl standard.
- Nouveaux fichiers : `06_katana_seeds.txt`, `06_katana_headless_seeds.txt`, `06_katana_dedup.tsv`.
- `ensure_httpx_input` ignore le `03_urlfinder.txt` d'un run précédent quand urlfinder est désactivé
  dans ce run (nécessaire pour le preset `fast`).

**Presets** (`config.py`, `cli.py`)

- `PRESETS` : `fast` (subfinder, subdomains, dnsx, httpx, nuclei1), `surface` (tous sauf nuclei, même
  avec `-n`), `full` (tout, nuclei sous `-n`). `resolve_modules(preset, enable, disable, nuclei, flags)`
  calcule l'état final ; l'option `--mode` n'est pas encore branchée (un commentaire marque l'endroit).
- `--enable a,b` / `--disable a,b` (noms validés, inconnu → exit 2). Précédence : option par module
  (`--no-gau`, `--skip-httpx`…) > `--enable/--disable` > preset. `--skip-*` = alias de `--disable`.
- Un module nuclei activé explicitement sans `-n` est une **erreur** (exit 2). `subdomains` et
  `merge_map` (plomberie) sont activés d'office quand un module qui en dépend l'est ; les désactiver
  alors est une erreur.
- `run_config.json` : champs `preset` et `katana`.

**Benchmark synthétique** (`bench/bench_pipeline.py`) : vrai ordonnanceur + vrai DAG, faux outils aux
durées scénarisées ; compare séquentiel / parallèle, avec et sans `-n`, et vérifie que nuclei #1
chevauche katana. Simulation, pas une mesure.

**Docs** : README réécrit de bout en bout, WORKFLOW.md réécrit (workflow modulaire), ce CHANGELOG.

**Tests** : 463 → **499** (`tests/test_phase5.py` : 36 nouveaux ; 5 assertions de débit katana 150 → 100 mises à jour).

### Valeurs par défaut — rappel

| Réglage | Défaut |
|---|---|
| `--max-rps` / `--workers` | 150 / 6 |
| httpx (`--rate-limit`) | 150 req/s |
| katana (`--katana-rate-limit`) | 100 req/s (était 150) |
| nuclei #1 / nuclei #2 / nuclei ports | 50 / 150 / 50 req/s |
| takeover / naabu / httpx ports / arjun | 10 / 100 / 50 / 20 |
| timeouts de module | amass 15 min · gau 15 · waybackurls 15 · crtsh 10 · jsluice 10 · secrets 10 · takeover 15 · naabu 30 · httpx ports 15 · nuclei ports 30 · arjun 30 · autres illimités |
