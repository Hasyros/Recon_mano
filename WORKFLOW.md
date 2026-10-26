# Recon Mano — Workflow & utilisation

Guide du pipeline modulaire. Le [README](README.md) est la référence (tables des
modules, des options, des fichiers) ; ce document explique **ce qui se passe pendant un
run**, **pourquoi** la chaîne est construite ainsi et **comment** la piloter.

> ⚠️ À n'utiliser que sur des cibles pour lesquelles tu as une **autorisation
> explicite** : programme de bug bounty dans son périmètre, mission de pentest, ou
> infrastructure t'appartenant.

---

## 1. La logique : un entonnoir, en parallèle

L'idée directrice est d'aller **du plus large au plus précis** : on récolte un maximum de
données brutes (sous-domaines, archives), on élimine ce qui ne répond pas, et on ne creuse
(crawl, ports, paramètres, nuclei) que ce qui est **confirmé vivant et dans le périmètre**.

Ce qui a changé depuis la première version : la chaîne n'est plus une suite de six étapes,
mais un **graphe de modules**. Chaque module sait de quoi il dépend ; un ordonnanceur
démarre tout module dont les dépendances sont terminées, en parallèle, dans la limite de
`--workers` modules et d'un budget de débit global `--max-rps` (la cible encaisse le trafic
cumulé, pas celui de chaque outil).

```
subfinder ─┐
crtsh ─────┼─ subdomains ── dnsx ─┬─ takeover (CNAME → subzy)
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


Deux « branches » se rejoignent : **le présent** (ce qui répond aujourd'hui : sous-domaines
→ DNS) et **le passé** (ce qui a existé : archives). On les fusionne, on valide d'un seul
coup avec httpx, on crawle, puis **httpx #2** revalide tout ce que katana, les archives et
jsluice ont ajouté — personne ne connaissait leur code HTTP.

---

## 2. Un run, pas à pas

Dans l'ordre où les choses se produisent. Les durées sont des ordres de grandeur.

### Avant le premier outil

1. **Lecture des options et choix des modules.** `recon_mano` part du jeu de modules `full`
   (tout, sauf nuclei), applique `--enable` / `--disable`, puis les options par module
   (`--no-gau`, `--skip-httpx`…). Une option inconnue ou contradictoire s'arrête ici avec le
   code 2 (par ex. `--enable nuclei2` sans `-n`).
2. **Périmètre.** Il est demandé **une seule fois** (cible + domaines `--in-scope`), jamais
   pendant l'exécution ; `-y` évite la question. Ce périmètre est ensuite appliqué après
   **chaque** étape qui produit des hôtes ou des URLs ; les rejets vont dans `rejected_scope.tsv`.
3. **Bannière** (cible, sortie, config), puis écriture de `run_config.json`.

### Sources : en parallèle, dès le début (0 → ~10 min)

Quatre modules sans dépendance démarrent ensemble :

- **subfinder** (`-all`), **crt.sh** (module Python, sans binaire) et **amass** (passif,
  15 min max) cherchent des sous-domaines ; **`subdomains`** les fusionne
  (`01_subdomains.txt`). Si *aucune* source ne rend d'hôte en périmètre, `subdomains` échoue
  et tout l'aval est ignoré proprement (code retour 1).
- **urlfinder** (depuis l'apex seul) lance la chaîne d'archives **urlfinder → gau →
  waybackurls**, volontairement sérialisée : les trois interrogent les mêmes archives
  publiques, déjà rate-limitées par IP. Cette chaîne n'envoie rien à la cible.

### DNS, puis une seule passe httpx

- **dnsx** (`-wd` : filtre les wildcards) ne garde que les hôtes qui résolvent.
- **httpx #1** attend dnsx *et* urlfinder, fusionne hôtes + URLs d'archive dans une seule
  entrée (`04_httpx_input.txt`) et ne garde que ce qui **répond** (`urls_live.txt`, codes
  `--live-codes`). C'est le filtre de tout l'aval : katana, nuclei et naabu ne voient jamais
  une cible non confirmée. Il demande aussi `-hash sha256` (pour le dédoublonnage de katana)
  et, avec `-n`, `-cdn` (pour ralentir derrière les WAF).

### Quand httpx a fini : tout part en même temps

- **katana** crawle les seeds vivantes (`06_katana.txt`) et **stocke les réponses** dans
  `responses/katana`. Avant de partir il écarte les hôtes qui servent un contenu identique à
  un autre (`06_katana_dedup.tsv`) et envoie les hôtes à framework JS (React, Vue, Next.js…)
  dans un second crawl headless. Débit demandé : **100 req/s**, ce qui laisse 50 req/s aux
  modules ci-dessous *pendant* le crawl (voir §4).
- **jsluice** et **secrets** lisent les réponses stockées (aucune requête) une fois katana
  fini : endpoints cachés dans le JS, secrets (trufflehog **sans vérification**, sinon gitleaks).
- **takeover** (CNAME hors périmètre → subzy) et **naabu** (ports des hôtes vivants) →
  **httpx ports** (services web hors 80/443) démarrent dès que dnsx est fini et qu'il reste du
  budget de débit.
- Avec `-n` : **nuclei #1** (par hôte) tourne *pendant* le crawl, et **nuclei ports** sur les
  services hors 80/443.

### La fin : carte, revalidation, paramètres

- **merge_map** attend katana, jsluice et la chaîne d'archives : carte `all_urls.txt` = seeds
  + crawl + archives réduites (K URLs par signature) + endpoints JS, périmètre strict.
- **httpx #2** ne teste que les URLs **inédites** de la carte (celles qu'httpx #1 n'a pas
  déjà vues) et reprend les services hors 80/443 : `urls_all_final.txt`, `urls_200_final.txt`,
  `urls_live_final.txt`.
- **tree** produit `urls_tree.html` ; **arjun** cherche des paramètres cachés sur ≤ 30 URLs
  représentatives ; avec `-n`, **nuclei #2** (DAST + exposition) clôt le pipeline en
  attendant arjun.

### Les trois décisions de conception qui expliquent la forme du graphe

**urlfinder est une branche parallèle, pas un maillon après httpx.** Les archives sont la
seule source où un hôte *mort* a encore de la valeur : le brancher après le filtre des
vivants reviendrait à ne jamais demander à la Wayback ce qu'il y avait sur les hôtes tombés —
précisément les fichiers oubliés qu'on cherche. Il part de l'apex : un appel couvre tous les
sous-domaines connus des archives.

**Les deux branches fusionnent avant une passe httpx unique.** Chaîner `dnsx → urlfinder →
httpx` perdrait tout hôte sans historique (un `staging-v2` mis en ligne le mois dernier
résout et sert du HTTP, mais la Wayback ne le connaît pas). Les ensembles sont disjoints :
on les réunit et on ne paie qu'une passe réseau.

**httpx n'est pas une étape, c'est un filtre.** On le ré-applique dès qu'on génère des URLs
depuis une source non vivante (archives, crawl, JS). Sans lui, on sèmerait nuclei et arjun
avec des milliers d'URLs mortes.

---

## 3. Lire le board et le récapitulatif

### Pendant le run

Un **board live** (une ligne par module) : état (`…` attente · `▶` en cours · `✓` terminé ·
`✗` échec · `⏱` timeout · `–` ignoré · `⊘` désactivé), nombre de lignes déjà écrites par l'outil,
temps écoulé et **débit accordé**. Un module en attente de budget l'indique (« attend le
budget de débit »). Quand un module se termine, son bloc de détails est imprimé d'un coup
(durée, fichiers, diagnostics, ce qui a été écarté par le périmètre). En `-v`, pas de board :
les commandes exactes et le flux des outils défilent (préfixe `outil │`).

### À la fin

- La liste des **livrables** (carte, surface vivante, 200, arbre, secrets, takeover, ports,
  paramètres) — seulement ceux que **ce** run a produits.
- Le **récapitulatif** : une ligne par module, dans l'ordre de **démarrage**, avec la colonne
  `début` (décalage depuis le lancement). C'est là qu'on voit nuclei #1 démarrer pendant le crawl
  katana, ou naabu attendre. La légende sous le tableau compare la **durée réelle** au
  **cumul des modules** : la différence est le gain du parallélisme.
- `run_stats.json` : les mêmes informations en JSON (statut, début, fin, durée, débit accordé,
  note par module). C'est l'outil pour comparer deux versions ou deux réglages sur la même cible.

### Quand quelque chose a l'air bizarre

| Ce que tu vois | Interprétation |
|---|---|
| `⊘ désactivé — binaire X introuvable` | Le module saute, le pipeline continue avec ses replis (`recon_mano --check` liste les binaires). |
| `– ignoré — désactivé (option)` | Éteint par `--no-X`, `--disable`, `--skip-X` ou le preset. |
| `– ignoré — httpx n'a trouvé aucune URL vivante` | Volontaire : katana ne crawle jamais de cibles non confirmées. |
| `… attend le budget de débit` | Le budget `--max-rps` est consommé par d'autres modules ; il démarrera quand l'un se libère. |
| `✗ échec` | Message dans le tableau, traceback complet avec `-v`. Les modules indépendants finissent quand même. |
| katana : `headless en échec` | Pas de Chrome/Chromium : le crawl standard est conservé, rien d'autre ne change. |
| `→ 0 entrées · 5s` sur urlfinder | Throttling par IP des archives (voir §6), pas un timeout. |

---

## 4. Le budget de débit en pratique

`--max-rps` (défaut 150) est le débit **total** vers la cible, partagé par httpx, katana,
takeover, naabu, httpx ports, httpx #2, arjun et les nuclei. Chaque module demande un débit
(`--katana-rate-limit`, `--naabu-rate`…) et reçoit `min(demandé, budget restant)` à son départ ;
s'il reste moins de `min(demandé, 10)`, il attend.

Avec les défauts, **sans `-n`** :

| Moment | Qui tourne | Budget |
|---|---|---|
| httpx #1 | httpx | 150 |
| crawl | katana 100 + takeover 10 + naabu 40 (sur 100 demandés) | 150 |
| après naabu | katana 100 + httpx ports 50 | 150 |
| fin | httpx #2 150, puis arjun 20 | ≤ 150 |

Avec **`-n`**, nuclei #1 (50) + katana (100) remplissent le budget : takeover et naabu attendent
la fin de nuclei #1. Pour les faire avancer en même temps, monte `--max-rps` (et les débits
demandés) **si la cible l'accepte**.

Si le crawl katana te paraît trop lent ou trop agressif : `--katana-rate-limit` règle son débit,
`--module-timeout katana=45` borne le **module entier** (le `-ct` de katana, `--katana-duration`,
s'applique **par seed**, pas à l'ensemble du run).

---

## 5. Commandes typiques

```bash
# Run complet par défaut : tout est actif sauf nuclei
recon_mano cible.com sortie

# Même chose + nuclei (opt-in : la seule étape qui envoie des payloads)
recon_mano cible.com sortie -n

# Repartir de zéro (efface les anciens fichiers de sortie)
recon_mano cible.com sortie --clean

# Périmètre élargi à d'autres domaines de l'organisation, sans question interactive
recon_mano cible.com sortie --in-scope autre.fr,encore.com -y

# Exclure des hôtes (égaux ou sous-domaines d'une entrée)
recon_mano cible.com sortie --exclude status.cible.com,prod-legacy.cible.com

# Couper des modules : options dédiées, ou --disable (virgules, noms du registre)
recon_mano cible.com sortie --no-amass --no-gau
recon_mano cible.com sortie --disable amass,naabu,arjun

# Ce qui est explicitement demandé l'emporte : --disable gau mais --gau → gau tourne
recon_mano cible.com sortie --disable gau,waybackurls --gau

# Partir de sous-domaines déjà trouvés (ex. ffuf) : remplace subfinder
recon_mano cible.com sortie --subdomains mes_sous_domaines.txt

# Ralentir / limiter
recon_mano cible.com sortie --max-rps 60 --katana-rate-limit 40 --module-timeout katana=30

# Un seul module à la fois (débogage, comparaison avec l'ancien comportement)
recon_mano cible.com sortie --sequential

# Voir les commandes exactes et le flux des outils
recon_mano cible.com sortie -v

# Rejouer la fusion finale sans relancer d'outil (après avoir édité une liste ou le périmètre)
recon_mano merge sortie

# Régénérer l'arbre HTML
recon_mano report sortie
recon_mano report sortie/urls_all_final.txt     # arbre tous codes (401/403/500)
```

**Précédence des réglages** (de la plus forte à la plus faible) : option par module
(`--gau` / `--no-gau`, `--skip-httpx`…) > `--enable` / `--disable` > preset (aujourd'hui `full`).
Les presets `fast` et `surface` existent déjà dans `recon_mano/config.py` ; l'option `--mode`
qui les expose reste à brancher. Les modules nuclei exigent toujours `-n` : les activer
explicitement sans `-n` est une erreur, pas un oubli silencieux.

---

## 6. nuclei : opt-in, deux passes

nuclei est une **attaque** (templates actifs, payloads). Il ne part que sur `-n`, uniquement
sur des cibles **vivantes** et **dans le périmètre**. Sans `-n`, rien de nuclei n'existe :
même commande httpx, aucun fichier, aucun budget réservé.

| | Passe 1 — nuclei #1 | Passe 2 — nuclei #2 |
|---|---|---|
| Granularité | par **hôte** | par **URL représentante** (K par signature) |
| Quand | dès qu'httpx #1 a fini, **pendant** le crawl | en fin de pipeline, après httpx #2 et arjun |
| Templates | `--nuclei-mode` (`auto` = `-as`), sans fuzz/dos/intrusive | run DAST (`-dast`) + run exposition |
| Débit demandé | 50 | 150 |

`nuclei ports` applique les réglages de la passe 1 aux services web hors 80/443. Détails (WAF/CDN,
signatures, liste prioritaire, `gf`) : README, section « nuclei en deux passes ».

---

## 7. urlfinder : lire un résultat maigre

C'est le point le plus subtil. Les archives publiques sont **fortement rate-limitées par IP** :
un run peut rendre 19000 URLs et le suivant 30, sans que rien ne soit cassé. Quand ton IP a
épuisé son quota, Wayback/CommonCrawl répondent souvent par une page **vide en HTTP 200**, pas
une erreur 429 : urlfinder enregistre un succès (`Found 30 urls`) sans warning.

Ce que fait le pipeline : `-all` par défaut ; `-v` (pas `-silent`) pour capturer la sortie par
source et **toujours** afficher le récap, les `[WRN]` et un avertissement de throttling silencieux
quand le résultat est bas sans erreur ; aucun timeout ; un retry sur résultat vide avec délai
progressif (`--urlfinder-retries`, `--urlfinder-retry-wait`).

| Ce que tu vois | Interprétation |
|---|---|
| `→ 0 entrées · 5s` | coupé net par les sources (pas un timeout) |
| `→ 69 entrées · 36s` | a tourné mais dégradé / throttlé |
| `→ 19000 entrées · 2m` | run sain |

Pour retrouver du volume : laisser la fenêtre de quota reposer (quelques heures) ou changer
d'IP. Une clé d'API dans `~/.config/urlfinder/provider-config.yaml` ajoute *d'autres* sources
mais ne dé-throttle pas Wayback. gau et waybackurls viennent compléter, sérialisés derrière
urlfinder pour ne pas marteler les mêmes archives.

---

## 8. Dépannage

| Symptôme | Cause probable / remède |
|---|---|
| `httpx (ProjectDiscovery) introuvable` | Un `httpx` du PATH est le client Python. Installe le vrai (`./install.sh`, ou `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`) ou passe `--httpx-bin`. |
| urlfinder rend très peu (sans erreur) | Throttling silencieux par IP. Laisse reposer / change d'IP (§7). |
| dnsx efface presque tout | Domaine wildcard légitime, ou résolveur lent. Diagnostique avec `--no-wildcard-filter`. |
| katana traîne / ne finit pas | Le `-ct` est **par seed** : borne le module (`--module-timeout katana=45`), baisse `--depth 1` ou `--katana-max-pages`. Le dédoublonnage par contenu (activé) réduit déjà les hôtes. |
| katana sort du périmètre | Hôtes tiers venus des archives. Resserre `--scope fqdn` ou `dn` ; le filtre de périmètre écarte de toute façon ces hôtes des résultats. |
| katana headless « en échec » | Installe Chromium (`sudo apt install chromium`) ; en root katana passe `-no-sandbox` tout seul (`--katana-no-sandbox`). Ou coupe-le : `--katana-headless off`. |
| jsluice / secrets « ignorés » | `--no-katana-store`, ou katana n'a rien stocké (hôtes 100 % headless : katana ne stocke pas les réponses dans ce mode). |
| naabu / takeover attendent | Le budget de débit est pris (nuclei #1 + katana = 150). Monte `--max-rps` ou attends la fin de nuclei #1. |
| Une étape échoue | Le pipeline ne meurt pas sur un exit code non nul : il affiche l'erreur et continue avec ce qu'il a. |
| `--enable nuclei2` refusé | Les modules nuclei exigent `-n`. |

---

## 9. Rappel éthique

Ce pipeline génère du trafic actif (httpx, katana, naabu, arjun, subzy) et, avec `-n`, envoie des
payloads. Ne le lance que dans un périmètre autorisé. Les étapes passives (subfinder, crt.sh,
amass, urlfinder, gau, waybackurls) interrogent des tiers : reste dans les limites de leurs
conditions d'utilisation. trufflehog n'est jamais lancé avec vérification : essayer un secret
trouvé, ce serait utiliser un identifiant tiers hors périmètre.
