#!/usr/bin/env bash
# install.sh - installation en une commande de Recon Mano (Kali / Debian).
# Idempotent : à relancer après chaque `git pull` pour tout mettre à jour.
set -euo pipefail

# --------------------------------------------------------------------------- #
# Constantes
# --------------------------------------------------------------------------- #

# Go minimal : max des directives `go` des outils ProjectDiscovery de base
# (nuclei v3 : 1.26 ; katana, httpx, subfinder : 1.26.0 ; dnsx : 1.25 ; naabu : 1.24).
GO_MIN="1.26"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# nom|module (outils de base : un échec = échec final de l'installation)
CORE_GO_TOOLS=(
  "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "urlfinder|github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
  "katana|github.com/projectdiscovery/katana/cmd/katana@latest"
  "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)
# Outils optionnels : un échec = simple avertissement
OPT_GO_TOOLS=(
  "gau|github.com/lc/gau/v2/cmd/gau@latest"
  "waybackurls|github.com/tomnomnom/waybackurls@latest"
  "jsluice|github.com/BishopFox/jsluice/cmd/jsluice@latest"
  "subzy|github.com/PentestPad/subzy@latest"
  "gf|github.com/tomnomnom/gf@latest"
)
# Paquets apt de base (golang-go est ajouté seulement si aucun Go suffisant).
APT_BASE=(git pipx libpcap-dev curl gcc libc6-dev)
APT_OPTIONAL=(amass arjun trufflehog gitleaks)

# --------------------------------------------------------------------------- #
# Options
# --------------------------------------------------------------------------- #

CORE_ONLY=0
INSTALL_GO=0
NO_APT=0
DRY_RUN=0
VERBOSE=0

usage() {
  cat <<'EOF'
Usage : ./install.sh [options]

Installe Recon Mano et tous ses outils (apt, Go, pipx). Idempotent : à relancer
après chaque `git pull` pour mettre à jour le code et les outils.

Options :
  --core         outils de base uniquement (saute amass, arjun, trufflehog,
                 gitleaks, gau, waybackurls, jsluice, subzy, gf)
  --install-go   installe le Go officiel (go.dev) dans /usr/local/go si Go est
                 absent ou trop ancien, sans poser la question
  --no-apt       saute l'étape apt (machine sans sudo)
  --dry-run      affiche chaque commande au lieu de l'exécuter
  --verbose      affiche toute la sortie des commandes
  -h, --help     cette aide
EOF
}

while (($#)); do
  case "$1" in
    --core) CORE_ONLY=1 ;;
    --install-go) INSTALL_GO=1 ;;
    --no-apt) NO_APT=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --verbose) VERBOSE=1 ;;
    -h | --help) usage; exit 0 ;;
    *) printf 'Option inconnue : %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# --------------------------------------------------------------------------- #
# Affichage
# --------------------------------------------------------------------------- #

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_ARR=$'\033[36m'; C_WARN=$'\033[33m'
  C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_ERR=""; C_ARR=""; C_WARN=""; C_DIM=""; C_BOLD=""; C_OFF=""
fi

info() { printf '%s→%s %s\n' "$C_ARR" "$C_OFF" "$*"; }
ok() { printf '%s✓%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%s!%s %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
fail() { printf '%s✗%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; }
dry() { printf '  %s[dry-run]%s %s\n' "$C_DIM" "$C_OFF" "$*"; }
section() { printf '\n%s== %s ==%s\n' "$C_BOLD" "$*" "$C_OFF"; }
die() { fail "$*"; exit 1; }

# Résultats : "statut|outil|détail" (statut : ok, fail, skip)
RESULTS=()
CORE_FAILED=0
record() { RESULTS+=("$1|$2|$3"); }
record_core_fail() { CORE_FAILED=$((CORE_FAILED + 1)); record fail "$1" "$2"; }

# --------------------------------------------------------------------------- #
# Exécution
# --------------------------------------------------------------------------- #

# run_logged cmd... : exécute en silence (sortie conservée dans un log),
# affiche la fin du log seulement en cas d'échec. --verbose : tout est affiché.
run_logged() {
  if ((DRY_RUN)); then
    dry "$*"
    return 0
  fi
  if ((VERBOSE)); then
    "$@"
    return
  fi
  local log rc=0
  log="$(mktemp)"
  "$@" >"$log" 2>&1 || rc=$?
  if ((rc != 0)); then
    tail -n 8 "$log" | sed 's/^/      /' >&2
  fi
  rm -f "$log"
  return "$rc"
}

# "a >= b" pour des versions pointées (sort -V).
version_ge() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }

# --------------------------------------------------------------------------- #
# 1. Vérifications de base
# --------------------------------------------------------------------------- #

banner() {
  printf '%s' "$C_BOLD"
  printf '+----------------------------------------------+\n'
  printf '|        Recon Mano - installation             |\n'
  printf '+----------------------------------------------+\n'
  printf '%s' "$C_OFF"
  info "Dépôt : $REPO_DIR"
  local opts=""
  ((CORE_ONLY)) && opts+=" --core"
  ((INSTALL_GO)) && opts+=" --install-go"
  ((NO_APT)) && opts+=" --no-apt"
  ((DRY_RUN)) && opts+=" --dry-run"
  ((VERBOSE)) && opts+=" --verbose"
  [[ -n "$opts" ]] && info "Options :$opts"
  return 0
}

SUDO=""
HAVE_APT=0

preflight() {
  section "Vérifications"
  if [[ "$(uname -s)" != "Linux" ]]; then
    if ((DRY_RUN)); then
      warn "Système $(uname -s) : non Linux (simulation --dry-run seulement)."
    else
      die "Ce script cible Linux (Kali/Debian). Système détecté : $(uname -s)."
    fi
  else
    ok "Linux détecté"
  fi

  if command -v apt-get >/dev/null 2>&1; then
    HAVE_APT=1
    ok "apt détecté"
  elif ((DRY_RUN)); then
    HAVE_APT=1
    warn "apt-get absent ici : simulé (--dry-run)."
  else
    warn "apt-get introuvable : l'étape apt sera sautée (installe les paquets à la main)."
  fi

  if [[ "$(id -u)" -eq 0 ]]; then
    ok "Exécuté en root (pas de sudo) - HOME=$HOME"
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
      warn "Lancé via sudo : tout s'installera pour root ($HOME), pas pour $SUDO_USER. Relance sans sudo."
    fi
  elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
    ok "sudo disponible (utilisé pour apt et /usr/local/go uniquement)"
  else
    warn "Ni root ni sudo : étapes apt / /usr/local/go impossibles (utilise --no-apt)."
  fi

  if command -v python3 >/dev/null 2>&1; then
    local pyv
    pyv="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    if version_ge "$pyv" "3.11"; then
      ok "Python $pyv"
    else
      warn "Python $pyv < 3.11 : requires-python = >=3.11, l'installation pipx échouera."
    fi
  else
    warn "python3 introuvable."
  fi
}

# Le PATH est étendu dès le début pour le reste du script.
setup_path() {
  export PATH="/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:$PATH"
  # Évite que git/go demandent des identifiants en cas de dépôt introuvable.
  export GIT_TERMINAL_PROMPT=0
  # -buildvcs=false : pas de dépendance à l'état git pendant `go install`.
  export GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false"
}

# --------------------------------------------------------------------------- #
# 2. apt
# --------------------------------------------------------------------------- #

APT_OK=()        # paquets apt installés (ou simulés)
GO_LOCAL=0       # 1 si /usr/local/go est (ou sera) utilisé

go_version() {
  command -v go >/dev/null 2>&1 || return 1
  go version | sed -n 's/.*go\([0-9][0-9.]*\).*/\1/p' | head -n1
}

go_ok() {
  local v
  v="$(go_version)" || return 1
  [[ -n "$v" ]] && version_ge "$v" "$GO_MIN"
}

apt_step() {
  section "Paquets apt"
  if ((NO_APT)); then
    info "--no-apt : étape sautée"
    record skip "apt" "--no-apt"
    return 0
  fi
  if ((!HAVE_APT)); then
    record skip "apt" "apt-get absent"
    return 0
  fi
  if [[ -z "$SUDO" && "$(id -u)" -ne 0 ]] && ((!DRY_RUN)); then
    warn "Pas de droits root : étape apt sautée."
    record skip "apt" "pas de root/sudo"
    return 0
  fi

  local pkgs=("${APT_BASE[@]}")
  if ! go_ok; then
    pkgs+=(golang-go)
  fi
  # chromium (katana headless) : Debian/Kali = chromium ; Ubuntu = chromium-browser

  info "apt-get update"
  # shellcheck disable=SC2086
  if run_logged $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update; then
    ok "index apt à jour"
  else
    warn "apt-get update a échoué (on continue)"
  fi

  info "Installation : ${pkgs[*]}"
  # shellcheck disable=SC2086
  if run_logged $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"; then
    ok "paquets de base installés"
    record ok "apt (base)" "${pkgs[*]}"
  else
    fail "échec de l'installation apt de base"
    record_core_fail "apt (base)" "${pkgs[*]}"
  fi

  apt_try chromium "katana headless"

  if ((CORE_ONLY)); then
    info "--core : paquets optionnels apt sautés"
    return 0
  fi
  local p
  for p in "${APT_OPTIONAL[@]}"; do
    apt_try "$p" "optionnel"
  done
}

# apt_try paquet détail : un paquet à la fois, un échec est toléré.
apt_try() {
  local pkg="$1" what="$2"
  info "apt install $pkg ($what)"
  # shellcheck disable=SC2086
  if run_logged $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"; then
    ok "$pkg (apt)"
    APT_OK+=("$pkg")
    record ok "$pkg" "apt"
  else
    warn "$pkg indisponible via apt"
  fi
}

in_apt_ok() {
  local p
  for p in ${APT_OK[@]+"${APT_OK[@]}"}; do
    [[ "$p" == "$1" ]] && return 0
  done
  return 1
}

# --------------------------------------------------------------------------- #
# 3. Go
# --------------------------------------------------------------------------- #

install_go_official() {
  local arch ver file tmp
  case "$(uname -m)" in
    x86_64 | amd64) arch="amd64" ;;
    aarch64 | arm64) arch="arm64" ;;
    *) fail "Architecture non gérée : $(uname -m)"; return 1 ;;
  esac

  info "Installation du Go officiel (go.dev) -> /usr/local/go"
  if ((DRY_RUN)); then
    dry "curl -fsSL 'https://go.dev/VERSION?m=text'   # ex. go1.27.3"
    dry "curl -fsSL -o go<version>.linux-${arch}.tar.gz https://go.dev/dl/go<version>.linux-${arch}.tar.gz"
    dry "vérification sha256 via https://go.dev/dl/?mode=json&include=all"
    dry "$SUDO rm -rf /usr/local/go && $SUDO tar -C /usr/local -xzf go<version>.linux-${arch}.tar.gz"
    GO_LOCAL=1
    return 0
  fi

  if [[ -z "$SUDO" && "$(id -u)" -ne 0 ]]; then
    fail "Il faut root (ou sudo) pour écrire dans /usr/local."
    return 1
  fi
  command -v curl >/dev/null 2>&1 || { fail "curl est requis."; return 1; }
  command -v python3 >/dev/null 2>&1 || { fail "python3 est requis (lecture du JSON de checksums)."; return 1; }

  ver="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -n1)"
  [[ "$ver" =~ ^go[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || { fail "Version Go illisible : '$ver'"; return 1; }
  file="${ver}.linux-${arch}.tar.gz"
  info "Dernière version : $ver ($file)"

  tmp="$(mktemp -d)"
  local rc=0
  go_fetch_and_extract "$tmp" "$file" || rc=$?
  rm -rf "$tmp"
  if ((rc != 0)); then return "$rc"; fi
  GO_LOCAL=1
  hash -r
  ok "Go $(go_version) installé dans /usr/local/go"
}

# go_fetch_and_extract dossier_tmp fichier : télécharge, vérifie le sha256, extrait.
go_fetch_and_extract() {
  local tmp="$1" file="$2" sum
  curl -fsSL -o "$tmp/$file" "https://go.dev/dl/$file" || { fail "Téléchargement de $file échoué."; return 1; }
  curl -fsSL -o "$tmp/dl.json" 'https://go.dev/dl/?mode=json&include=all' || { fail "Liste des checksums indisponible."; return 1; }
  sum="$(python3 -c '
import json, sys
for release in json.load(open(sys.argv[1])):
    for f in release.get("files", []):
        if f.get("filename") == sys.argv[2]:
            print(f.get("sha256", ""))
            sys.exit(0)
' "$tmp/dl.json" "$file")"
  [[ -n "$sum" ]] || { fail "Aucun checksum publié pour $file."; return 1; }
  if ! printf '%s  %s\n' "$sum" "$tmp/$file" | sha256sum -c --status -; then
    fail "Checksum sha256 invalide pour $file : archive rejetée."
    return 1
  fi
  ok "sha256 vérifié"
  $SUDO rm -rf /usr/local/go
  $SUDO tar -C /usr/local -xzf "$tmp/$file" || { fail "Extraction échouée."; return 1; }
}

go_step() {
  section "Go (minimum $GO_MIN)"
  if [[ -x /usr/local/go/bin/go ]]; then
    GO_LOCAL=1
  fi

  if go_ok; then
    ok "Go $(go_version) ($(command -v go))"
    return 0
  fi

  if command -v go >/dev/null 2>&1; then
    warn "Go $(go_version) est trop ancien : les outils ProjectDiscovery exigent Go >= $GO_MIN."
  else
    warn "Go est introuvable (Go >= $GO_MIN requis)."
  fi

  local do_install=0
  if ((INSTALL_GO)); then
    do_install=1
  elif ((DRY_RUN)); then
    info "(dry-run) sans --install-go, la question « installer le Go officiel ? » serait posée (ou échec en non interactif)."
    GO_SIMULATED=1
    return 0
  elif [[ -t 0 && -t 1 ]]; then
    local ans=""
    read -r -p "Installer le Go officiel depuis go.dev dans /usr/local/go ? [o/N] " ans || true
    [[ "$ans" =~ ^[oOyY] ]] && do_install=1
  fi

  if ((!do_install)); then
    fail "Go >= $GO_MIN est nécessaire."
    printf '    Relance avec : %s./install.sh --install-go%s\n' "$C_BOLD" "$C_OFF" >&2
    record_core_fail "go" "absent ou < $GO_MIN (relancer avec --install-go)"
    return 1
  fi

  if install_go_official && { ((DRY_RUN)) || go_ok; }; then
    record ok "go" "go.dev -> /usr/local/go"
  else
    fail "Installation du Go officiel échouée."
    record_core_fail "go" "installation officielle échouée"
    return 1
  fi
}
GO_SIMULATED=0

# --------------------------------------------------------------------------- #
# 4. Outils Go
# --------------------------------------------------------------------------- #

GOBIN_DIR="$HOME/go/bin"

resolve_gobin() {
  if command -v go >/dev/null 2>&1; then
    local gb gp
    gb="$(go env GOBIN 2>/dev/null || true)"
    gp="$(go env GOPATH 2>/dev/null || true)"
    if [[ -n "$gb" ]]; then
      GOBIN_DIR="$gb"
    elif [[ -n "$gp" ]]; then
      GOBIN_DIR="${gp%%:*}/bin"
    fi
  fi
  export PATH="$GOBIN_DIR:$PATH"
}

tool_present() {
  command -v "$1" >/dev/null 2>&1 || [[ -x "$GOBIN_DIR/$1" || -x "$GOBIN_DIR/$1.exe" ]]
}

# go_install nom module core|opt
go_install() {
  local name="$1" mod="$2" kind="$3"
  local flags=()
  if ((VERBOSE)); then flags=(-v); fi
  info "go install $name"
  if run_logged go install ${flags[@]+"${flags[@]}"} "$mod"; then
    if ((DRY_RUN)) || tool_present "$name"; then
      ok "$name"
      record ok "$name" "go install"
      return 0
    fi
    fail "$name compilé mais introuvable dans le PATH ($GOBIN_DIR)"
  else
    fail "$name : go install a échoué"
  fi
  if [[ "$kind" == "core" ]]; then
    record_core_fail "$name" "go install échoué"
  else
    warn "$name est optionnel : on continue."
    record fail "$name" "optionnel, go install échoué"
  fi
  return 1
}

# go_build_from_git nom dépôt : clone superficiel puis `go build` (pour les
# dépôts dont le go.mod contient des `replace`, incompatibles avec `go install @latest`).
go_build_from_git() {
  local name="$1" repo="$2"
  info "build de $name depuis $repo"
  if ((DRY_RUN)); then
    dry "git clone --depth 1 $repo <tmp>/$name"
    dry "(cd <tmp>/$name && go build -o $GOBIN_DIR/$name .)"
    record ok "$name" "git clone + go build (repli)"
    ok "$name"
    return 0
  fi
  local tmp
  tmp="$(mktemp -d)"
  mkdir -p "$GOBIN_DIR"
  if run_logged git clone --depth 1 "$repo" "$tmp/src" \
    && (cd "$tmp/src" && run_logged go build -o "$GOBIN_DIR/$name" .); then
    rm -rf "$tmp"
    ok "$name"
    record ok "$name" "git clone + go build (repli)"
    return 0
  fi
  rm -rf "$tmp"
  warn "$name : build depuis les sources échoué (optionnel)."
  record fail "$name" "optionnel, build échoué"
  return 1
}

go_tools_step() {
  section "Outils Go (core)"
  if ! command -v go >/dev/null 2>&1 && ((!GO_SIMULATED)) && ((!DRY_RUN)); then
    fail "Go indisponible : outils Go sautés."
    local t
    for t in "${CORE_GO_TOOLS[@]}"; do
      record_core_fail "${t%%|*}" "Go indisponible"
    done
    return 0
  fi
  resolve_gobin
  info "Binaires installés dans $GOBIN_DIR"

  local entry
  for entry in "${CORE_GO_TOOLS[@]}"; do
    go_install "${entry%%|*}" "${entry#*|}" core || true
  done

  if ((CORE_ONLY)); then
    section "Outils optionnels"
    info "--core : outils optionnels sautés"
    record skip "optionnels" "--core"
    return 0
  fi

  section "Outils Go (optionnels)"
  for entry in "${OPT_GO_TOOLS[@]}"; do
    go_install "${entry%%|*}" "${entry#*|}" opt || true
  done

  section "Repli des outils optionnels absents d'apt"
  fallback_tools
}

# Pour amass / trufflehog / gitleaks / arjun : repli si apt n'a pas pu les installer.
fallback_tools() {
  local need=0

  if ! in_apt_ok amass && ! tool_present amass; then
    need=1
    local flags=()
    if ((VERBOSE)); then flags=(-v); fi
    info "amass (repli go install, v5)"
    # Le go.mod d'amass v5 exige un Go très récent (voir --install-go).
    if run_logged go install ${flags[@]+"${flags[@]}"} github.com/owasp-amass/amass/v5/cmd/amass@main \
      || run_logged go install ${flags[@]+"${flags[@]}"} github.com/owasp-amass/amass/v5/cmd/amass@latest; then
      ok "amass"
      record ok "amass" "go install (repli)"
    else
      warn "amass : repli échoué (optionnel)."
      record fail "amass" "optionnel, apt et go install échoués"
    fi
  fi

  if ! in_apt_ok trufflehog && ! tool_present trufflehog; then
    need=1
    go_build_from_git trufflehog https://github.com/trufflesecurity/trufflehog.git || true
  fi

  if ! in_apt_ok gitleaks && ! tool_present gitleaks; then
    need=1
    go_build_from_git gitleaks https://github.com/gitleaks/gitleaks.git || true
  fi

  if ! in_apt_ok arjun && ! tool_present arjun; then
    need=1
    info "arjun (repli pipx)"
    if run_logged pipx install --force arjun; then
      ok "arjun"
      record ok "arjun" "pipx (repli)"
    else
      warn "arjun : repli échoué (optionnel)."
      record fail "arjun" "optionnel, apt et pipx échoués"
    fi
  fi

  if ((!need)); then
    ok "rien à rattraper"
  fi
}

# --------------------------------------------------------------------------- #
# 5. Templates nuclei
# --------------------------------------------------------------------------- #

nuclei_templates_step() {
  section "Templates nuclei"
  if ((DRY_RUN)) || command -v nuclei >/dev/null 2>&1; then
    info "nuclei -update-templates"
    if run_logged nuclei -update-templates -silent; then
      ok "templates nuclei à jour"
      record ok "nuclei-templates" "update"
    else
      warn "mise à jour des templates échouée (non bloquant)."
      record fail "nuclei-templates" "non bloquant"
    fi
  else
    warn "nuclei absent : templates non mis à jour."
    record skip "nuclei-templates" "nuclei absent"
  fi
}

# --------------------------------------------------------------------------- #
# 6. CLI Python
# --------------------------------------------------------------------------- #

python_step() {
  section "CLI Python (pipx)"
  if ! command -v pipx >/dev/null 2>&1 && ((!DRY_RUN)); then
    fail "pipx introuvable (apt install pipx)."
    record_core_fail "recon_mano" "pipx absent"
    return 0
  fi
  info "pipx install --force $REPO_DIR"
  if run_logged pipx install --force "$REPO_DIR"; then
    ok "recon_mano installé"
    record ok "recon_mano" "pipx"
  else
    fail "pipx install a échoué"
    record_core_fail "recon_mano" "pipx install échoué"
    return 0
  fi
  info "pipx ensurepath"
  run_logged pipx ensurepath || warn "pipx ensurepath a échoué (non bloquant)."
}

# --------------------------------------------------------------------------- #
# 7. Persistance du PATH
# --------------------------------------------------------------------------- #

persist_path() {
  section "PATH persistant"
  local line_main='export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"  # recon_mano'
  local line_go='export PATH="/usr/local/go/bin:$PATH"  # recon_mano:go'
  local rc
  for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if ((DRY_RUN)); then
      dry "ajouterait à $rc (si absent) : $line_main"
      ((GO_LOCAL)) && dry "ajouterait à $rc (si absent) : $line_go"
      continue
    fi
    [[ -f "$rc" ]] || : >"$rc"
    if grep -qE '# recon_mano$' "$rc"; then
      info "$rc : PATH déjà présent"
    else
      printf '\n%s\n' "$line_main" >>"$rc"
      ok "$rc : PATH ajouté"
    fi
    if ((GO_LOCAL)) || [[ -x /usr/local/go/bin/go ]]; then
      if grep -qF '# recon_mano:go' "$rc"; then
        info "$rc : /usr/local/go/bin déjà présent"
      else
        printf '%s\n' "$line_go" >>"$rc"
        ok "$rc : /usr/local/go/bin ajouté"
      fi
    fi
  done
  return 0
}

# --------------------------------------------------------------------------- #
# 8. Vérification finale et résumé
# --------------------------------------------------------------------------- #

final_check() {
  section "Vérification (recon_mano --check)"
  if ((DRY_RUN)); then
    dry "recon_mano --check"
    return 0
  fi
  if command -v recon_mano >/dev/null 2>&1; then
    if recon_mano --check; then
      ok "tous les outils requis sont disponibles"
    else
      warn "recon_mano --check signale des outils requis manquants (voir plus haut)."
    fi
  else
    warn "recon_mano introuvable dans le PATH (ouvre un nouveau terminal)."
  fi
}

summary() {
  section "Résumé"
  local line status name detail mark color n_ok=0 n_fail=0 n_skip=0
  printf '%s%-3s %-18s %s%s\n' "$C_BOLD" "" "OUTIL" "DÉTAIL" "$C_OFF"
  for line in ${RESULTS[@]+"${RESULTS[@]}"}; do
    status="${line%%|*}"
    line="${line#*|}"
    name="${line%%|*}"
    detail="${line#*|}"
    case "$status" in
      ok) mark="✓"; color="$C_OK"; n_ok=$((n_ok + 1)) ;;
      fail) mark="✗"; color="$C_ERR"; n_fail=$((n_fail + 1)) ;;
      *) mark="-"; color="$C_DIM"; n_skip=$((n_skip + 1)) ;;
    esac
    printf '%s%-3s%s %-18s %s\n' "$color" "$mark" "$C_OFF" "$name" "$detail"
  done
  printf '\n%d installé(s), %d échec(s), %d sauté(s)' "$n_ok" "$n_fail" "$n_skip"
  if ((DRY_RUN)); then printf ' %s(simulation)%s' "$C_DIM" "$C_OFF"; fi
  printf '\n'

  if ((CORE_FAILED > 0)); then
    printf '\n%s✗ %d outil(s) de base en échec : l'"'"'installation est incomplète.%s\n' "$C_ERR" "$CORE_FAILED" "$C_OFF"
    printf '  Corrige puis relance ./install.sh (idempotent).\n'
    return 1
  fi
  printf '\n%s✓ Installation terminée.%s\n' "$C_OK" "$C_OFF"
  printf 'Étape suivante :\n'
  printf '  %ssource ~/.zshrc%s   (ou ouvre un nouveau terminal)\n' "$C_BOLD" "$C_OFF"
  printf '  %srecon_mano cible.com -y%s\n' "$C_BOLD" "$C_OFF"
  printf '%sAprès un git pull : relance ./install.sh pour tout mettre à jour.%s\n' "$C_DIM" "$C_OFF"
  return 0
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

main() {
  banner
  preflight
  setup_path
  apt_step
  go_step || true
  go_tools_step
  nuclei_templates_step
  python_step
  persist_path
  final_check
  summary
}

main
