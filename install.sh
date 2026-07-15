#!/usr/bin/env bash
#
# install.sh — instalador universal do `alive` (macOS + Linux)
#
# Uso:
#   ./install.sh                instala o alive (pergunta sobre nmap)
#   ./install.sh --with-nmap    instala e também instala o nmap
#   ./install.sh --no-nmap      instala sem instalar o nmap
#   ./install.sh --uninstall    remove o alive
#   ./install.sh -h | --help    mostra esta ajuda
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# Cores
# --------------------------------------------------------------------------- #
if [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  BOLD="$(tput bold)"; DIM="$(tput dim)"; RESET="$(tput sgr0)"
  RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"
  BLUE="$(tput setaf 4)"; MAGENTA="$(tput setaf 5)"; CYAN="$(tput setaf 6)"
else
  BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""
fi

info()  { printf "%s›%s %s\n" "$CYAN" "$RESET" "$1"; }
ok()    { printf "%s✓%s %s\n" "$GREEN" "$RESET" "$1"; }
warn()  { printf "%s!%s %s\n" "$YELLOW" "$RESET" "$1"; }
err()   { printf "%s✗ erro:%s %s\n" "$RED" "$RESET" "$1" >&2; }
step()  { printf "\n%s%s==>%s %s%s\n" "$BOLD" "$MAGENTA" "$RESET" "$BOLD" "$1$RESET"; }

banner() {
  printf "%s%s" "$BOLD" "$CYAN"
  cat <<'EOF'
   __ _  _ (_)_   __ ___
  / _` || || | \ / // -_)
  \__,_||_||_|_/_/ \___|
EOF
  printf "%s%s  instalador — quem está vivo na sua rede?%s\n" "$RESET" "$DIM" "$RESET"
}

usage() {
  banner
  cat <<EOF

${BOLD}uso:${RESET} ./install.sh [opções]

${BOLD}opções:${RESET}
  ${CYAN}--with-nmap${RESET}   instala o alive e o nmap (melhora a detecção)
  ${CYAN}--no-nmap${RESET}     instala o alive sem tocar no nmap
  ${CYAN}--uninstall${RESET}   remove o alive
  ${CYAN}-h, --help${RESET}    mostra esta ajuda
EOF
}

# --------------------------------------------------------------------------- #
# Detecção de SO / gerenciador de pacotes
# --------------------------------------------------------------------------- #
OS="$(uname -s)"
PKG=""
detect_pkg() {
  if [ "$OS" = "Darwin" ]; then
    PKG="brew"
  elif command -v apt-get >/dev/null 2>&1; then PKG="apt"
  elif command -v dnf     >/dev/null 2>&1; then PKG="dnf"
  elif command -v yum     >/dev/null 2>&1; then PKG="yum"
  elif command -v pacman  >/dev/null 2>&1; then PKG="pacman"
  elif command -v zypper  >/dev/null 2>&1; then PKG="zypper"
  else PKG=""; fi
}

SUDO=""
need_sudo() {
  if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  fi
}

pkg_install() {
  # pkg_install <pacote>
  local p="$1"
  case "$PKG" in
    brew)   brew install "$p" ;;
    apt)    $SUDO apt-get update -qq && $SUDO apt-get install -y "$p" ;;
    dnf)    $SUDO dnf install -y "$p" ;;
    yum)    $SUDO yum install -y "$p" ;;
    pacman) $SUDO pacman -Sy --noconfirm "$p" ;;
    zypper) $SUDO zypper install -y "$p" ;;
    *)      return 1 ;;
  esac
}

# --------------------------------------------------------------------------- #
# Etapas
# --------------------------------------------------------------------------- #
PYBIN=""

# Um Python é "saudável" se stdlib essencial (pyexpat/ssl/ctypes) carrega. Algumas
# instalações do Homebrew ficam quebradas (ex.: symbol libexpat), e o pipx herdaria
# o problema — então escolhemos explicitamente um interpretador que funcione.
_python_healthy() {
  "$1" -c "import pyexpat, ssl, ctypes, venv" >/dev/null 2>&1
}

pick_python() {
  local c
  for c in python3.13 python3.12 python3.11 python3.10 python3 python3.14 python3.9; do
    if command -v "$c" >/dev/null 2>&1 && _python_healthy "$c"; then
      PYBIN="$(command -v "$c")"
      return 0
    fi
  done
  return 1
}

ensure_python() {
  step "Verificando Python 3"
  if pick_python; then
    ok "usando: $PYBIN ($("$PYBIN" --version 2>&1))"
    return
  fi
  warn "nenhum Python 3 saudável encontrado; tentando instalar..."
  if [ "$PKG" = "brew" ]; then pkg_install python
  elif [ "$PKG" = "pacman" ]; then pkg_install python
  else pkg_install python3; fi || true
  if pick_python; then
    ok "usando: $PYBIN ($("$PYBIN" --version 2>&1))"
    return
  fi
  err "não encontrei um Python 3 funcional. Instale/repare o Python 3 e rode de novo."
  [ "$PKG" = "brew" ] && err "dica: 'brew reinstall python@3.13' costuma resolver instalações quebradas."
  exit 1
}

# Instalamos num venv dedicado (criado com o Python saudável) e expomos o comando
# via symlink. É mais robusto e portável do que pipx — que, quando instalado pelo
# gerenciador do SO, pode ficar preso a um Python quebrado.
VENV_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/alive/venv"
BIN_DIR="$HOME/.local/bin"
LINK="$BIN_DIR/alive"

resolve_paths() {
  mkdir -p "$BIN_DIR"
}

maybe_install_nmap() {
  local choice="$1"  # yes | no | ask
  step "nmap (opcional, melhora a detecção)"
  if command -v nmap >/dev/null 2>&1; then
    ok "nmap já instalado."
    return
  fi
  if [ "$choice" = "no" ]; then
    info "pulando nmap (--no-nmap). O alive funciona sem ele via ping sweep."
    return
  fi
  if [ "$choice" = "ask" ]; then
    if [ ! -t 0 ]; then
      info "modo não-interativo; pulando nmap. Use --with-nmap para forçar."
      return
    fi
    printf "%sInstalar o nmap agora? Recomendado.%s [S/n] " "$BOLD" "$RESET"
    read -r ans || ans=""
    case "$ans" in
      [Nn]*) info "ok, seguindo sem nmap."; return ;;
    esac
  fi
  if [ -z "$PKG" ]; then
    warn "gerenciador de pacotes não detectado; instale o nmap manualmente se quiser."
    return
  fi
  info "instalando nmap via $PKG..."
  if pkg_install nmap; then ok "nmap instalado."
  else warn "não consegui instalar o nmap; o alive seguirá com ping sweep."; fi
}

install_alive() {
  step "Instalando o alive"
  local dir
  dir="$(cd "$(dirname "$0")" && pwd)"

  info "criando ambiente isolado em ${BOLD}$VENV_DIR${RESET}"
  rm -rf "$VENV_DIR"
  "$PYBIN" -m venv "$VENV_DIR" || { err "falha ao criar o venv."; exit 1; }

  info "instalando dependências (pode levar um minuto)..."
  "$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
  if ! "$VENV_DIR/bin/python" -m pip install --quiet "$dir"; then
    err "falha ao instalar o pacote alive e suas dependências."
    exit 1
  fi

  # Expor o comando `alive` via symlink no BIN_DIR.
  ln -sf "$VENV_DIR/bin/alive" "$LINK"
  ok "alive instalado em $LINK"
  ensure_path_has_bindir
}

ensure_path_has_bindir() {
  case ":$PATH:" in
    *":$BIN_DIR:"*) return ;;  # já está no PATH
  esac
  # Adicionar BIN_DIR ao arquivo de perfil do shell atual.
  local shell_name rc line
  shell_name="$(basename "${SHELL:-bash}")"
  case "$shell_name" in
    zsh)  rc="$HOME/.zshrc" ;;
    bash) rc="$HOME/.bashrc" ;;
    fish) rc="$HOME/.config/fish/config.fish" ;;
    *)    rc="$HOME/.profile" ;;
  esac
  line="export PATH=\"$BIN_DIR:\$PATH\""
  [ "$shell_name" = "fish" ] && line="set -gx PATH $BIN_DIR \$PATH"
  if [ -f "$rc" ] && grep -qF "$BIN_DIR" "$rc" 2>/dev/null; then
    :
  else
    mkdir -p "$(dirname "$rc")"
    printf '\n# adicionado pelo instalador do alive\n%s\n' "$line" >> "$rc"
    warn "adicionei $BIN_DIR ao seu PATH em $rc"
  fi
}

pre_seed_oui() {
  step "Baixando base de fabricantes (OUI)"
  # Best-effort: se falhar (sem internet), o alive baixa no primeiro uso.
  if "$VENV_DIR/bin/python" -c \
     "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()" >/dev/null 2>&1; then
    ok "base OUI atualizada (lookup de fabricante offline pronto)."
  else
    warn "não consegui baixar a base OUI agora. O alive tenta atualizar no primeiro uso."
  fi
}

uninstall_alive() {
  banner
  step "Removendo o alive"
  [ -L "$LINK" ] && rm -f "$LINK" && ok "removido symlink $LINK"
  [ -d "$VENV_DIR" ] && rm -rf "$VENV_DIR" && ok "removido ambiente $VENV_DIR"
  info "pronto. (não removemos entradas de PATH no seu perfil — apague manualmente se quiser)"
  exit 0
}

finish() {
  step "Tudo pronto! 🎉"
  cat <<EOF
${GREEN}O comando ${BOLD}alive${RESET}${GREEN} está instalado.${RESET}

  ${BOLD}Experimente:${RESET}
    ${CYAN}alive${RESET}            escaneia sua rede WiFi
    ${CYAN}alive --help${RESET}     todas as opções

${DIM}Se o comando não for encontrado, reabra o terminal (o PATH foi atualizado)${RESET}
${DIM}ou rode diretamente:${RESET} ${CYAN}$LINK${RESET}
EOF
}

# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
NMAP_CHOICE="ask"
for arg in "$@"; do
  case "$arg" in
    --with-nmap) NMAP_CHOICE="yes" ;;
    --no-nmap)   NMAP_CHOICE="no" ;;
    --uninstall) uninstall_alive ;;
    -h|--help)   usage; exit 0 ;;
    *) err "opção desconhecida: $arg"; usage; exit 2 ;;
  esac
done

banner
detect_pkg
need_sudo
[ -n "$PKG" ] && info "gerenciador de pacotes: ${BOLD}$PKG${RESET}" || warn "gerenciador de pacotes não detectado."

ensure_python
resolve_paths
maybe_install_nmap "$NMAP_CHOICE"
install_alive
pre_seed_oui
finish
