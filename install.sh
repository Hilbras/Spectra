#!/usr/bin/env bash
# =============================================================================
# Hilbras Spectra — Installation Script
# Installs Node.js, npm packages, and verifies system requirements.
# Usage: bash install.sh
# =============================================================================
set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_DIM='\033[2m'
C_GOLD='\033[38;5;220m'
C_GREEN='\033[32m'
C_RED='\033[31m'
C_YELLOW='\033[33m'
C_CYAN='\033[36m'
C_GRAY='\033[90m'

ok()    { echo -e "  ${C_GREEN}✓${C_RESET} $1"; }
warn()  { echo -e "  ${C_YELLOW}⚠${C_RESET} $1"; }
fail()  { echo -e "  ${C_RED}✗${C_RESET} $1" >&2; exit 1; }
info()  { echo -e "  ${C_DIM}$1${C_RESET}"; }
step()  { echo -e "\n${C_BOLD}${C_GOLD}▶ $1${C_RESET}"; }

# ─── Header ───────────────────────────────────────────────────────────────────
echo -e "${C_GOLD}"
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║        🔍  HILBRAS SPECTRA — INSTALLER v0.0.6              ║"
echo "  ║        Autonomous AI Security Research Platform             ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo -e "${C_RESET}"

# ─── Detect OS ────────────────────────────────────────────────────────────────
step "Detecting system..."
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux)   OS="linux";;
  Darwin)  OS="macos";;
  *)       fail "Unsupported OS: $OS";;
esac
case "$ARCH" in
  x86_64)  ARCH="x64";;
  aarch64|arm64) ARCH="arm64";;
  *)       warn "Unknown arch $ARCH, proceeding anyway";;
esac
ok "System: $OS / $ARCH"

# ─── Check Node.js ────────────────────────────────────────────────────────────
step "Checking Node.js..."
if ! command -v node &>/dev/null; then
  warn "Node.js not found. Installing via NodeSource..."
  if [[ "$OS" == "linux" ]]; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y nodejs 2>/dev/null || \
    sudo yum install -y nodejs      2>/dev/null || \
    fail "Could not install Node.js. Please install Node.js 22+ manually."
  else
    fail "Please install Node.js 22+ from https://nodejs.org/"
  fi
fi

NODE_VERSION=$(node --version | sed 's/v//' | cut -d. -f1)
[[ "$NODE_VERSION" -ge 20 ]] || fail "Node.js >= 20 required (found v$NODE_VERSION)"
ok "Node.js $(node --version)"

if ! command -v npm &>/dev/null; then
  fail "npm not found — Node.js installation may be incomplete"
fi
ok "npm $(npm --version)"

# ─── Set up user-level npm prefix (no sudo needed) ───────────────────────────
step "Configuring npm..."
NPM_GLOBAL="$HOME/.npm-global"
mkdir -p "$NPM_GLOBAL/bin" "$NPM_GLOBAL/lib"

# Update PATH in current shell and persist to .bashrc / .zshrc
if [[ ":$PATH:" != *":$NPM_GLOBAL/bin:"* ]]; then
  export PATH="$NPM_GLOBAL/bin:$PATH"
  for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    [[ -f "$rc" ]] && grep -q "npm-global" "$rc" 2>/dev/null || \
      echo "" >> "$rc" && echo "export PATH=\"\$HOME/.npm-global/bin:\$PATH\"" >> "$rc"
  done
  ok "npm global path: $NPM_GLOBAL/bin"
fi

npm config set prefix "$NPM_GLOBAL"
ok "npm prefix → $NPM_GLOBAL"

# ─── Install project dependencies ────────────────────────────────────────────
step "Installing project dependencies..."
npm install --no-audit --no-fund 2>&1 | tail -1 || fail "npm install failed"
ok "Backend dependencies installed"

step "Installing web frontend dependencies..."
cd web
npm install --no-audit --no-fund 2>&1 | tail -1 || fail "web npm install failed"
cd ..
ok "Frontend dependencies installed"

# ─── Build ───────────────────────────────────────────────────────────────────
step "Building TypeScript..."
npm run build || fail "TypeScript build failed"
ok "Backend compiled (dist/)"

step "Building web frontend..."
cd web && npx vite build || fail "Web build failed"
cd ..
ok "Frontend compiled (dist/web/)"

# ─── Install CLI globally ────────────────────────────────────────────────────
step "Installing spectra CLI globally..."
NPM_CONFIG_PREFIX="$NPM_GLOBAL" npm install -g . --no-audit --no-fund 2>&1 | tail -3 || \
  warn "Global install skipped — use 'npm run dev' instead"
ok "spectra CLI ready"

# ─── Initialize config ───────────────────────────────────────────────────────
step "Initializing Spectra config..."
SPECTRA_DIR="$HOME/.spectra"
mkdir -p "$SPECTRA_DIR/data"
if [[ ! -f "$SPECTRA_DIR/config.json" ]]; then
  cat > "$SPECTRA_DIR/config.json" <<'CONF'
{
  "defaultModel": "mock",
  "defaultFormat": "json",
  "autoApproveThreshold": "medium",
  "theme": "dark",
  "profiles": {},
  "apiKeys": {}
}
CONF
  ok "Created $SPECTRA_DIR/config.json"
else
  ok "Config already exists at $SPECTRA_DIR/config.json"
fi

# ─── Check optional dependencies ─────────────────────────────────────────────
step "Checking optional dependencies..."
if command -v docker &>/dev/null; then
  ok "Docker available (sandbox execution enabled)"
else
  warn "Docker not found — sandbox will use process fallback"
fi

if command -v git &>/dev/null; then
  ok "Git available"
else
  warn "Git not found — some features may be limited"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo -e "\n${C_BOLD}${C_GOLD}════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}  ✓  Installation complete!${C_RESET}"
echo -e "${C_RESET}"
echo -e "  ${C_CYAN}Quick start:${C_RESET}"
echo -e "    ${C_BOLD}npm run dev${C_RESET}          ${C_DIM}Start web UI + API server${C_RESET}"
echo -e "    ${C_BOLD}npm run web:start${C_RESET}    ${C_DIM}Start API server only${C_RESET}"
echo -e "    ${C_BOLD}spectra audit ./app${C_RESET}  ${C_DIM}Run CLI audit${C_RESET}"
echo -e "    ${C_BOLD}spectra ui${C_RESET}           ${C_DIM}Launch interactive terminal UI${C_RESET}"
echo -e "${C_GOLD}════════════════════════════════════════════════════════════════${C_RESET}\n"
