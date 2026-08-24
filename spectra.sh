#!/usr/bin/env bash
# =============================================================================
# Hilbras Spectra — Server Launcher
# Starts all Spectra services: CLI backend API + Web UI frontend.
# Usage: ./spectra.sh [dev|prod|cli|web|health|benchmarks]
# =============================================================================
set -euo pipefail

C_RESET='\033[0m'
C_BOLD='\033[1m'
C_DIM='\033[2m'
C_GOLD='\033[38;5;220m'
C_GREEN='\033[32m'
C_CYAN='\033[36m'
C_YELLOW='\033[33m'
C_RED='\033[31m'

ok()    { echo -e "  ${C_GREEN}✓${C_RESET} $1"; }
warn()  { echo -e "  ${C_YELLOW}⚠${C_RESET} $1"; }
fail()  { echo -e "  ${C_RED}✗${C_RESET} $1" >&2; exit 1; }
info()  { echo -e "  ${C_DIM}$1${C_RESET}"; }

# ─── Resolve project root ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure npm global bin is in PATH
NPM_GLOBAL="${HOME}/.npm-global"
export PATH="$NPM_GLOBAL/bin:$PATH"

# ─── Header ───────────────────────────────────────────────────────────────────
show_banner() {
  echo -e "${C_GOLD}"
  echo "  ╔══════════════════════════════════════════════════════════════╗"
  echo "  ║        🔍  HILBRAS SPECTRA v0.0.6                          ║"
  echo "  ║        Autonomous AI Security Research Platform             ║"
  echo "  ╚══════════════════════════════════════════════════════════════╝"
  echo -e "${C_RESET}"
}

show_usage() {
  show_banner
  echo -e "  ${C_BOLD}Usage:${C_RESET}"
  echo -e "    ${C_CYAN}./spectra.sh${C_RESET}                  ${C_DIM}Start dev mode (web + API)${C_RESET}"
  echo -e "    ${C_CYAN}./spectra.sh dev${C_RESET}              ${C_DIM}Start dev mode (web + API)${C_RESET}"
  echo -e "    ${C_CYAN}./spectra.sh prod${C_RESET}             ${C_DIM}Start production server only${C_RESET}"
  echo -e "    ${C_CYAN}./spectra.sh cli${C_RESET}              ${C_DIM}Run CLI command (pass args after)${C_RESET}"
  echo -e "    ${C_CYAN}./spectra.sh web${C_RESET}              ${C_DIM}Start web UI only${C_RESET}"
  echo -e "    ${C_CYAN}./spectra.sh api${C_RESET}              ${C_DIM}Start API server only${C_RESET}"
  echo -e "    ${C_CYAN}./spectra.sh health${C_RESET}           ${C_DIM}Run health check${C_RESET}"
  echo -e "    ${C_CYAN}./spectra.sh benchmarks${C_RESET}       ${C_DIM}Run benchmark suite${C_RESET}"
  echo -e "    ${C_CYAN}./spectra.sh audit <target>${C_RESET}    ${C_DIM}Run audit on project${C_RESET}"
  echo ""
  echo -e "  ${C_BOLD}Examples:${C_RESET}"
  echo -e "    ${C_DIM}$ ./spectra.sh                  # dev mode, open browser${C_RESET}"
  echo -e "    ${C_DIM}$ ./spectra.sh audit ./my-app   # quick audit${C_RESET}"
  echo -e "    ${C_DIM}$ ./spectra.sh cli version      # CLI version info${C_RESET}"
  echo ""
}

# ─── Pre-flight checks ────────────────────────────────────────────────────────
check_prereqs() {
  if ! command -v node &>/dev/null; then
    fail "Node.js not found. Run: bash install.sh"
  fi
  if [[ ! -d "node_modules" ]]; then
    warn "Dependencies not installed. Running install.sh..."
    bash install.sh
  fi
  if [[ ! -d "web/node_modules" ]]; then
    warn "Web dependencies not installed. Running install.sh..."
    bash install.sh
  fi
}

# ─── Commands ──────────────────────────────────────────────────────────────────

cmd_dev() {
  show_banner
  echo -e "  ${C_BOLD}${C_CYAN}Starting development servers...${C_RESET}"
  echo -e "  ${C_DIM}Backend API : http://localhost:3456${C_RESET}"
  echo -e "  ${C_DIM}Web UI      : http://localhost:3001${C_RESET}"
  echo -e "  ${C_DIM}Press Ctrl+C to stop${C_RESET}"
  echo ""
  npm run dev
}

cmd_prod() {
  show_banner
  info "Building for production..."
  npm run build 2>/dev/null || true
  cd web && npx vite build 2>/dev/null || true
  cd ..
  info "Starting production server on port 3456..."
  info "Open http://localhost:3456 in your browser"
  node dist/web/server.js
}

cmd_web() {
  show_banner
  info "Starting web frontend on http://localhost:3001"
  info "API proxy → http://localhost:3456"
  info "Press Ctrl+C to stop"
  echo ""
  cd web && npx vite
}

cmd_api() {
  show_banner
  if [[ ! -f "dist/web/server.js" ]]; then
    info "Building server first..."
    npm run build 2>/dev/null || true
    cd web && npx vite build 2>/dev/null || true
    cd ..
  fi
  info "Starting API server on http://localhost:3456"
  node dist/web/server.js
}

cmd_cli() {
  shift  # remove 'cli'
  if [[ $# -eq 0 ]]; then
    spectra --help
  else
    spectra "$@"
  fi
}

cmd_health() {
  show_banner
  spectra health
}

cmd_benchmarks() {
  show_banner
  spectra benchmarks
}

cmd_audit() {
  show_banner
  shift  # remove 'audit'
  spectra audit "$@"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
CHECKED=false
check() {
  if [[ "$CHECKED" == "false" ]]; then
    check_prereqs
    CHECKED=true
  fi
}

case "${1:-dev}" in
  dev|development)       check; cmd_dev;;
  prod|production)       check; cmd_prod;;
  web)                   check; cmd_web;;
  api)                   check; cmd_api;;
  cli)                   check; cmd_cli "$@";;
  health)                check; cmd_health;;
  benchmarks)            check; cmd_benchmarks;;
  audit)                 check; cmd_audit "$@";;
  help|--help|-h)        show_usage; exit 0;;
  *)
    # Treat as CLI command: spectra <args>
    check
    spectra "$@"
    ;;
esac
