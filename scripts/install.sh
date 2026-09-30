#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }

# ─── Check / install Rust ───────────────────────────────────────────
if ! command -v rustc &>/dev/null; then
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    info "Rust found: $(rustc --version)"
fi

# Update rustup
rustup update stable 2>/dev/null || true

# ─── System dependencies (Debian/Ubuntu/Fedora/Arch) ────────────────
install_system_deps() {
    if command -v apt-get &>/dev/null; then
        info "Installing system deps via apt..."
        sudo apt-get update -qq
        sudo apt-get install -y -qq build-essential pkg-config libssl-dev \
            libsqlite3-dev cmake protobuf-compiler curl jq
    elif command -v dnf &>/dev/null; then
        info "Installing system deps via dnf..."
        sudo dnf install -y gcc gcc-c++ make openssl-devel sqlite-devel \
            cmake protobuf-compiler curl jq
    elif command -v pacman &>/dev/null; then
        info "Installing system deps via pacman..."
        sudo pacman -S --needed --noconfirm base-devel openssl sqlite \
            cmake protobuf curl jq
    elif command -v brew &>/dev/null; then
        info "Installing system deps via brew..."
        brew install openssl sqlite cmake protobuf curl jq
    else
        warn "Unknown package manager. Ensure these are installed:"
        warn "  build-essential, openssl-dev, sqlite3-dev, cmake, protobuf-compiler, curl, jq"
    fi
}

install_system_deps

# ─── Build the project ─────────────────────────────────────────────
info "Building Spectra (release mode)..."
cd "$PROJECT_ROOT"
cargo build --release 2>&1 | tail -5

info "Build complete. Binaries at:"
echo "  target/release/spectra-api"
echo "  target/release/spectra-worker"
echo "  target/release/spectra"

# ─── Verify ─────────────────────────────────────────────────────────
for bin in spectra-api spectra-worker spectra; do
    if [[ -f "target/release/$bin" ]]; then
        info "$bin: OK ($(du -h "target/release/$bin" | cut -f1))"
    else
        error "$bin: NOT FOUND"
    fi
done

echo ""
info "Installation complete!"
echo "  Run: ./scripts/start.sh"
