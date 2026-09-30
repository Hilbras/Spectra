#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
PID_DIR="$PROJECT_ROOT/.pids"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }

mkdir -p "$LOG_DIR" "$PID_DIR"

# ─── Stop existing instances ────────────────────────────────────────
stop_all() {
    info "Stopping existing Spectra processes..."
    for name in spectra-api spectra-worker; do
        pidfile="$PID_DIR/$name.pid"
        if [[ -f "$pidfile" ]]; then
            pid=$(cat "$pidfile")
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                info "Stopped $name (PID $pid)"
            fi
            rm -f "$pidfile"
        fi
    done
    # Kill any stray processes
    pkill -f "spectra-api" 2>/dev/null || true
    pkill -f "spectra-worker" 2>/dev/null || true
    sleep 1
}

# ─── Build if needed ────────────────────────────────────────────────
build_if_needed() {
    api_bin="$PROJECT_ROOT/target/release/spectra-api"
    worker_bin="$PROJECT_ROOT/target/release/spectra-worker"

    needs_build=false
    if [[ ! -f "$api_bin" ]] || [[ ! -f "$worker_bin" ]]; then
        needs_build=true
    fi

    # Check if source is newer than binary
    src_time=$(stat -c %Y "$PROJECT_ROOT/apps/api/src/main.rs" 2>/dev/null || echo 0)
    bin_time=$(stat -c %Y "$api_bin" 2>/dev/null || echo 0)
    if [[ "$src_time" -gt "$bin_time" ]]; then
        needs_build=true
    fi

    if $needs_build; then
        info "Building Spectra..."
        cd "$PROJECT_ROOT"
        cargo build --release 2>&1 | tail -3
    else
        info "Binaries up to date"
    fi
}

# ─── Start API server ───────────────────────────────────────────────
start_api() {
    info "Starting API server on http://0.0.0.0:8080..."
    cd "$PROJECT_ROOT"
    nohup "$PROJECT_ROOT/target/release/spectra-api" \
        > "$LOG_DIR/api.log" 2>&1 &
    echo $! > "$PID_DIR/spectra-api.pid"
    info "API server started (PID $(cat "$PID_DIR/spectra-api.pid"))"
}

# ─── Start Worker ───────────────────────────────────────────────────
start_worker() {
    info "Starting Worker..."
    cd "$PROJECT_ROOT"
    nohup "$PROJECT_ROOT/target/release/spectra-worker" \
        > "$LOG_DIR/worker.log" 2>&1 &
    echo $! > "$PID_DIR/spectra-worker.pid"
    info "Worker started (PID $(cat "$PID_DIR/spectra-worker.pid"))"
}

# ─── Status ─────────────────────────────────────────────────────────
show_status() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Spectra Security Scanner - Status${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    for name in spectra-api spectra-worker; do
        pidfile="$PID_DIR/$name.pid"
        if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            echo -e "  ${GREEN}●${NC} $name  (PID $(cat "$pidfile"))"
        else
            echo -e "  ${RED}●${NC} $name  (stopped)"
        fi
    done
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  Dashboard:  http://localhost:8080"
    echo "  API:        http://localhost:8080/api/v1/health"
    echo "  Logs:       $LOG_DIR/"
    echo ""
}

# ─── Main ───────────────────────────────────────────────────────────
case "${1:-start}" in
    start)
        stop_all
        build_if_needed
        start_api
        start_worker
        show_status
        ;;
    stop)
        stop_all
        info "All services stopped"
        ;;
    restart)
        stop_all
        build_if_needed
        start_api
        start_worker
        show_status
        ;;
    status)
        show_status
        ;;
    logs)
        echo "=== API Log ==="
        tail -20 "$LOG_DIR/api.log" 2>/dev/null || echo "No API log"
        echo ""
        echo "=== Worker Log ==="
        tail -20 "$LOG_DIR/worker.log" 2>/dev/null || echo "No Worker log"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
