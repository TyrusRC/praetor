#!/usr/bin/env bash
# Praetor — BloodHound CE auto-setup (optional)
#
# Installs / starts a local BloodHound Community Edition (the graph UI +
# Neo4j the kali.org 'bloodhound' package ships — CE, not legacy BloodHound)
# via the official Docker Compose quickstart. Idempotent: re-running just
# ensures the stack is up.
#
# Praetor's ingest_bloodhound / sync_bloodhound_to_ghostwriter tools do NOT
# need this running — they parse a SharpHound/bloodhound-python/certipy
# collection file directly and forward high-value edges to the operator log
# + Ghostwriter. This script is for the VISUAL graph UI (Cypher queries,
# "shortest path to Domain Admins") on top of the same collection file —
# import it by hand via the UI's Upload Files button once the stack is up.
# No Praetor tool talks to BloodHound CE's own API; nothing here is
# auto-wired into Praetor's .env.
#
# Usage:  ./setup-bloodhound.sh
# Env:    BLOODHOUND_DIR   install location (default: $HOME/bloodhound-ce)

set -euo pipefail

BH_DIR="${BLOODHOUND_DIR:-$HOME/bloodhound-ce}"
COMPOSE_URL="https://ghst.ly/getbhce"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info() { echo -e "${BLUE}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; exit 1; }
has()  { command -v "$1" >/dev/null 2>&1; }

# ── Preflight ────────────────────────────────────────────────────────
info "Preflight checks..."
has docker || fail "docker not found. Install Docker Desktop + WSL integration first."
docker compose version >/dev/null 2>&1 || docker-compose version >/dev/null 2>&1 \
    || fail "docker compose not found (need Docker Compose v2)."
docker info >/dev/null 2>&1 || fail "docker daemon not reachable (start Docker Desktop / dockerd)."
ok "docker $(docker --version | awk '{print $3}' | tr -d ,), compose present, daemon up"

COMPOSE() { docker compose "$@" 2>/dev/null || docker-compose "$@"; }

# ── Fetch the official quickstart compose file (idempotent) ──────────
mkdir -p "$BH_DIR"
if [ -f "$BH_DIR/docker-compose.yml" ]; then
    ok "docker-compose.yml already present at $BH_DIR — leaving as-is"
else
    info "Fetching the official BloodHound CE quickstart compose file..."
    curl -fsSL "$COMPOSE_URL" -o "$BH_DIR/docker-compose.yml" \
        || fail "download failed — fetch manually: curl -L $COMPOSE_URL -o $BH_DIR/docker-compose.yml"
    ok "saved to $BH_DIR/docker-compose.yml"
fi

# ── Start (idempotent — compose up is a no-op on an already-running stack) ──
cd "$BH_DIR"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qi bloodhound; then
    ok "BloodHound CE containers already running — ensuring they are up to date"
else
    warn "Not started yet. Pulling images and starting the stack (several minutes, first run)."
fi
COMPOSE up -d || fail "docker compose up failed — see output above"
ok "stack up"

# ── The quickstart writes a random initial admin password into its own
#    .env on first run — read it back instead of asking the operator to
#    find it themselves. ──────────────────────────────────────────────
ADMIN_PW=""
if [ -f "$BH_DIR/.env" ]; then
    ADMIN_PW="$(grep -E '^BLOODHOUND_INITIAL_PASSWORD=' "$BH_DIR/.env" 2>/dev/null | cut -d= -f2-)"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo "  BloodHound CE ready"
echo "════════════════════════════════════════════════════"
echo "  URL:        http://127.0.0.1:8080/ui/login"
echo "  Login user: admin"
if [ -n "$ADMIN_PW" ]; then
    echo "  Password:   $ADMIN_PW   (from $BH_DIR/.env — change it on first login)"
else
    echo "  Password:   check $BH_DIR/.env for BLOODHOUND_INITIAL_PASSWORD, or:"
    echo "              docker compose -f $BH_DIR/docker-compose.yml logs app | grep -i 'initial password'"
fi
echo ""
echo "  This does NOT auto-import anything — Praetor's ingest_bloodhound"
echo "  tool parses a collection file independently of this UI. To see the"
echo "  SAME data as a graph, upload the identical SharpHound/bloodhound-"
echo "  python/certipy file here (UI -> Upload Files) after logging in."
echo ""
echo "  Stop the stack:  cd $BH_DIR && docker compose down"
