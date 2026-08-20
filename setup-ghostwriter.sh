#!/usr/bin/env bash
# Praetor — Ghostwriter auto-setup
#
# Installs / starts a local Ghostwriter (SpecterOps reporting + oplog hub) and
# wires Praetor's .env to forward BOTH lanes (web/Burp findings + network
# operator log) into it. Idempotent: re-running just ensures it is up and the
# .env is current.
#
# Ghostwriter is a heavyweight Docker stack (Postgres/Neo4j/Hasura/Django). This
# script drives the official ghostwriter-cli. It does NOT echo secrets — the
# Hasura admin secret is written to .env (a file), and the admin LOGIN password
# is retrieved with a command you run yourself (printed at the end).
#
# Usage:  ./setup-ghostwriter.sh
# Env:    GHOSTWRITER_DIR   install location (default: $HOME/Ghostwriter)
#         GHOSTWRITER_HOST  URL Praetor uses (default: https://127.0.0.1)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GW_DIR="${GHOSTWRITER_DIR:-$HOME/Ghostwriter}"
GW_HOST="${GHOSTWRITER_HOST:-https://127.0.0.1}"
ENV_FILE="$SCRIPT_DIR/.env"
GW_REPO="https://github.com/GhostManager/Ghostwriter.git"

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
has git || fail "git not found."
ok "docker $(docker --version | awk '{print $3}' | tr -d ,), compose present, daemon up"

# ── Clone (idempotent) ───────────────────────────────────────────────
if [ ! -d "$GW_DIR/.git" ]; then
    info "Cloning Ghostwriter -> $GW_DIR (first time only)..."
    git clone --depth 1 "$GW_REPO" "$GW_DIR" || fail "clone failed"
    ok "cloned"
else
    ok "Ghostwriter repo present at $GW_DIR"
fi

cd "$GW_DIR"
CLI="./ghostwriter-cli-linux"
[ -f "$CLI" ] || fail "ghostwriter-cli-linux not found in $GW_DIR (repo layout changed?)"
chmod +x "$CLI" 2>/dev/null || true

# `config get KEY` prints a table: header + a ` KEY\t<value>` row. Extract the
# value = last field on the row whose first field equals the key. (config values
# are generated on read, so they exist even before install — do NOT use them to
# detect install state.)
gw_get() { "$CLI" config get "$1" 2>/dev/null | awk -v k="$1" '$1==k{print $NF}'; }

# ── Install or ensure running ────────────────────────────────────────
# Installed iff Ghostwriter containers exist (created by `install`).
if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qi ghostwriter; then
    ok "Ghostwriter containers exist — ensuring they are up"
    "$CLI" containers up 2>&1 | tail -3 || warn "containers up returned non-zero"
else
    warn "Not installed yet. Running production install (downloads images + builds;"
    warn "this takes several minutes and binds TCP 443)."
    "$CLI" install || fail "ghostwriter-cli install failed — see output above"
    ok "install complete"
fi

# ── Retrieve the Hasura admin secret (written to .env, never echoed) ──
ADMIN_SECRET="$(gw_get HASURA_GRAPHQL_ADMIN_SECRET)"
if [ -z "$ADMIN_SECRET" ]; then
    warn "Could not read HASURA_GRAPHQL_ADMIN_SECRET automatically."
    warn "Create a UI API token instead (profile -> Create API token) and put it in"
    warn ".env as GHOSTWRITER_API_TOKEN=<token>. Continuing with URL only."
fi

# ── Best-effort: find an existing Oplog id via GraphQL ───────────────
OPLOG_ID=""
if [ -n "$ADMIN_SECRET" ]; then
    info "Querying Ghostwriter for an existing Oplog..."
    RESP="$(curl -sk --max-time 15 "$GW_HOST/v1/graphql" \
        -H "Content-Type: application/json" \
        -H "X-Hasura-Admin-Secret: $ADMIN_SECRET" \
        -d '{"query":"{ oplog(limit:1, order_by:{id:asc}) { id name } }"}' 2>/dev/null || true)"
    OPLOG_ID="$(printf '%s' "$RESP" | python3 -c \
        'import sys,json;
try:
 d=json.load(sys.stdin); o=d.get("data",{}).get("oplog",[]); print(o[0]["id"] if o else "")
except Exception: print("")' 2>/dev/null || true)"
    [ -n "$OPLOG_ID" ] && ok "found Oplog id=$OPLOG_ID" \
        || warn "no Oplog yet — create one in the UI (a Project's Oplog), then set GHOSTWRITER_OPLOG_ID"
fi

# ── Upsert Praetor .env (idempotent: drop old GHOSTWRITER_* then append) ──
info "Wiring Praetor .env -> $ENV_FILE"
touch "$ENV_FILE"
grep -v '^GHOSTWRITER_' "$ENV_FILE" > "$ENV_FILE.tmp" 2>/dev/null || true
mv "$ENV_FILE.tmp" "$ENV_FILE"
{
    echo "GHOSTWRITER_URL=$GW_HOST"
    [ -n "$ADMIN_SECRET" ] && echo "GHOSTWRITER_ADMIN_SECRET=$ADMIN_SECRET"
    echo "GHOSTWRITER_INSECURE_TLS=1"
    [ -n "$OPLOG_ID" ] && echo "GHOSTWRITER_OPLOG_ID=$OPLOG_ID"
} >> "$ENV_FILE"
chmod 600 "$ENV_FILE" 2>/dev/null || true
ok ".env updated (secret written to file, not shown here)"

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo "  Ghostwriter ready"
echo "════════════════════════════════════════════════════"
echo "  URL:        $GW_HOST   (self-signed cert — accept the browser warning)"
echo "  Login user: admin"
echo "  Password:   run ->  (cd $GW_DIR && ./ghostwriter-cli-linux config get ADMIN_PASSWORD)"
if [ -z "$OPLOG_ID" ]; then
    echo ""
    echo "  Next: create a Project + its Oplog in the UI, then:"
    echo "        echo 'GHOSTWRITER_OPLOG_ID=<id>' >> $ENV_FILE"
fi
echo ""
echo "  Verify from Praetor:  ghostwriter_status   then   sync_to_ghostwriter('<domain>')"
echo "  (First sync may need column-name tweaks for your Ghostwriter version.)"
