#!/usr/bin/env bash
# Burp Suite Swiss Knife MCP — Doctor
# Checks environment, build artifacts, Burp connection, and optional tools.
# Non-zero exit only when something critical is missing.
# Usage: ./doctor.sh

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Colors ──────────────────────────────────────────────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

# Counters
OK=0; WARN=0; FAIL=0

pass() { echo -e "  ${GREEN}[OK]${NC}   $1"; OK=$((OK+1)); }
skip() { echo -e "  ${YELLOW}[--]${NC}   $1 — $2"; WARN=$((WARN+1)); }
bad()  { echo -e "  ${RED}[XX]${NC}   $1 — $2"; FAIL=$((FAIL+1)); }
head() { echo; echo -e "${BOLD}$1${NC}"; }

# Detect platform
OS="$(uname -s)"
case "$OS" in
    Linux*)            PLATFORM="linux"   ;;
    Darwin*)           PLATFORM="macos"   ;;
    MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
    *)                 PLATFORM="unknown" ;;
esac

has() { command -v "$1" >/dev/null 2>&1; }

# TCP check — prefer bash /dev/tcp (no deps), fall back to nc, then a real python
tcp_open() {
    local host="$1" port="$2"
    # bash built-in, works on Linux/macOS/git-bash
    if timeout 2 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
        return 0
    fi
    if has nc && nc -z -w 2 "$host" "$port" >/dev/null 2>&1; then
        return 0
    fi
    # Last resort: a real python (skip the Windows-Store python3 stub)
    local py=""
    [ -n "${VENV_PY:-}" ] && py="$VENV_PY"
    [ -z "$py" ] && has python && py="python"
    if [ -n "$py" ]; then
        "$py" -c "import socket,sys;s=socket.socket();s.settimeout(2)
try: s.connect(('$host',$port)); s.close()
except: sys.exit(1)" 2>/dev/null
        return $?
    fi
    return 1
}

# HTTP GET returning status code (prints code or empty on failure)
http_status() {
    local url="$1"
    curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url" 2>/dev/null || echo ""
}

echo -e "${BOLD}Burp Suite Swiss Knife MCP — Doctor${NC}"
echo "Platform: $PLATFORM  |  Project: $SCRIPT_DIR"

# ════════════════════════════════════════════════════════════════════
head "Environment"
# ════════════════════════════════════════════════════════════════════

if has java; then
    ver=$(java -version 2>&1 | awk -F'"' '/version/ {print $2; exit}')
    major=$(echo "$ver" | awk -F'.' '{print $1}')
    if [ -n "$major" ] && [ "$major" -ge 21 ] 2>/dev/null; then
        pass "Java $ver"
    else
        bad "Java $ver" "need 21+"
    fi
else
    bad "java" "not on PATH — install JDK 21+"
fi

if has mvn; then
    mvn_ver=$(mvn -v 2>/dev/null | grep -iE '^apache maven' | head -1 | awk '{print $3}')
    pass "Maven ${mvn_ver:-(version unknown)}"
else
    skip "mvn" "optional (only needed to rebuild the extension)"
fi

if has uv; then
    pass "uv $(uv --version 2>&1 | awk '{print $2}')"
else
    bad "uv" "install from https://docs.astral.sh/uv/getting-started/installation/"
fi

# `python3` on Windows is often a Microsoft Store stub that prints
# "Python was not found; run without arguments...". Probe --version output
# for the string "Python " and reject anything else.
detect_python() {
    # The Windows Store stub also starts with "Python " ("Python was not
    # found..."), so require "Python <digit>" to reject it.
    local candidate ver
    for candidate in python3 python; do
        if has "$candidate"; then
            ver=$("$candidate" --version 2>&1)
            if [[ "$ver" =~ ^Python\ [0-9]+\.[0-9]+ ]]; then
                echo "$candidate ${ver#Python }"
                return 0
            fi
        fi
    done
    return 1
}
if py_info=$(detect_python); then
    pass "$py_info"
else
    skip "python on PATH" "venv at mcp-server/.venv/ is used directly — this is informational only"
fi

if has git; then
    pass "git $(git --version | awk '{print $3}')"
else
    skip "git" "optional but recommended"
fi

# ════════════════════════════════════════════════════════════════════
head "Build artifacts"
# ════════════════════════════════════════════════════════════════════

JAR="$SCRIPT_DIR/burp-extension/target/burpsuite-swiss-knife-0.3.0.jar"
if [ -f "$JAR" ]; then
    size_kb=$(($(wc -c < "$JAR") / 1024))
    pass "Extension JAR (${size_kb} KB)"
else
    bad "Extension JAR" "not built — cd burp-extension && mvn package"
fi

VENV="$SCRIPT_DIR/mcp-server/.venv"
VENV_PY=""
if [ -x "$VENV/Scripts/python.exe" ]; then
    VENV_PY="$VENV/Scripts/python.exe"
elif [ -x "$VENV/bin/python" ]; then
    VENV_PY="$VENV/bin/python"
fi
if [ -n "$VENV_PY" ]; then
    pass "Python venv at mcp-server/.venv"
    tool_count=$("$VENV_PY" -c "from burpsuite_mcp.server import mcp; print(len(mcp._tool_manager._tools))" 2>/dev/null || echo "0")
    if [ "${tool_count:-0}" -gt 0 ] 2>/dev/null; then
        pass "MCP server imports, $tool_count tools registered"
    else
        bad "MCP server import" "'uv pip install -e .' inside mcp-server/"
    fi
else
    bad "Python venv" "not created — cd mcp-server && uv venv && uv pip install -e ."
fi

# ════════════════════════════════════════════════════════════════════
head "Burp runtime"
# ════════════════════════════════════════════════════════════════════

# API (extension's HTTP server)
API_URL="http://127.0.0.1:8111/api/health"
code=$(http_status "$API_URL")
if [ "$code" = "200" ]; then
    info=$(curl -s --max-time 3 "$API_URL" 2>/dev/null)
    pass "Extension API reachable (${info:0:80})"
else
    bad "Extension API" "127.0.0.1:8111 unreachable (HTTP='$code') — is Burp running with the extension loaded?"
fi

# Proxy port
if tcp_open 127.0.0.1 8080; then
    pass "Burp proxy listening on 127.0.0.1:8080"
else
    bad "Burp proxy" "127.0.0.1:8080 not listening — external recon tools will fail"
fi

# ════════════════════════════════════════════════════════════════════
head "Browser tools (Playwright)"
# ════════════════════════════════════════════════════════════════════

user_name="${USER:-${USERNAME:-$(whoami 2>/dev/null)}}"
PW_DIRS=(
    "$HOME/.cache/ms-playwright"
    "$HOME/AppData/Local/ms-playwright"
    "$HOME/Library/Caches/ms-playwright"
    "/c/Users/${user_name}/AppData/Local/ms-playwright"
)
pw_found=""
for d in "${PW_DIRS[@]}"; do
    if [ -d "$d" ] && ls "$d" 2>/dev/null | grep -qE 'chromium'; then
        pw_found="$d"
        break
    fi
done
if [ -n "$pw_found" ]; then
    pass "Playwright Chromium installed ($pw_found)"
else
    skip "Playwright Chromium" "browser_crawl will fail — run: uv run python -m playwright install chromium"
fi

# ════════════════════════════════════════════════════════════════════
head "Recon tools (optional)"
# ════════════════════════════════════════════════════════════════════

check_recon() {
    local tool="$1" install_hint="$2"
    if has "$tool"; then
        pass "$tool"
    else
        skip "$tool" "$install_hint"
    fi
}

check_recon subfinder  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
check_recon nuclei     "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
check_recon katana     "go install github.com/projectdiscovery/katana/cmd/katana@latest"
check_recon ffuf       "go install github.com/ffuf/ffuf/v2@latest  (or: scoop install ffuf)"
check_recon dalfox     "go install github.com/hahwul/dalfox/v2@latest"
check_recon sqlmap     "pip install sqlmap  (or package manager)"
check_recon dig        "apt install dnsutils / brew install bind / scoop install dnsutils"

# ════════════════════════════════════════════════════════════════════
head "Project files"
# ════════════════════════════════════════════════════════════════════

if [ -f "$SCRIPT_DIR/.mcp.json" ]; then
    pass ".mcp.json present"
    # Sanity-check that .mcp.json points at a reachable interpreter
    if grep -q '/mnt/c/' "$SCRIPT_DIR/.mcp.json" 2>/dev/null && [ "$PLATFORM" = "windows" ]; then
        skip ".mcp.json uses /mnt/c/... WSL paths but platform is native Windows" "re-generate with Windows-style paths"
    fi
else
    skip ".mcp.json" "create from .mcp.json.example or re-run setup"
fi

for f in .claude/rules/hunting.md CLAUDE.md AGENTS.md; do
    if [ -f "$SCRIPT_DIR/$f" ]; then
        pass "$f"
    else
        skip "$f" "missing (not fatal, but skills/rules won't load)"
    fi
done

# ════════════════════════════════════════════════════════════════════
head "Summary"
# ════════════════════════════════════════════════════════════════════

echo "  OK: $OK   optional missing: $WARN   failures: $FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}Doctor found $FAIL critical problem(s). Fix the [XX] items above.${NC}"
    exit 1
fi
if [ "$WARN" -gt 0 ]; then
    echo -e "${YELLOW}Healthy. Optional items in [--] can be installed when needed.${NC}"
else
    echo -e "${GREEN}All clear.${NC}"
fi
exit 0
