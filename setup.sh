#!/usr/bin/env bash
# Burp Suite Swiss Knife MCP — Setup Script
# Installs all required and optional dependencies for Linux and macOS.
# Usage: chmod +x setup.sh && ./setup.sh

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[-]${NC} $1"; }

# ── Detect OS ───────────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
    Linux*)  PLATFORM="linux";;
    Darwin*) PLATFORM="macos";;
    *)       fail "Unsupported OS: $OS"; exit 1;;
esac
info "Detected platform: $PLATFORM"

# ── Helper: check if command exists ─────────────────────────────────
has() { command -v "$1" &>/dev/null; }

# ── Helper: install package via system package manager ──────────────
pkg_install() {
    if [ "$PLATFORM" = "linux" ]; then
        if has apt-get; then
            sudo apt-get install -y "$@"
        elif has dnf; then
            sudo dnf install -y "$@"
        elif has pacman; then
            sudo pacman -S --noconfirm "$@"
        else
            fail "No supported package manager found (apt/dnf/pacman)"
            return 1
        fi
    elif [ "$PLATFORM" = "macos" ]; then
        if has brew; then
            brew install "$@"
        else
            fail "Homebrew not found. Install: https://brew.sh"
            return 1
        fi
    fi
}

# ════════════════════════════════════════════════════════════════════
# PHASE 1: Required Dependencies
# ════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════"
echo "  Phase 1: Required Dependencies"
echo "════════════════════════════════════════════════════"

# ── Java 21+ ────────────────────────────────────────────────────────
info "Checking Java..."

detect_java() {
    # Returns the path to a java binary, or empty string if none found.
    if has java; then
        command -v java
        return
    fi
    if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
        echo "$JAVA_HOME/bin/java"
        return
    fi
    echo ""
}

parse_java_major() {
    # Parse the major version from `<java> -version` output (both old "1.8" and new "21" styles).
    local java_bin="$1"
    "$java_bin" -version 2>&1 | awk -F'"' '
        /version/ {
            split($2, v, ".")
            if (v[1] == "1") print v[2]; else print v[1]
            exit
        }
    '
}

JAVA_BIN="$(detect_java)"
if [ -n "$JAVA_BIN" ]; then
    JAVA_VER="$(parse_java_major "$JAVA_BIN" 2>/dev/null || echo 0)"
    if [ -n "$JAVA_VER" ] && [ "$JAVA_VER" -ge 21 ] 2>/dev/null; then
        ok "Java $JAVA_VER found at $JAVA_BIN"
    else
        warn "Java found at $JAVA_BIN but version=${JAVA_VER:-unknown} < 21"
        warn "Install Java 21+: https://adoptium.net/temurin/releases/?version=21"
    fi
else
    warn "Java not found (checked PATH and JAVA_HOME)"
    info "Installing Java 21..."
    if [ "$PLATFORM" = "linux" ]; then
        if has apt-get; then
            sudo apt-get install -y openjdk-21-jdk
        elif has dnf; then
            sudo dnf install -y java-21-openjdk-devel
        elif has pacman; then
            sudo pacman -S --noconfirm jdk21-openjdk
        fi
    elif [ "$PLATFORM" = "macos" ]; then
        pkg_install openjdk@21
    fi
    if has java; then
        ok "Java installed"
    else
        fail "Java installation failed — install manually: https://adoptium.net/temurin/releases/?version=21"
    fi
fi

# ── Maven ───────────────────────────────────────────────────────────
info "Checking Maven..."
if has mvn; then
    ok "Maven found: $(mvn --version 2>&1 | head -1)"
else
    info "Installing Maven..."
    pkg_install maven
    has mvn && ok "Maven installed" || fail "Maven installation failed"
fi

# ── Python 3.11+ ────────────────────────────────────────────────────
info "Checking Python..."
if has python3; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
    if [ "$PY_MINOR" -ge 11 ] 2>/dev/null; then
        ok "Python $PY_VER found"
    else
        warn "Python $PY_VER found but < 3.11 required"
    fi
else
    warn "Python3 not found"
    info "Installing Python..."
    if [ "$PLATFORM" = "linux" ]; then
        pkg_install python3 python3-venv python3-pip
    elif [ "$PLATFORM" = "macos" ]; then
        pkg_install python@3.13
    fi
fi

# ── uv (Python package manager) ────────────────────────────────────
info "Checking uv..."
if has uv; then
    ok "uv found: $(uv --version 2>&1)"
else
    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Add to current session PATH
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    has uv && ok "uv installed" || fail "uv installation failed — see https://docs.astral.sh/uv/"
fi

# ── Go (for ProjectDiscovery tools) ────────────────────────────────
info "Checking Go..."
if has go; then
    ok "Go found: $(go version)"
else
    info "Installing Go..."
    if [ "$PLATFORM" = "linux" ]; then
        GO_VERSION="1.24.4"
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64)  GO_ARCH="amd64";;
            aarch64) GO_ARCH="arm64";;
            *)       GO_ARCH="amd64";;
        esac
        curl -LO "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        rm -f "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
    elif [ "$PLATFORM" = "macos" ]; then
        pkg_install go
    fi
    has go && ok "Go installed: $(go version)" || fail "Go installation failed — see https://go.dev/dl/"
fi

# Ensure Go bin is in PATH
export PATH="$HOME/go/bin:$PATH"

# ════════════════════════════════════════════════════════════════════
# PHASE 2: Build the Project
# ════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════"
echo "  Phase 2: Build the Project"
echo "════════════════════════════════════════════════════"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Build Java extension ────────────────────────────────────────────
info "Building Burp extension..."
cd "$SCRIPT_DIR/burp-extension"
if mvn package -q; then
    JAR="target/burpsuite-swiss-knife-0.3.0.jar"
    if [ -f "$JAR" ]; then
        ok "Extension built: $JAR"
    else
        fail "JAR not found at $JAR"
    fi
else
    fail "Maven build failed"
fi

# ── Install Python MCP server ──────────────────────────────────────
info "Setting up Python MCP server..."
cd "$SCRIPT_DIR/mcp-server"
uv venv 2>/dev/null || true
uv pip install -e . 2>&1 | tail -1
ok "MCP server installed"

# Verify it loads
TOOL_COUNT=$(uv run python -c "from burpsuite_mcp.server import mcp; print(len(mcp._tool_manager._tools))" 2>/dev/null || echo "0")
if [ "$TOOL_COUNT" -gt 0 ]; then
    ok "MCP server verified: $TOOL_COUNT tools loaded"
else
    fail "MCP server failed to load"
fi

# ════════════════════════════════════════════════════════════════════
# PHASE 3: Optional — ProjectDiscovery Recon Tools
# ════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════"
echo "  Phase 3: Recon Tools (optional)"
echo "════════════════════════════════════════════════════"
info "These tools enhance reconnaissance. They are NOT required."
echo ""

install_pd_tool() {
    local name="$1"
    local install_cmd="$2"
    if has "$name"; then
        ok "$name already installed"
    else
        info "Installing $name..."
        if eval "$install_cmd" 2>&1 | tail -1; then
            has "$name" && ok "$name installed" || warn "$name: install completed but binary not in PATH"
        else
            warn "$name installation failed (optional — skipping)"
        fi
    fi
}

install_pd_tool "subfinder" \
    "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

install_pd_tool "httpx" \
    "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"

install_pd_tool "nuclei" \
    "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

install_pd_tool "katana" \
    "CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest"

install_pd_tool "dalfox" \
    "go install -v github.com/hahwul/dalfox/v2@latest"

install_pd_tool "gau" \
    "go install -v github.com/lc/gau/v2/cmd/gau@latest"

install_pd_tool "waybackurls" \
    "go install -v github.com/tomnomnom/waybackurls@latest"

# ════════════════════════════════════════════════════════════════════
# PHASE 4: Generate .mcp.json
# ════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════"
echo "  Phase 4: Claude Code Configuration"
echo "════════════════════════════════════════════════════"

cd "$SCRIPT_DIR"
MCP_JSON="$SCRIPT_DIR/.mcp.json"
VENV_PYTHON="$SCRIPT_DIR/mcp-server/.venv/bin/python"

if [ ! -f "$MCP_JSON" ]; then
    info "Generating .mcp.json..."
    cat > "$MCP_JSON" << MCPEOF
{
  "mcpServers": {
    "burpsuite": {
      "command": "$VENV_PYTHON",
      "args": ["-m", "burpsuite_mcp"]
    }
  }
}
MCPEOF
    ok "Created $MCP_JSON"
else
    ok ".mcp.json already exists — skipping"
fi

# ════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════"
echo "  Setup Complete"
echo "════════════════════════════════════════════════════"
echo ""

# Check all components
check() {
    if has "$1"; then
        echo -e "  ${GREEN}✓${NC} $1"
    else
        echo -e "  ${RED}✗${NC} $1 (not found)"
    fi
}

echo "Required:"
check java
check mvn
check python3
check uv
check go

echo ""
echo "Optional (recon):"
check subfinder
check httpx
check nuclei
check katana
check ffuf
check nmap
check sqlmap

echo ""
echo "Project:"
JAR_PATH="$SCRIPT_DIR/burp-extension/target/burpsuite-swiss-knife-0.3.0.jar"
if [ -f "$JAR_PATH" ]; then
    echo -e "  ${GREEN}✓${NC} Burp extension JAR built"
else
    echo -e "  ${RED}✗${NC} Burp extension JAR not found"
fi

if [ -f "$VENV_PYTHON" ]; then
    echo -e "  ${GREEN}✓${NC} Python venv ready"
else
    echo -e "  ${RED}✗${NC} Python venv not found"
fi

if [ -f "$MCP_JSON" ]; then
    echo -e "  ${GREEN}✓${NC} .mcp.json configured"
else
    echo -e "  ${RED}✗${NC} .mcp.json not found"
fi

echo ""
echo "Next steps:"
echo "  1. Open Burp Suite"
echo "  2. Extensions → Add → Java → Select: $JAR_PATH"
echo "  3. Verify: 'Swiss Knife MCP started on port 8111' in Burp output"
echo "  4. Start Claude Code in this directory"
echo ""
