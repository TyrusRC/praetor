#!/usr/bin/env bash
# Phase 1: Java/Maven/Python/uv/Go toolchain.
# Sourced by ../../setup.sh in order — do not run this file directly, it has
# no shebang-level set -e/colors/has() of its own; those come from lib.sh.

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
    curl -LsSf $DL_FLAGS https://astral.sh/uv/install.sh | sh
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
        curl -LO $DL_FLAGS "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
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

