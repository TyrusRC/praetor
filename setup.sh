#!/usr/bin/env bash
# Praetor — Setup Script
# Installs all dependencies (web + network lanes) for Linux and macOS.
# Usage: chmod +x setup.sh && ./setup.sh
#
# Coverage policy (2026-05-22):
#   The KB ships 122 probe catalogs mapped to OWASP Top 10 (Web/API/LLM/Mobile),
#   WSTG, PayloadsAllTheThings, HackTricks Web + Cloud. Cloud coverage is
#   ANONYMOUS-EXTERNAL ONLY (anonymous list / public Function URL / exposed
#   K8s endpoint) — no provider-credential-based tooling (e.g. Pacu, ScoutSuite,
#   Prowler) is installed here, by design. Operators who need cred-based cloud
#   privesc testing install those separately, out-of-band, with their own
#   engagement-specific credentials.

set -euo pipefail

# Newest built extension jar, or "" when unbuilt. Version-agnostic, so a bump in
# pom.xml never makes this report "not built".
#
# Pure glob on purpose. The previous `ls -t | grep -v | head -1` returned nothing
# on any host where `grep` is a wrapper (ugrep, ripgrep shims), reporting a
# perfectly good build as missing. No external command, nothing to shim.
resolve_jar() {
    local newest="" f
    for f in "$1"/burp-extension/target/praetor-burp-ext-*.jar; do
        [ -f "$f" ] || continue
        case "$f" in *-sources.jar|*-javadoc.jar) continue ;; esac
        if [ -z "$newest" ] || [ "$f" -nt "$newest" ]; then
            newest="$f"
        fi
    done
    printf '%s' "$newest"
}

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
# Delegate to build.sh: it resolves the artifact from the POM (a version bump
# must not make setup report a failed build) and prints the absolute jar path.
info "Building Burp extension..."
cd "$SCRIPT_DIR/burp-extension"
if "$SCRIPT_DIR/build.sh" --skip-tests >/dev/null 2>&1; then
    JAR="$(resolve_jar "$SCRIPT_DIR")"
    if [ -n "$JAR" ] && [ -f "$JAR" ]; then
        ok "Extension built: $JAR"
    else
        fail "build reported success but no jar under burp-extension/target/"
    fi
else
    fail "Maven build failed — re-run ./build.sh to see the compiler output"
fi

# ── Install Python MCP server ──────────────────────────────────────
info "Setting up Python MCP server..."
cd "$SCRIPT_DIR/mcp-server"
uv venv 2>/dev/null || true
uv pip install -e . 2>&1 | tail -1
ok "MCP server installed"

# Verify it loads
TOOL_COUNT=$(uv run python -c "from praetor.server import mcp; print(len(mcp._tool_manager._tools))" 2>/dev/null || echo "0")
if [ "$TOOL_COUNT" -gt 0 ]; then
    ok "MCP server verified: $TOOL_COUNT tools loaded"
else
    fail "MCP server failed to load"
fi

# CloakBrowser stealth Chromium for browser_* tools (browser_crawl, browser_navigate, ...)
# First import auto-downloads the patched binary (~200MB, cached). Pre-warm it
# now so the first MCP call doesn't pay that latency.
info "Warming CloakBrowser stealth Chromium (first run downloads ~200MB)..."
if uv run python -c "import cloakbrowser" >/dev/null 2>&1; then
    ok "CloakBrowser ready"
else
    warn "CloakBrowser warm-up failed — browser_* tools will trigger the download on first call instead"
fi

# ════════════════════════════════════════════════════════════════════
# PHASE 3: Recon Tools (core — web lane)
# ════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════"
echo "  Phase 3: Recon Tools (core — web lane)"
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
            warn "$name installation failed — core tool; install manually"
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

install_pd_tool "ffuf" \
    "go install -v github.com/ffuf/ffuf/v2@latest"

install_pd_tool "amass" \
    "go install -v github.com/owasp-amass/amass/v4/cmd/amass@master"

# Python CLI tools — installed via `uv tool install` (isolated venv per tool,
# same UX as pipx). Project standardizes on uv; never pip.
install_pd_tool "wafw00f" \
    "uv tool install wafw00f"

install_pd_tool "arjun" \
    "uv tool install arjun"

install_pd_tool "sqlmap" \
    "uv tool install sqlmap"

install_pd_tool "commix" \
    "uv tool install commix"

# nikto — web server scanner (backs run_nikto)
if has nikto; then
    ok "nikto already installed"
else
    info "Installing nikto..."
    pkg_install nikto || warn "nikto install failed — install manually"
fi

# wpscan (WordPress — Ruby gem)
if has wpscan; then
    ok "wpscan already installed"
else
    if has gem; then
        info "Installing wpscan..."
        gem install --user-install wpscan 2>&1 | tail -1 || warn "wpscan install failed — install manually"
    else
        warn "wpscan not found and no Ruby gem available — install via: gem install wpscan"
    fi
fi

# ── Praetor v1.0 SAST + secrets layer ──
echo ""
info "Praetor v1.0 — installing SAST + secrets layer (core)..."

install_pd_tool "opengrep" \
    "curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash"

install_pd_tool "gitleaks" \
    "go install -v github.com/gitleaks/gitleaks/v8@latest"

install_pd_tool "trufflehog" \
    "go install -v github.com/trufflesecurity/trufflehog/v3@latest"

# git-dumper — Python CLI, install via uv tool
install_pd_tool "git-dumper" \
    "uv tool install git-dumper"

# OWASP Noir — Crystal binary. brew tap exists for macOS; Linux build from source.
# We surface a hint only; binary distribution is platform-specific.
if has noir; then
    ok "noir already installed"
else
    warn "noir not installed — operator install: https://github.com/owasp-noir/noir (brew tap noir-cr/noir/noir on macOS)"
fi

# dig — DNS lookups used across recon (dnsutils / bind-tools)
if has dig; then
    ok "dig already installed"
elif [ "$PLATFORM" = "linux" ]; then
    pkg_install dnsutils || pkg_install bind-tools || warn "dig not installed — install dnsutils/bind-tools manually"
elif [ "$PLATFORM" = "macos" ]; then
    pkg_install bind || warn "dig not installed — brew install bind"
fi

# ── ProjectDiscovery expansion — recon_pd tools (run_dnsx / run_naabu / ...) ──
echo ""
info "ProjectDiscovery expansion (DNS / ports / TLS / ASN / OSINT recon)..."
install_pd_tool "dnsx"      "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_pd_tool "naabu"     "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_pd_tool "tlsx"      "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
install_pd_tool "asnmap"    "go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
install_pd_tool "uncover"   "go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest"
install_pd_tool "cloudlist" "go install -v github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest"
install_pd_tool "notify"    "go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
install_pd_tool "mapcves"   "go install -v github.com/projectdiscovery/mapcves@latest"
install_pd_tool "cdncheck"  "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
install_pd_tool "alterx"    "go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest"
install_pd_tool "shuffledns" "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
install_pd_tool "chaos"     "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
install_pd_tool "graphw00f" "uv tool install graphw00f"
install_pd_tool "dnsgen"    "uv tool install dnsgen"

# ── 40x / 403 bypass (run_dontgo403 / run_byp4xx) ──
echo ""
info "40x access-control bypass tools..."
install_pd_tool "dontgo403" "go install -v github.com/devploit/dontgo403@latest"
install_pd_tool "byp4xx"    "go install -v github.com/lobuhi/byp4xx@latest"

# ── SCA / containers / SBOM (run_osv_scanner / run_trivy / run_grype / run_syft / run_cosign_verify) ──
echo ""
info "SCA + container + SBOM tools..."
install_pd_tool "osv-scanner" "go install -v github.com/google/osv-scanner/cmd/osv-scanner@v2"
install_pd_tool "cosign"    "go install -v github.com/sigstore/cosign/v2/cmd/cosign@latest"
install_pd_tool "trivy"     "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b \"$HOME/go/bin\""
install_pd_tool "grype"     "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b \"$HOME/go/bin\""
install_pd_tool "syft"      "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b \"$HOME/go/bin\""

# ── LLM / MCP security (run_garak / run_mcp_scan) ──
echo ""
info "LLM + MCP security tools..."
install_pd_tool "garak"     "uv tool install garak"
install_pd_tool "mcp-scan"  "uv tool install mcp-scan"

# ── HTTP request smuggling (run_smuggle) ──
install_pd_tool "smuggle"   "uv tool install smuggle"

# ── Kubernetes (run_kubescape / run_kube_hunter / run_peirates / run_kdigger / run_kubeletctl) ──
echo ""
info "Kubernetes audit + attack tools..."
install_pd_tool "peirates"   "go install -v github.com/inguardians/peirates@latest"
install_pd_tool "kubeletctl" "go install -v github.com/cyberark/kubeletctl/cmd/kubeletctl@latest"
install_pd_tool "kube-hunter" "uv tool install kube-hunter"
install_pd_tool "kubescape"  "curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash"
if has kdigger; then
    ok "kdigger already installed"
else
    warn "kdigger not installed — operator install: release binary from https://github.com/quarkslab/kdigger/releases (brew: mtardy/tap/kdigger)"
fi

# ── Cloud posture (run_prowler / run_scout_suite / run_cloudsploit / run_pacu) ──
echo ""
info "Cloud posture tools..."
install_pd_tool "prowler"   "uv tool install prowler"
install_pd_tool "scout"     "uv tool install scoutsuite"
install_pd_tool "pacu"      "uv tool install pacu"
if has cloudsploit; then
    ok "cloudsploit already installed"
elif has npm; then
    info "Installing cloudsploit (npm)..."
    npm i -g cloudsploit 2>&1 | tail -1 || warn "cloudsploit install failed — install manually: npm i -g cloudsploit"
else
    warn "cloudsploit not installed — needs npm: npm i -g cloudsploit"
fi

# ── IaC / CI (run_checkov / run_tfsec / run_terrascan / run_hadolint / run_poutine / run_octoscan) ──
echo ""
info "IaC + CI/CD audit tools..."
install_pd_tool "checkov"   "uv tool install checkov"
install_pd_tool "tfsec"     "go install -v github.com/aquasecurity/tfsec/cmd/tfsec@latest"
install_pd_tool "terrascan" "go install -v github.com/tenable/terrascan/cmd/terrascan@latest"
install_pd_tool "poutine"   "go install -v github.com/boostsecurityio/poutine@latest"
install_pd_tool "octoscan"  "go install -v github.com/synacktiv/octoscan@latest"
if has hadolint; then
    ok "hadolint already installed"
else
    warn "hadolint not installed — operator install: release binary from https://github.com/hadolint/hadolint/releases (brew install hadolint)"
fi

# ── Visual EASM (visual_easm_diff) ──
install_pd_tool "gowitness"  "go install -v github.com/sensepost/gowitness@latest"

# ════════════════════════════════════════════════════════════════════
# Red-team / network lane (core) — powers run_nmap + run_network_recon
# ════════════════════════════════════════════════════════════════════
echo ""
info "Red-team / network lane tools (core — run_nmap / run_network_recon / run_network_tool)..."

IS_KALI=0
if grep -qiE 'kali|parrot' /etc/os-release 2>/dev/null; then IS_KALI=1; fi

# Most of these ship in the Kali/Parrot repos under one apt bundle. On other
# distros install what the package manager has and print a hint for the rest.
RT_APT_PKGS="nmap netexec impacket-scripts responder john hashcat gobuster \
feroxbuster smbmap enum4linux-ng ldapdomaindump certipy-ad kerbrute evil-winrm \
bloodhound.py sshuttle seclists"

if [ "$IS_KALI" -eq 1 ]; then
    info "Kali/Parrot detected — installing the red-team bundle via apt..."
    sudo apt-get install -y $RT_APT_PKGS 2>&1 | tail -2 \
        || warn "some red-team apt packages failed — core; install individually"
elif has apt-get; then
    info "Debian/Ubuntu — installing what the repos carry..."
    sudo apt-get install -y nmap john hashcat gobuster feroxbuster smbmap sshuttle 2>&1 | tail -2 \
        || warn "some apt packages failed — install manually"
    # Python-side red-team tools via uv (isolated per-tool venv).
    install_pd_tool "nxc"        "uv tool install git+https://github.com/Pennyw0rth/NetExec"
    install_pd_tool "impacket-secretsdump" "uv tool install impacket"
    install_pd_tool "certipy"    "uv tool install certipy-ad"
    install_pd_tool "bloodhound-python" "uv tool install bloodhound"
    install_pd_tool "kerbrute"   "go install github.com/ropnop/kerbrute@latest"
else
    warn "Non-apt host — install red-team tools manually. redteam_tool_guide(tool='<name>')"
    warn "  in Praetor prints the apt/clone/go command for each."
fi

# SecLists: apt on Kali; otherwise clone to /opt/SecLists (detect_seclists finds both).
if [ -d /usr/share/seclists ] || [ -d /usr/share/SecLists ] || [ -d /opt/SecLists ]; then
    ok "SecLists present"
elif [ "$IS_KALI" -eq 0 ]; then
    info "Cloning SecLists to /opt/SecLists (large; shallow clone)..."
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists 2>&1 | tail -1 \
        || warn "SecLists clone failed — clone manually to /opt/SecLists"
fi

# ════════════════════════════════════════════════════════════════════
# Mobile lane — powers mobile_* device-control tools (Android + iOS)
# ════════════════════════════════════════════════════════════════════
echo ""
info "Mobile lane tools (adb / frida / iOS-on-Linux via go-ios+libimobiledevice)..."

# Android: adb
if has adb; then ok "adb already installed"
elif [ "$PLATFORM" = "linux" ]; then
    pkg_install android-tools-adb || pkg_install adb || warn "adb not installed — install platform-tools manually"
elif [ "$PLATFORM" = "macos" ]; then
    pkg_install android-platform-tools || warn "adb not installed — brew install android-platform-tools"
fi

# Frida (SSL-pin/root bypass, hooks) — isolated uv tool venv
install_pd_tool "frida" "uv tool install frida-tools"
# NOTE: this installs the host-side frida-tools CLI only. The on-device
# frida-server binary (rooted Android target) is a runtime artifact the
# operator pushes per-engagement, matched to this frida-tools version and the
# device arch — not installed here. Push it over wireless adb, not USB/usbip:
# usbip resets mid-transfer on a 50MB+ binary (see phone-control.md).

# iOS-on-Linux stack (Mac-free): usbmuxd + libimobiledevice + ideviceinstaller + go-ios.
# libusbmuxd-tools (iproxy) + sshpass power the jailbroken-iOS SSH-over-USB path:
#   iproxy 2222 22 <udid>  ->  ssh mobile@127.0.0.1 -p 2222  (frida/objection on the device)
if [ "$PLATFORM" = "linux" ]; then
    pkg_install usbmuxd libimobiledevice-utils ideviceinstaller libusbmuxd-tools sshpass || \
        warn "iOS libs not fully installed — apt install usbmuxd libimobiledevice-utils ideviceinstaller libusbmuxd-tools sshpass"
elif [ "$PLATFORM" = "macos" ]; then
    pkg_install libimobiledevice ideviceinstaller libusbmuxd || warn "brew install libimobiledevice ideviceinstaller libusbmuxd"
    has sshpass || warn "sshpass not installed — brew install hudochenkov/sshpass/sshpass (jailbroken-iOS SSH)"
fi
# go-ios (cross-platform iOS control — the idb replacement)
install_pd_tool "ios" "go install github.com/danielpaulus/go-ios@latest && ln -sf \"$HOME/go/bin/go-ios\" \"$HOME/go/bin/ios\""

# USB passthrough for WSL (phone plugged into Windows)
if grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
    info "WSL detected — USB devices need usbipd-win passthrough:"
    warn "  Windows (admin PowerShell): usbipd bind --busid <id> ; usbipd attach --wsl --busid <id>"
    warn "  WSL: sudo modprobe vhci_hcd  (kernel module ships with the WSL kernel)"
    warn "  usbip resets Android devices on large pushes (frida-server, APKs) —"
    warn "  pair once over USB then switch to wireless adb (mobile_connect tcpip/connect)."
    pkg_install usbip || warn "usbip client not installed — apt install usbip (linux-tools) for passthrough"
fi

# ════════════════════════════════════════════════════════════════════
# Ghostwriter (core reporting/oplog hub) — auto-setup
# ════════════════════════════════════════════════════════════════════
echo ""
if [ "${PRAETOR_SKIP_GHOSTWRITER:-0}" = "1" ]; then
    info "Skipping Ghostwriter (PRAETOR_SKIP_GHOSTWRITER=1)."
elif has docker && docker info >/dev/null 2>&1; then
    info "Ghostwriter (central reporting/oplog hub) — running auto-setup..."
    info "  Heavy Docker install (GBs, binds 443). Skip with PRAETOR_SKIP_GHOSTWRITER=1."
    # Non-fatal: a Ghostwriter hiccup must not abort the rest of setup.
    "$SCRIPT_DIR/setup-ghostwriter.sh" || warn "Ghostwriter auto-setup did not finish — run ./setup-ghostwriter.sh manually."
else
    warn "Docker not available — skipping Ghostwriter. Install Docker, then run ./setup-ghostwriter.sh"
fi

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

# ── WSL detection ───────────────────────────────────────────────────
# When the MCP server runs in WSL but Burp runs on the Windows host, the
# extension API is not on WSL's 127.0.0.1. Two supported modes:
#   mirrored — Windows 127.0.0.1 is reachable from WSL as 127.0.0.1
#              (secure, recommended; no env override, no bind change).
#   NAT      — reach Burp via the Windows host IP (the WSL default-route
#              gateway); the extension must bind off-loopback.
IS_WSL=0
WSL_MODE=""
WSL_HOST_IP=""
if grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null || [ -n "${WSL_DISTRO_NAME:-}" ]; then
    IS_WSL=1
    if has wslinfo; then
        WSL_MODE="$(wslinfo --networking-mode 2>/dev/null || true)"
    fi
    if [ -z "$WSL_MODE" ]; then
        # wslinfo unavailable — infer from loopback reachability. In mirrored
        # mode the default route is the LAN gateway, NOT the Windows host, so
        # deriving BURP_API_HOST from it would be wrong. If Burp already answers
        # on loopback we're effectively connected (mirrored), so leave the host
        # at the default; otherwise assume NAT.
        if curl -s -m 2 -o /dev/null "http://127.0.0.1:${BURP_API_PORT:-8111}/api/health" 2>/dev/null; then
            WSL_MODE="mirrored"
        else
            WSL_MODE="nat"
        fi
    fi
    if [ "$WSL_MODE" != "mirrored" ]; then
        # NAT — Windows host is the WSL default-route gateway.
        WSL_HOST_IP="$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')"
    fi
    info "WSL detected (networking mode: ${WSL_MODE:-unknown})"
fi

if [ ! -f "$MCP_JSON" ]; then
    info "Generating .mcp.json..."
    if [ "$IS_WSL" = "1" ] && [ "$WSL_MODE" = "nat" ] && [ -n "$WSL_HOST_IP" ]; then
        cat > "$MCP_JSON" << MCPEOF
{
  "mcpServers": {
    "praetor": {
      "command": "$VENV_PYTHON",
      "args": ["-m", "praetor"],
      "env": {
        "BURP_API_HOST": "$WSL_HOST_IP"
      }
    }
  }
}
MCPEOF
        ok "Created $MCP_JSON (WSL NAT → BURP_API_HOST=$WSL_HOST_IP)"
    else
        cat > "$MCP_JSON" << MCPEOF
{
  "mcpServers": {
    "praetor": {
      "command": "$VENV_PYTHON",
      "args": ["-m", "praetor"]
    }
  }
}
MCPEOF
        ok "Created $MCP_JSON"
    fi
else
    ok ".mcp.json already exists — keeping"
    if [ "$IS_WSL" = "1" ] && [ "$WSL_MODE" = "nat" ] && [ -n "$WSL_HOST_IP" ]; then
        warn "WSL NAT: .mcp.json must set env BURP_API_HOST=$WSL_HOST_IP (Windows host) — or switch to mirrored networking (see 'WSL → Windows Burp' below)"
    fi
fi

# Ensure Claude Code is allowed to start the praetor server: drop it from any
# disabledMcpjsonServers list and add it to enabledMcpjsonServers. Without this,
# a project MCP server can sit disabled and never connect.
SETTINGS_LOCAL="$SCRIPT_DIR/.claude/settings.local.json"
mkdir -p "$SCRIPT_DIR/.claude"
python3 - "$SETTINGS_LOCAL" <<'PYEOF'
import json, os, sys
p = sys.argv[1]
try:
    d = json.load(open(p)) if os.path.exists(p) else {}
except Exception:
    d = {}
d["disabledMcpjsonServers"] = [s for s in d.get("disabledMcpjsonServers", []) if s != "praetor"]
if "praetor" not in d.get("enabledMcpjsonServers", []):
    d["enabledMcpjsonServers"] = d.get("enabledMcpjsonServers", []) + ["praetor"]
json.dump(d, open(p, "w"), indent=2)
PYEOF
ok "praetor MCP server enabled in .claude/settings.local.json"

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
echo "Core web / recon tools:"
check subfinder
check httpx
check nuclei
check katana
check ffuf
check dalfox
check amass
check wafw00f
check arjun
check sqlmap
check commix
check nikto
check wpscan

echo ""
echo "Extended coverage (cloud / k8s / SCA / IaC / CI / LLM / PD-extras):"
check dnsx
check naabu
check gowitness
check osv-scanner
check trivy
check grype
check syft
check garak
check mcp-scan
check prowler
check checkov
check kubescape
echo "  (run ./doctor.sh for the full per-tool inventory)"

echo ""
echo "Core red-team / network lane:"
check nmap
check nxc
check impacket-secretsdump
check responder
check bloodhound-python
check certipy
check kerbrute
check hashcat
check john
if [ -d /usr/share/seclists ] || [ -d /usr/share/SecLists ] || [ -d /opt/SecLists ]; then
    echo -e "  ${GREEN}✓${NC} seclists"
else
    echo -e "  ${YELLOW}○${NC} seclists (sudo apt install seclists / git clone SecLists)"
fi

echo ""
echo "Project:"
JAR_PATH="$(resolve_jar "$SCRIPT_DIR")"
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
echo "  3. Verify: 'Praetor MCP started on port 8111' in Burp output"
echo "  4. Start Claude Code in this directory"
echo ""
echo "The extension tab defaults to Host 127.0.0.1 / Port 8111 — same as the MCP"
echo "server default — so on a single host it auto-connects with no config. Edit the"
echo "tab's Host/Port only for a custom port or a cross-host bind (see WSL below)."
echo ""

if [ "$IS_WSL" = "1" ]; then
    echo "WSL → Windows Burp:"
    if [ "$WSL_MODE" = "mirrored" ]; then
        echo -e "  ${GREEN}✓${NC} Mirrored networking active — Burp on Windows 127.0.0.1:8111 is reachable directly."
        echo "    Keep the Praetor tab Host at 127.0.0.1 (no bind flag, no env override)."
        echo "    Verify (with Burp running):  curl -s http://127.0.0.1:8111/api/health"
    else
        echo "  NAT mode — pick one:"
        echo "    RECOMMENDED (secure): enable mirrored networking, then re-run this script —"
        echo "      • add to C:\\Users\\<you>\\.wslconfig :   [wsl2]  networkingMode=mirrored"
        echo "      • PowerShell:  wsl --shutdown   (restarts WSL)"
        echo "      • Burp stays on 127.0.0.1; drop the BURP_API_HOST env block from .mcp.json."
        echo "    OR (NAT — exposes the API on the WSL vSwitch, trusted host only):"
        echo "      • Praetor config tab → Host = 0.0.0.0"
        echo "      • launch Burp with JVM flag:  -Dpraetor.allow_non_loopback_bind=true"
        echo "      • keep  env BURP_API_HOST=${WSL_HOST_IP:-<windows-host-ip>}  in .mcp.json"
    fi
    echo ""
fi
