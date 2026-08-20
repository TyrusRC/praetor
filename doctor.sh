#!/usr/bin/env bash
# Praetor — Doctor
# Checks environment, build artifacts, Burp connection, and all core tools.
# Non-zero exit only when something critical is missing.
# Usage: ./doctor.sh

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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

echo -e "${BOLD}Praetor — Doctor${NC}"
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

JAR="$(resolve_jar "$SCRIPT_DIR")"
if [ -f "$JAR" ]; then
    size_kb=$(($(wc -c < "$JAR") / 1024))
    pass "Extension JAR (${size_kb} KB)"
    # Built-jar version, used below to tell a stale LOADED extension from a
    # stale BUILT one. Derived from the filename so it survives a version bump.
    JAR_VERSION="$(basename "$JAR" .jar | sed 's/^praetor-burp-ext-//')"
else
    bad "Extension JAR" "not built — run ./build.sh"
fi

# The extension was renamed Swiss Knife -> Praetor. Rebuilding cannot fix a Burp
# that still points at a jar from before the rename: Burp keeps loading the old
# path, the old name shows in the Extensions tab, and the source looks innocent.
#
# Scoped to where a Burp extension jar actually lives — the repo tree and Burp's
# own directories. Scanning all of $HOME would be slow and would still miss a jar
# parked somewhere else, so the authoritative check is the loaded-extension
# identity under "Burp runtime" below; this only helps when Burp is not running.
STALE_JARS=""
for d in "$SCRIPT_DIR" "$HOME/BurpSuite" "$HOME/.BurpSuite" "$HOME/burp" "$HOME/Downloads"; do
    [ -d "$d" ] || continue
    found="$(find "$d" -maxdepth 4 -iname '*swiss*knife*.jar' -not -path '*/.git/*' 2>/dev/null || true)"
    [ -n "$found" ] && STALE_JARS="$STALE_JARS$found"$'\n'
done
if [ -n "${STALE_JARS// /}" ] && [ -n "$(printf '%s' "$STALE_JARS" | tr -d '[:space:]')" ]; then
    bad "Pre-rename jar on disk" \
        "$(printf '%s' "$STALE_JARS" | tr '\n' ' ')— remove that entry in Burp: Extensions -> Installed"
else
    pass "No pre-rename (Swiss Knife) jars in the repo or Burp directories"
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

    # Reachable is not the same as current. Burp answers on 8111 whichever build
    # is loaded, so a stale extension looks healthy while behaving like an old
    # release. Compare what actually answered against what is on disk.
    live_name="$(printf '%s' "$info" | sed -n 's/.*"extension"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    live_version="$(printf '%s' "$info" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"

    case "$live_name" in
        *Praetor*) pass "Loaded extension is Praetor (\"$live_name\")" ;;
        "")        skip "Loaded extension identity" "health response carried no 'extension' field — pre-rename build" ;;
        *)         bad  "Loaded extension is NOT Praetor" \
                        "Burp is running \"$live_name\". Remove it in Extensions -> Installed and add $JAR" ;;
    esac

    if [ -n "${JAR_VERSION:-}" ] && [ -n "$live_version" ] && [ "$JAR_VERSION" != "$live_version" ]; then
        bad "Loaded extension is stale" \
            "Burp is running v$live_version, the built jar is v$JAR_VERSION — untick/retick the entry in Extensions -> Installed to reload"
    elif [ -n "$live_version" ]; then
        pass "Loaded extension version matches the built jar (v$live_version)"
    fi
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
head "Browser tools (CloakBrowser)"
# ════════════════════════════════════════════════════════════════════

# CloakBrowser is the stealth Chromium fork used by browser_* tools. It
# vendors its patched binary and auto-downloads on first import (~200MB,
# cached). We check importability via the venv python rather than poking
# at cache directories — that survives upstream cache-path changes.
if [ -n "$VENV_PY" ]; then
    if "$VENV_PY" -c "import cloakbrowser" >/dev/null 2>&1; then
        pass "CloakBrowser importable"
    else
        bad "CloakBrowser" "not installed — cd mcp-server && uv pip install -e ."
    fi
else
    skip "CloakBrowser" "venv missing — cannot probe; install with uv pip install -e ."
fi

# ════════════════════════════════════════════════════════════════════
head "Recon tools (core — web lane)"
# ════════════════════════════════════════════════════════════════════

check_recon() {
    local tool="$1" install_hint="$2"
    if has "$tool"; then
        pass "$tool"
    else
        skip "$tool" "$install_hint"
    fi
}

check_recon subfinder  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
check_recon httpx      "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
check_recon nuclei     "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
check_recon katana     "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
check_recon ffuf       "go install -v github.com/ffuf/ffuf/v2@latest"
check_recon dalfox     "go install -v github.com/hahwul/dalfox/v2@latest"
check_recon amass      "go install -v github.com/owasp-amass/amass/v4/cmd/amass@master"
check_recon gau        "go install -v github.com/lc/gau/v2/cmd/gau@latest"
check_recon wafw00f    "uv tool install wafw00f"
check_recon arjun      "uv tool install arjun"
check_recon sqlmap     "uv tool install sqlmap"
check_recon commix     "uv tool install commix"
check_recon nikto      "sudo apt install nikto    # or: brew install nikto"
check_recon wpscan     "gem install wpscan        # requires Ruby"
check_recon dig        "sudo apt install dnsutils # or: brew install bind / scoop install dnsutils"

# ── SAST + secrets + Noir layer ──
check_recon opengrep   "brew install opengrep                              # or: curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash"
check_recon gitleaks   "brew install gitleaks                              # or: go install github.com/gitleaks/gitleaks/v8@latest"
check_recon trufflehog "brew install trufflehog                            # or: go install github.com/trufflesecurity/trufflehog/v3@latest"
check_recon git-dumper "pipx install git-dumper                            # or: pip install git-dumper"
check_recon noir       "build from https://github.com/owasp-noir/noir      # Crystal binary; brew tap noir-cr/noir && brew install noir"

# ── ProjectDiscovery expansion (W3) ──
check_recon dnsx       "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
check_recon naabu      "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
check_recon tlsx       "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
check_recon asnmap     "go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
check_recon uncover    "go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest"
check_recon cloudlist  "go install -v github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest"
check_recon notify     "go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
check_recon mapcves    "go install -v github.com/projectdiscovery/mapcves@latest"
check_recon cdncheck   "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
check_recon alterx     "go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest"
check_recon graphw00f  "pipx install graphw00f                              # https://github.com/dolevf/graphw00f"

# ── 40x bypass (W4) ──
check_recon dontgo403  "go install -v github.com/devploit/dontgo403@latest"
check_recon byp4xx     "go install -v github.com/lobuhi/byp4xx@latest"

# ── SCA + LLM + K8s + smuggle (W5) ──
check_recon osv-scanner "go install -v github.com/google/osv-scanner/cmd/osv-scanner@v2"
check_recon trivy      "brew install aquasecurity/trivy/trivy               # or: https://github.com/aquasecurity/trivy/releases"
check_recon grype      "brew install grype                                  # or: https://github.com/anchore/grype#installation"
check_recon garak      "pipx install garak"
check_recon mcp-scan   "pipx install mcp-scan                               # https://github.com/invariantlabs-ai/mcp-scan"
check_recon kubescape  "curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash"
check_recon kube-hunter "pipx install kube-hunter"
check_recon smuggle    "pipx install smuggle                                # or: https://github.com/defparam/smuggler"

# ── Cloud / IaC / CI / SBOM / K8s active / Visual EASM (W6) ──
check_recon prowler    "pipx install prowler                                # https://github.com/prowler-cloud/prowler"
check_recon scout      "pipx install scoutsuite                             # https://github.com/nccgroup/ScoutSuite"
check_recon cloudsploit "npm i -g cloudsploit                                # https://github.com/aquasecurity/cloudsploit"
check_recon pacu       "pipx install pacu                                   # https://github.com/RhinoSecurityLabs/pacu"
check_recon checkov    "pipx install checkov                                # https://github.com/bridgecrewio/checkov"
check_recon tfsec      "brew install tfsec                                  # or: https://github.com/aquasecurity/tfsec/releases"
check_recon terrascan  "brew install terrascan                              # or: https://github.com/tenable/terrascan/releases"
check_recon hadolint   "brew install hadolint                               # or: https://github.com/hadolint/hadolint/releases"
check_recon poutine    "brew install boostsecurityio/tap/poutine            # https://github.com/boostsecurityio/poutine"
check_recon octoscan   "go install -v github.com/synacktiv/octoscan@latest  # https://github.com/synacktiv/octoscan"
check_recon syft       "brew install syft                                   # or: https://github.com/anchore/syft#installation"
check_recon cosign     "brew install cosign                                 # or: https://github.com/sigstore/cosign/releases"
check_recon peirates   "go install -v github.com/inguardians/peirates@latest"
check_recon kdigger    "brew install mtardy/tap/kdigger                     # or: https://github.com/quarkslab/kdigger/releases"
check_recon kubeletctl "go install -v github.com/cyberark/kubeletctl/cmd/kubeletctl@latest"
check_recon gowitness  "go install -v github.com/sensepost/gowitness@latest"
check_recon dnsgen     "pipx install dnsgen                                 # https://github.com/AlephNullSK/dnsgen"
check_recon shuffledns "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
check_recon chaos      "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"

# ════════════════════════════════════════════════════════════════════
head "Red-team / network lane (core)"
# ════════════════════════════════════════════════════════════════════
# Powers run_nmap + run_network_tool. Traffic is TCP/SMB/LDAP/Kerberos — it
# does NOT route through Burp; evidence lands in the operator log instead.
check_recon nmap       "sudo apt install nmap                               # Kali: preinstalled"
check_recon nxc        "sudo apt install netexec                            # or: uv tool install git+https://github.com/Pennyw0rth/NetExec"
check_recon impacket-secretsdump "sudo apt install impacket-scripts        # or: uv tool install impacket"
check_recon responder  "sudo apt install responder                          # or: git clone https://github.com/lgandx/Responder"
check_recon bloodhound-python "sudo apt install bloodhound.py               # or: uv tool install bloodhound"
check_recon certipy    "sudo apt install certipy-ad                         # or: uv tool install certipy-ad"
check_recon kerbrute   "sudo apt install kerbrute                           # or: go install github.com/ropnop/kerbrute@latest"
check_recon enum4linux-ng "sudo apt install enum4linux-ng"
check_recon smbmap     "sudo apt install smbmap"
check_recon evil-winrm "sudo apt install evil-winrm                         # or: gem install evil-winrm"
check_recon gobuster   "sudo apt install gobuster                           # or: go install github.com/OJ/gobuster/v3@latest"
check_recon feroxbuster "sudo apt install feroxbuster                        # or: cargo install feroxbuster"
check_recon hashcat    "sudo apt install hashcat                            # offline cracking (not Rule-6 brute)"
check_recon john       "sudo apt install john                               # offline cracking"
check_recon sshuttle   "sudo apt install sshuttle                           # pivoting (alt: ligolo-ng / chisel)"
# SecLists is a directory, not a binary — detect the path detect_seclists() uses.
if [ -d /usr/share/seclists ] || [ -d /usr/share/SecLists ] || [ -d /opt/SecLists ]; then
    pass "seclists (wordlists present)"
else
    skip "seclists" "sudo apt install seclists   # or: git clone https://github.com/danielmiessler/SecLists /opt/SecLists"
fi

# ════════════════════════════════════════════════════════════════════
head "Ghostwriter (reporting / oplog hub)"
# ════════════════════════════════════════════════════════════════════
# Central hub both lanes forward into. Needs Docker; wired via .env
# (GHOSTWRITER_URL / GHOSTWRITER_ADMIN_SECRET|API_TOKEN / GHOSTWRITER_OPLOG_ID).
if has docker && docker info >/dev/null 2>&1; then
    pass "docker daemon reachable"
    gw_running="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -ci ghostwriter || true)"
    if [ "${gw_running:-0}" -gt 0 ] 2>/dev/null; then
        pass "Ghostwriter containers running ($gw_running)"
    else
        skip "Ghostwriter containers" "not running — ./setup-ghostwriter.sh"
    fi
else
    skip "docker" "not available — install Docker, then ./setup-ghostwriter.sh"
fi
# Praetor-side wiring (read from repo .env if present).
GW_ENV="$SCRIPT_DIR/.env"
gw_url="${GHOSTWRITER_URL:-}"; gw_auth=""; gw_oplog="${GHOSTWRITER_OPLOG_ID:-}"
if [ -f "$GW_ENV" ]; then
    [ -z "$gw_url" ] && gw_url="$(grep -E '^GHOSTWRITER_URL=' "$GW_ENV" | tail -1 | cut -d= -f2-)"
    [ -z "$gw_oplog" ] && gw_oplog="$(grep -E '^GHOSTWRITER_OPLOG_ID=' "$GW_ENV" | tail -1 | cut -d= -f2-)"
    grep -qE '^GHOSTWRITER_(ADMIN_SECRET|API_TOKEN)=.+' "$GW_ENV" && gw_auth="set"
fi
if [ -n "$gw_url" ] && [ -n "$gw_auth" ] && [ -n "$gw_oplog" ]; then
    pass "Praetor forwarding configured (url + auth + oplog $gw_oplog)"
elif [ -n "$gw_url" ]; then
    skip "Praetor forwarding" "partial — need auth + GHOSTWRITER_OPLOG_ID in .env (ghostwriter_status)"
else
    skip "Praetor forwarding" "unset — ./setup-ghostwriter.sh writes .env, then set GHOSTWRITER_OPLOG_ID"
fi
if [ -n "$gw_url" ]; then
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 4 "$gw_url/v1/graphql" 2>/dev/null || echo "")
    [ -n "$code" ] && [ "$code" != "000" ] && pass "GraphQL endpoint reachable ($gw_url/v1/graphql -> $code)" \
        || skip "GraphQL endpoint" "$gw_url/v1/graphql not reachable — is Ghostwriter up?"
fi

# ════════════════════════════════════════════════════════════════════
head "Knowledge base"
# ════════════════════════════════════════════════════════════════════

# Counts the JSON probe catalogs that drive auto_probe and confirms the
# reference-only set is consistent with the on-disk files. A drift between
# the constants module and the directory listing means new KBs aren't being
# routed through the prefix-loader.
KB_DIR="$SCRIPT_DIR/mcp-server/src/burpsuite_mcp/knowledge"
if [ -d "$KB_DIR" ]; then
    # JSON file count (exclude underscore-prefixed meta files)
    kb_total=$(find "$KB_DIR" -maxdepth 1 -name '*.json' ! -name '_*' 2>/dev/null | wc -l | tr -d ' ')
    pass "KB files: $kb_total under knowledge/"

    if [ -n "$VENV_PY" ]; then
        # Use the venv python to ask the scan module how many KBs are
        # reference-only — this is the same source of truth auto_probe uses.
        ref_count=$("$VENV_PY" -c "from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY; print(len(_REFERENCE_ONLY))" 2>/dev/null || echo "?")
        if [ "$ref_count" != "?" ] && [ "$ref_count" -gt 0 ] 2>/dev/null; then
            auto_count=$((kb_total - ref_count))
            pass "KB routing: $auto_count auto-probe + $ref_count reference-only"
        else
            skip "KB routing" "could not import scan._constants — server may not be installed"
        fi

        # Verify every reference-only entry corresponds to a real .json
        orphan=$("$VENV_PY" -c "
from pathlib import Path
from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY
files = {p.stem for p in Path('$KB_DIR').glob('*.json')}
print(','.join(sorted(r for r in _REFERENCE_ONLY if r not in files)))
" 2>/dev/null)
        if [ -z "$orphan" ]; then
            pass "Reference-only entries all resolve to files"
        else
            bad "Reference-only orphans" "$orphan"
        fi
    else
        skip "KB routing audit" "venv missing"
    fi
else
    bad "Knowledge dir" "$KB_DIR missing — KB-driven probes will fail"
fi

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

echo "  OK: $OK   tools missing: $WARN   failures: $FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}Doctor found $FAIL critical problem(s). Fix the [XX] items above.${NC}"
    exit 1
fi
if [ "$WARN" -gt 0 ]; then
    echo -e "${YELLOW}Healthy. Items in [--] are tools to install for full coverage.${NC}"
else
    echo -e "${GREEN}All clear.${NC}"
fi
exit 0
