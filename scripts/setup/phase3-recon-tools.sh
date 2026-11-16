#!/usr/bin/env bash
# Phase 3: core web/network/mobile recon+attack tool install, + optional Ghostwriter/BloodHound CE.
# Sourced by ../../setup.sh in order — do not run this file directly, it has
# no shebang-level set -e/colors/has() of its own; those come from lib.sh.

# ════════════════════════════════════════════════════════════════════
# PHASE 3: Recon Tools (core — web lane)
# ════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════"
echo "  Phase 3: Recon Tools (core — web lane)"
echo "════════════════════════════════════════════════════"
info "Installing core recon + attack tools (web + network lanes)."
echo ""

install_pd_tool() {
    local name="$1"
    local install_cmd="$2"
    # A `go install pkg@latest` command always re-resolves to the latest commit
    # and is a cheap no-op when already current, so --update re-runs it even
    # when $name is already on PATH. Without this, an operator who already had
    # an old vigil/groma/etc binary NEVER got a newer one — found from a real
    # bug report: vigil's `mcp` subcommand (added upstream after this
    # operator's build) never arrived via a plain OR --update re-run, because
    # install_pd_tool skipped the whole install step once `has vigil` was
    # true. Other install methods (uv tool install, curl|bash, brew) keep the
    # old skip-if-present behavior — they are not all safely idempotent to
    # blind-rerun, unlike go install.
    if has "$name" && { [ "$FORCE_UPDATE" != 1 ] || [[ "$install_cmd" != *"go install"* ]]; }; then
        ok "$name already installed"
    else
        if has "$name"; then
            info "Refreshing $name (--update)..."
        else
            info "Installing $name..."
        fi
        if eval "$install_cmd" 2>&1 | tail -1; then
            has "$name" && ok "$name installed" || warn "$name: install completed but binary not in PATH"
        else
            warn "$name installation failed — core tool; install manually"
        fi
    fi
}

# Go tools install into ~/go/bin (already on PATH for the go tools above).
BIN_DIR="$(go env GOBIN 2>/dev/null)"; [ -n "$BIN_DIR" ] || BIN_DIR="$(go env GOPATH 2>/dev/null)/bin"; [ -n "$BIN_DIR" ] || BIN_DIR="$HOME/go/bin"

# OS / arch tokens for release-binary asset names (macOS may be Apple Silicon).
OS=linux; OS_CAP=Linux; [ "$PLATFORM" = "macos" ] && { OS=darwin; OS_CAP=Darwin; }
case "$(uname -m)" in arm64|aarch64) ARCH=arm64; ARCH_X=arm64 ;; *) ARCH=amd64; ARCH_X=x86_64 ;; esac

# DL_FLAGS (bounded-download curl flags) and run_to (bounded git/hf) are defined
# once near the top of this script, so they are available to every phase.

# Pinned release tags. Release binaries are fetched from github.com at these
# EXACT tags, so setup never calls the api.github.com "latest" endpoint — the
# unauthenticated-and-rate-limited (60/hr per IP) lookup that hung, then aborted,
# a macOS run at kdigger. github.com/releases/download is not rate-limited the
# same way. Bump a version HERE when you want newer; nothing else looks it up.
KDIGGER_TAG=v1.5.1
KUBESCAPE_TAG=v4.0.14
KUBELETCTL_TAG=v1.13
TERRASCAN_TAG=v1.19.9
NOMORE403_TAG=v2.0.1
OSV_SCANNER_TAG=v2.6.0
HADOLINT_TAG=v2.15.1
NOIR_TAG=v1.3.1

# install_gh_binary <name> <owner/repo> <tag> <asset-filename> — download a
# single-file release binary into BIN_DIR as <name>, at a PINNED tag. For tools
# whose go.mod carries replace directives (go install pkg@latest is impossible)
# or that ship no source module.
install_gh_binary() {
    local name="$1" repo="$2" tag="$3" asset="$4"
    if has "$name"; then ok "$name already installed"; return; fi
    info "Installing $name $tag (release binary)..."
    mkdir -p "$BIN_DIR"
    if curl -fsSL $DL_FLAGS -o "$BIN_DIR/$name" \
            "https://github.com/$repo/releases/download/$tag/$asset"; then
        chmod +x "$BIN_DIR/$name"
        has "$name" && ok "$name $tag installed" || warn "$name installed to $BIN_DIR but not on PATH"
    else
        warn "$name release download failed — install manually: https://github.com/$repo/releases"
    fi
}

install_pd_tool "subfinder" \
    "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

install_pd_tool "httpx" \
    "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"

install_pd_tool "nuclei" \
    "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

# vigil — Praetor's default web-scan engine (run_vigil / merge_scan). Native
# context-aware detectors + nuclei-compatible template engine + headless.
install_pd_tool "vigil" \
    "go install github.com/TyrusRC/vigil/cmd/vigil@latest"
# `vigil mcp` is what .mcp.json's "vigil" server entry spawns — a build from
# before that subcommand existed upstream "installs" fine (has vigil = true)
# but leaves the MCP server dead on every later run, plain or --update, since
# install_pd_tool otherwise never re-touches an already-present binary. Force
# a refresh regardless of --update when the capability is missing — this is
# a repair, not an upgrade preference.
if has vigil && ! vigil mcp --help >/dev/null 2>&1; then
    warn "vigil is missing its 'mcp' subcommand (stale build) — forcing a refresh..."
    go install github.com/TyrusRC/vigil/cmd/vigil@latest 2>&1 | tail -1
    if vigil mcp --help >/dev/null 2>&1; then
        ok "vigil refreshed — 'mcp' subcommand present"
    else
        warn "vigil still missing 'mcp' after refresh — the .mcp.json vigil server will fail to start; check go install output above"
    fi
fi

# groma — Praetor's default network-scan engine (run_groma). Full 1-65535
# port range by default, naabu-based service fingerprinting + YAML CVE
# checks. Replaces the old direct run_naabu wrapper; naabu itself (below,
# in the PD expansion block) stays installed as groma's OWN optional
# dependency, not a Praetor-exposed tool anymore.
install_pd_tool "groma" \
    "go install github.com/TyrusRC/groma/cmd/groma@latest"

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

# ── Nuclei templates: Praetor custom set ────────────────────────────
# run_vigil (and nuclei) load these. The custom set is cloned into the user
# data dir run_vigil auto-detects ($HOME/.local/share/praetor/custom-nuclei-templates;
# override the list with PRAETOR_VIGIL_TEMPLATES). Default nuclei store
# (~/nuclei-templates) is fetched on first nuclei/vigil run.
CUSTOM_TPL_DIR="$HOME/.local/share/praetor/custom-nuclei-templates"
if has git; then
    if [ -d "$CUSTOM_TPL_DIR/.git" ]; then
        info "Updating custom nuclei templates..."
        run_to "$GIT_TIMEOUT" git -C "$CUSTOM_TPL_DIR" pull --ff-only >/dev/null 2>&1 \
            && ok "custom nuclei templates updated ($CUSTOM_TPL_DIR)" \
            || warn "custom templates update failed — pull manually in $CUSTOM_TPL_DIR"
    elif [ -d "$CUSTOM_TPL_DIR" ]; then
        warn "custom templates dir exists but is not a git clone — leaving as-is ($CUSTOM_TPL_DIR)"
    else
        info "Cloning custom nuclei templates (TyrusRC/custom-nuclei-templates)..."
        mkdir -p "$(dirname "$CUSTOM_TPL_DIR")"
        if run_to "$GIT_TIMEOUT" git clone --depth 1 https://github.com/TyrusRC/custom-nuclei-templates.git "$CUSTOM_TPL_DIR" >/dev/null 2>&1; then
            ok "custom nuclei templates cloned ($CUSTOM_TPL_DIR)"
        else
            warn "custom templates clone failed — clone manually: git clone https://github.com/TyrusRC/custom-nuclei-templates.git \"$CUSTOM_TPL_DIR\""
        fi
    fi
else
    warn "git not found — skipping custom nuclei templates (run_vigil auto-detects $CUSTOM_TPL_DIR when present)"
fi

# ── Praetor v1.0 SAST + secrets layer ──
echo ""
info "Praetor v1.0 — installing SAST + secrets layer (core)..."

install_pd_tool "opengrep" \
    "curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash"

# ── Praetor engines: mantis (source-audit) + centurion (mobile) ──────
# Both are CORE, not optional. mantis backs run_mantis (needs opengrep, installed
# above). centurion is the core mobile engine, loaded as a companion MCP server
# alongside praetor (separate server for device/MASTG depth — see
# examples/mcp-clients/claude-code.mcp.json); its device/static binaries (jadx,
# frida, apkid, objection, class-dump, ...) are detected on demand.
# Installed from git until published to PyPI (mantis dist = mantis-sast; centurion
# dist name TBD — 'centurion' is taken on PyPI). Switch to `uv tool install <name>`
# once published.
install_pd_tool "mantis" \
    "uv tool install 'git+https://github.com/TyrusRC/mantis.git'"
install_pd_tool "centurion-mcp" \
    "uv tool install 'git+https://github.com/TyrusRC/centurion.git'"

# gitleaks — the module still declares the legacy zricethezav path (the
# gitleaks/gitleaks path fails "declares its path as ... but was required as").
install_pd_tool "gitleaks" \
    "go install -v github.com/zricethezav/gitleaks/v8@latest"

# trufflehog — secrets scanner (v3). macOS: Homebrew. Kali/Linux: official
# install script (prebuilt binary) into ~/go/bin, which is already on PATH for
# the go tools above. `go install` is unreliable here (main-package layout).
if [ "$PLATFORM" = "macos" ]; then
    install_pd_tool "trufflehog" "brew install trufflehog"
else
    install_pd_tool "trufflehog" \
        'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$HOME/go/bin"'
fi

# git-dumper — Python CLI, install via uv tool
install_pd_tool "git-dumper" \
    "uv tool install git-dumper"

# credshound — local-host credential-surface scanner (run_credshound). LOLCreds-
# template-driven, like nuclei for credential artifacts (env/files/proc, AI/MCP
# configs, cloud/DevOps creds). Templates auto-fetch on first run_credshound call.
install_pd_tool "credshound" \
    "go install github.com/haxxm0nkey/credshound/cmd/credshound@latest"

# OWASP Noir — Crystal binary. macOS: Homebrew formula. Kali/Debian: official
# .deb from GitHub Releases (dpkg). Other distros: see the install docs.
if has noir; then
    ok "noir already installed"
elif [ "$PLATFORM" = "macos" ]; then
    install_pd_tool "noir" "brew install noir"
elif has apt-get; then
    info "Installing noir (.deb from GitHub releases)..."
    NOIR_VER="${NOIR_TAG#v}"
    if [ -n "$NOIR_VER" ] && curl -fsSL $DL_FLAGS -o /tmp/noir.deb "https://github.com/owasp-noir/noir/releases/download/v${NOIR_VER}/noir_${NOIR_VER}_amd64.deb"; then
        sudo dpkg -i /tmp/noir.deb && ok "noir $NOIR_VER installed" || warn "noir dpkg failed — install manually"
        rm -f /tmp/noir.deb
    else
        warn "noir release download failed — see https://owasp-noir.github.io/noir/get_started/installation/"
    fi
else
    warn "noir not installed — see https://owasp-noir.github.io/noir/get_started/installation/ (brew install noir / sudo snap install noir / build from source)"
fi

# dig — DNS lookups used across recon (dnsutils / bind-tools)
if has dig; then
    ok "dig already installed"
elif [ "$PLATFORM" = "linux" ]; then
    pkg_install dnsutils || pkg_install bind-tools || warn "dig not installed — install dnsutils/bind-tools manually"
elif [ "$PLATFORM" = "macos" ]; then
    pkg_install bind || warn "dig not installed — brew install bind"
fi

# ── tesseract OCR — screenshot auto-redaction (auto_redact_screenshot) ──
if has tesseract; then
    ok "tesseract already installed ($(tesseract --version 2>&1 | head -1))"
elif [ "$PLATFORM" = "linux" ]; then
    pkg_install tesseract-ocr && ok "tesseract installed" \
        || warn "tesseract not installed — apt/dnf install tesseract-ocr (screenshot auto-redaction)"
else
    pkg_install tesseract && ok "tesseract installed" \
        || warn "tesseract not installed — brew install tesseract (screenshot auto-redaction)"
fi

# ── ProjectDiscovery expansion — recon_pd tools (run_dnsx / ...) ──
echo ""
info "ProjectDiscovery expansion (DNS / ports / TLS / ASN / OSINT recon)..."
install_pd_tool "dnsx"      "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
# naabu is not a direct Praetor tool (recon_pd dropped run_naabu) — groma
# wraps it internally (fast full-range port sweep + -sV fingerprinting) and
# degrades gracefully to its own native scanner if this install is skipped.
install_pd_tool "naabu"     "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_pd_tool "tlsx"      "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
install_pd_tool "asnmap"    "go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
install_pd_tool "uncover"   "go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest"
install_pd_tool "cloudlist" "go install -v github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest"
install_pd_tool "notify"    "go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
install_pd_tool "vulnx"     "go install -v github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest"
install_pd_tool "cdncheck"  "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
install_pd_tool "alterx"    "go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest"
install_pd_tool "shuffledns" "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
install_pd_tool "chaos"     "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
install_pd_tool "graphw00f" "uv tool install graphw00f"
install_pd_tool "dnsgen"    "uv tool install dnsgen"

# ── 40x / 403 bypass (run_nomore403 / run_byp4xx) ──
echo ""
info "40x access-control bypass tools..."
install_gh_binary "nomore403" "devploit/nomore403" "$NOMORE403_TAG" "nomore403_${OS}_${ARCH}"
install_pd_tool "byp4xx"    "go install -v github.com/lobuhi/byp4xx@latest"

# ── SCA / containers / SBOM (run_osv_scanner / run_trivy / run_grype / run_syft / run_cosign_verify) ──
echo ""
info "SCA + container + SBOM tools..."
# osv-scanner via release binary — `go install` compiles a huge dep tree
# (modernc sqlite, etc.) and looks like a hang; the prebuilt binary is instant.
install_gh_binary "osv-scanner" "google/osv-scanner" "$OSV_SCANNER_TAG" "osv-scanner_${OS}_${ARCH}"
install_pd_tool "cosign"    "go install -v github.com/sigstore/cosign/v2/cmd/cosign@latest"
install_pd_tool "trivy"     "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b \"$HOME/go/bin\""
install_pd_tool "grype"     "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b \"$HOME/go/bin\""
install_pd_tool "syft"      "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b \"$HOME/go/bin\""

# ── LLM / MCP security (run_garak / run_mcp_scan) ──
echo ""
info "LLM + MCP security tools..."
install_pd_tool "garak"     "uv tool install garak"
# mcp-scan (invariantlabs) was renamed to snyk-agent-scan; the old package is
# now a dead redirect stub that scans nothing. run_mcp_scan targets the new one.
install_pd_tool "snyk-agent-scan"  "uv tool install snyk-agent-scan"

# HTTP request smuggling has no external CLI dependency — Praetor ships it natively
# (send_raw_request + testing_extended/_smuggle_capture + test_request_smuggling).

# ── Kubernetes (run_kubescape / run_kube_hunter / run_peirates / run_kdigger / run_kubeletctl) ──
echo ""
info "Kubernetes audit + attack tools..."
# peirates main package lives in cmd/peirates (not the module root).
install_pd_tool "peirates"   "go install -v github.com/inguardians/peirates/cmd/peirates@latest"
# kubeletctl's go.mod declares a bare module name (not a URL) — not go-installable;
# use the release binary.
install_gh_binary "kubeletctl" "cyberark/kubeletctl" "$KUBELETCTL_TAG" "kubeletctl_${OS}_${ARCH}"
install_pd_tool "kube-hunter" "uv tool install kube-hunter"
# kubescape — the install.sh drops the binary in a dir off PATH; fetch the
# release binary straight into BIN_DIR instead (asset carries the version).
if has kubescape; then
    ok "kubescape already installed"
else
    info "Installing kubescape (release binary)..."
    KS_TAG="$KUBESCAPE_TAG"; KS_VER="${KS_TAG#v}"
    mkdir -p "$BIN_DIR"
    if [ -n "$KS_VER" ] && curl -fsSL $DL_FLAGS -o "$BIN_DIR/kubescape" \
            "https://github.com/kubescape/kubescape/releases/download/${KS_TAG}/kubescape_${KS_VER}_${OS}_${ARCH}"; then
        chmod +x "$BIN_DIR/kubescape"
        has kubescape && ok "kubescape $KS_VER installed" || warn "kubescape installed to $BIN_DIR but not on PATH"
    else
        warn "kubescape release download failed — https://github.com/kubescape/kubescape/releases"
    fi
fi
if has kdigger; then
    ok "kdigger already installed"
else
    install_gh_binary "kdigger" "quarkslab/kdigger" "$KDIGGER_TAG" "kdigger-${OS}-${ARCH}"
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
# terrascan / octoscan carry `replace` directives in go.mod, so `go install
# pkg@latest` is impossible ("interpreted differently than if it were the main
# module"). terrascan → release tarball; octoscan → build from a clone.
if has terrascan; then
    ok "terrascan already installed"
else
    info "Installing terrascan (release tarball)..."
    TS_TAG="$TERRASCAN_TAG"; TS_VER="${TS_TAG#v}"
    mkdir -p "$BIN_DIR"
    if [ -n "$TS_VER" ] && curl -fsSL $DL_FLAGS -o /tmp/terrascan.tgz \
            "https://github.com/tenable/terrascan/releases/download/${TS_TAG}/terrascan_${TS_VER}_${OS_CAP}_${ARCH_X}.tar.gz" \
            && tar -xzf /tmp/terrascan.tgz -C "$BIN_DIR" terrascan 2>/dev/null; then
        chmod +x "$BIN_DIR/terrascan"; ok "terrascan $TS_VER installed"
    else
        warn "terrascan release download failed — https://github.com/tenable/terrascan/releases"
    fi
    rm -f /tmp/terrascan.tgz
fi
install_pd_tool "poutine"   "go install -v github.com/boostsecurityio/poutine@latest"
if has octoscan; then
    ok "octoscan already installed"
else
    info "Installing octoscan (build from source)..."
    OCT_TMP="$(mktemp -d)"
    if run_to "$GIT_TIMEOUT" git clone --depth 1 https://github.com/synacktiv/octoscan "$OCT_TMP/octoscan" >/dev/null 2>&1 \
            && (cd "$OCT_TMP/octoscan" && go build -o "$BIN_DIR/octoscan" . >/dev/null 2>&1) && has octoscan; then
        ok "octoscan installed"
    else
        warn "octoscan build failed — manual: git clone https://github.com/synacktiv/octoscan && go build"
    fi
    rm -rf "$OCT_TMP"
fi
if has hadolint; then
    ok "hadolint already installed"
elif [ "$PLATFORM" = "macos" ]; then
    install_pd_tool "hadolint" "brew install hadolint"
else
    install_gh_binary "hadolint" "hadolint/hadolint" "$HADOLINT_TAG" "hadolint-${OS}-${ARCH_X}"
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

# NetExec is installed from git on every non-Kali host (it is not on PyPI, and
# only Kali/Parrot ship a `netexec` apt package). Its dependency `aardwolf`
# (and other AD deps) build from source and need a Rust toolchain — uv aborts
# with "Rust compiler toolchain" when cargo is absent, which is exactly why nxc
# failed on macOS. Provide cargo before the git build. No-op if already present.
ensure_rust() {
    has cargo && return 0
    info "Installing Rust toolchain (NetExec build dependency)..."
    if [ "$PLATFORM" = "macos" ]; then
        brew install rust 2>&1 | tail -1 || warn "brew install rust failed — nxc build may fail"
    elif has apt-get; then
        sudo apt-get install -y cargo 2>&1 | tail -1 || warn "apt install cargo failed — nxc build may fail"
    elif has dnf; then
        sudo dnf install -y cargo 2>&1 | tail -1 || warn "dnf install cargo failed — nxc build may fail"
    elif has pacman; then
        sudo pacman -S --noconfirm rust 2>&1 | tail -1 || warn "pacman install rust failed — nxc build may fail"
    fi
}

# Most of these ship in the Kali/Parrot repos under one apt bundle. On other
# distros install what the package manager has and print a hint for the rest.
# NOTE: ldapdomaindump and kerbrute are NOT in the Kali apt repos — and a single
# unlocatable name makes `apt-get install` abort the ENTIRE bundle, so they are
# installed separately below (pypi / go) rather than listed here.
RT_APT_PKGS="nmap netexec impacket-scripts responder john hashcat gobuster \
feroxbuster smbmap enum4linux-ng certipy-ad evil-winrm \
bloodhound.py sshuttle seclists"

if [ "$IS_KALI" -eq 1 ]; then
    info "Kali/Parrot detected — installing the red-team bundle via apt..."
    sudo apt-get install -y $RT_APT_PKGS 2>&1 | tail -2 \
        || warn "some red-team apt packages failed — core; install individually"
    # Not in apt — install via their upstream methods.
    install_pd_tool "ldapdomaindump" "uv tool install ldapdomaindump"
    install_pd_tool "kerbrute"       "go install github.com/ropnop/kerbrute@latest"
elif has apt-get; then
    info "Debian/Ubuntu — installing what the repos carry..."
    sudo apt-get install -y nmap john hashcat gobuster feroxbuster smbmap sshuttle 2>&1 | tail -2 \
        || warn "some apt packages failed — install manually"
    # Python-side red-team tools via uv (isolated per-tool venv). impacket from
    # PyPI installs `secretsdump.py` et al. (NOT the Debian `impacket-*` names);
    # run_network_tool accepts either, so verify the name PyPI actually creates.
    ensure_rust
    install_pd_tool "nxc"        "uv tool install git+https://github.com/Pennyw0rth/NetExec"
    install_pd_tool "secretsdump.py" "uv tool install impacket"
    install_pd_tool "certipy"    "uv tool install certipy-ad"
    install_pd_tool "bloodhound-python" "uv tool install bloodhound"
    install_pd_tool "kerbrute"   "go install github.com/ropnop/kerbrute@latest"
    # Responder (LLMNR/NBT-NS/MDNS poisoner). Not on PyPI under this name — that
    # is an unrelated web framework — so install from git; the repo's pyproject
    # installs the `responder` console script and supports Linux + macOS.
    install_pd_tool "responder"  "uv tool install git+https://github.com/lgandx/Responder"
elif [ "$PLATFORM" = "macos" ]; then
    info "macOS — installing the network lane via Homebrew + uv/go..."
    # System tools Homebrew carries. Installed one per line via install_pd_tool
    # so a single missing/renamed formula can't abort the rest of the bundle
    # (a bare `brew install a b c` fails the whole line on one bad name).
    install_pd_tool "nmap"        "brew install nmap"
    install_pd_tool "john"        "brew install john"
    install_pd_tool "hashcat"     "brew install hashcat"
    install_pd_tool "gobuster"    "brew install gobuster"
    install_pd_tool "feroxbuster" "brew install feroxbuster"
    install_pd_tool "sshuttle"    "brew install sshuttle"
    # smbmap has no brew formula — same PyPI source works cross-platform.
    install_pd_tool "smbmap"      "uv tool install smbmap"
    # Python/Go red-team tools — identical cross-platform sources to the Debian branch.
    ensure_rust
    install_pd_tool "nxc"        "uv tool install git+https://github.com/Pennyw0rth/NetExec"
    install_pd_tool "secretsdump.py" "uv tool install impacket"
    install_pd_tool "certipy"    "uv tool install certipy-ad"
    install_pd_tool "bloodhound-python" "uv tool install bloodhound"
    install_pd_tool "kerbrute"   "go install github.com/ropnop/kerbrute@latest"
    # Responder — git install (see the Debian branch note). netifaces, one of
    # its deps, is a C extension; on macOS it needs the Xcode CLT that preflight
    # already checks for.
    install_pd_tool "responder"  "uv tool install git+https://github.com/lgandx/Responder"
else
    warn "Non-apt host — install red-team tools manually. redteam_tool_guide(tool='<name>')"
    warn "  in Praetor prints the apt/clone/go command for each."
fi

# SecLists: apt on Kali; otherwise clone to /opt/SecLists (detect_seclists finds both).
if [ -d /usr/share/seclists ] || [ -d /usr/share/SecLists ] || [ -d /opt/SecLists ]; then
    ok "SecLists present"
elif [ "$IS_KALI" -eq 0 ]; then
    info "Cloning SecLists to /opt/SecLists (large; shallow clone)..."
    run_to "$((GIT_TIMEOUT * 6))" sudo env \
             GIT_HTTP_LOW_SPEED_LIMIT="$GIT_HTTP_LOW_SPEED_LIMIT" \
             GIT_HTTP_LOW_SPEED_TIME="$GIT_HTTP_LOW_SPEED_TIME" \
        git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists 2>&1 | tail -1 \
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
# Ghostwriter (optional reporting/oplog hub) — auto-setup
# ════════════════════════════════════════════════════════════════════
echo ""
if ask_optional "Ghostwriter reporting/oplog hub (heavy Docker install, GBs, binds :443)" PRAETOR_SKIP_GHOSTWRITER; then
    if has docker && docker info >/dev/null 2>&1; then
        info "Ghostwriter (central reporting/oplog hub) — running auto-setup..."
        # Non-fatal: a Ghostwriter hiccup must not abort the rest of setup.
        "$SCRIPT_DIR/setup-ghostwriter.sh" || warn "Ghostwriter auto-setup did not finish — run ./setup-ghostwriter.sh manually."
    else
        warn "Docker not available — skipping Ghostwriter. Install Docker, then run ./setup-ghostwriter.sh"
    fi
fi

# ════════════════════════════════════════════════════════════════════
# BloodHound CE (optional AD attack-path graph — Neo4j/Postgres, Docker)
# ════════════════════════════════════════════════════════════════════
# ingest_bloodhound / sync_bloodhound_to_ghostwriter work WITHOUT this: they
# parse a SharpHound/bloodhound-python collection file directly and forward
# edges to the operator log + Ghostwriter. BloodHound CE itself is the
# visual graph UI (Cypher queries, "shortest path to Domain Admins") — the
# kali.org 'bloodhound' package is BloodHound CE, not legacy BloodHound; its
# apt install is Kali-only, so this script uses the official cross-platform
# Docker Compose quickstart instead. Not installed by this script's own
# verification — no Docker available in the environment this was written
# in, so setup-bloodhound.sh is syntax-checked only, not run end-to-end.
echo ""
if ask_optional "BloodHound CE attack-path graph UI (heavy Docker install, GBs)" PRAETOR_SKIP_BLOODHOUND; then
    if has docker && docker info >/dev/null 2>&1; then
        info "BloodHound CE — running auto-setup..."
        "$SCRIPT_DIR/setup-bloodhound.sh" || warn "BloodHound CE auto-setup did not finish — run ./setup-bloodhound.sh manually."
    else
        warn "Docker not available — skipping BloodHound CE. Install Docker, then run ./setup-bloodhound.sh"
    fi
fi

