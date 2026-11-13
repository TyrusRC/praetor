#!/usr/bin/env bash
# Shared helpers (colors, has/info/ok/warn/fail, ask_optional, pkg_install, bounded network, preflight) for every phase script below. Sets up state phase1-4 depend on.
# Sourced by ../../setup.sh in order — do not run this file directly, it has
# no shebang-level set -e/colors/has() of its own; those come from lib.sh.


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

# ── Interactive opt-in for heavy, non-core add-ons ──────────────────
# Haruspex (~150MB model download), Ghostwriter, and BloodHound CE (both
# multi-GB Docker stacks) are optional add-ons, not the core pentest
# toolset — everything else setup.sh installs is on by default. Ask when a
# human is at the keyboard; stay CI-safe otherwise: an explicit env var
# always wins with no prompt (1 = skip, 0 = install non-interactively), and
# a non-interactive run (no TTY — curl|bash, cron, CI) defaults to
# SKIPPING rather than blocking on stdin. Exported once per run (no var
# set) so later phases that re-check the same var don't re-prompt.
ask_optional() {
    local label="$1" envvar="$2"
    local cur="${!envvar:-}"
    if [ -n "$cur" ]; then
        [ "$cur" = "1" ] && { info "$label: skipped (\$$envvar=1)"; return 1; }
        return 0
    fi
    if [ ! -t 0 ] || [ ! -t 1 ]; then
        info "$label: skipped (non-interactive run — pass ${envvar}=0 to install without a prompt)"
        export "$envvar=1"
        return 1
    fi
    local reply=""
    read -r -p "Install $label? [y/N] " reply </dev/tty 2>/dev/null || reply="n"
    case "$reply" in
        [yY]|[yY][eE][sS]) export "$envvar=0"; return 0 ;;
        *) info "$label: skipped (pass ${envvar}=0 to force-install non-interactively next time)"
           export "$envvar=1"; return 1 ;;
    esac
}

# ── CLI flags ───────────────────────────────────────────────────────
# `./setup.sh` installs, and keeps whatever is already present. `./setup.sh
# --update` ALSO refreshes components that are otherwise kept on a re-run —
# today that is the Haruspex model adapters, re-pulled from HuggingFace so a
# newer trained adapter replaces the local copy. Git repos (haruspex,
# burp-expedition, nuclei templates) always pull --ff-only on every run.
FORCE_UPDATE=0
for _arg in "$@"; do
    case "$_arg" in
        -u|--update|--refresh) FORCE_UPDATE=1 ;;
        -h|--help)
            echo "Praetor setup. Usage: ./setup.sh [--update] [--help]"
            echo "  --update   refresh kept components (re-download Haruspex adapters)"
            echo "  --help     show this help"
            exit 0 ;;
        *) echo "[!] unknown flag: $_arg (ignored)" ;;
    esac
done
[ "$FORCE_UPDATE" = 1 ] && echo "[*] Update mode: kept components will be refreshed."

# ── Bounded network ops — a stalled socket must never hang setup ──────
# git-over-https and `hf download` can block forever on a half-open socket.
# Wrap them in a hard wall-clock cap, and make git abort a transfer that
# stalls under 1 KB/s for 30s. Caps are tunable via the env vars below.
export GIT_HTTP_LOW_SPEED_LIMIT="${GIT_HTTP_LOW_SPEED_LIMIT:-1024}"
export GIT_HTTP_LOW_SPEED_TIME="${GIT_HTTP_LOW_SPEED_TIME:-30}"
GIT_TIMEOUT="${PRAETOR_GIT_TIMEOUT:-300}"
HF_TIMEOUT="${PRAETOR_HF_TIMEOUT:-900}"
if has timeout; then _TIMEOUT=timeout
elif has gtimeout; then _TIMEOUT=gtimeout   # coreutils on macOS
else _TIMEOUT=""; fi
# run_to <seconds> <cmd...> — run cmd under a hard time cap when `timeout` is
# available; otherwise run it unwrapped (never block the whole script on it).
run_to() {
    local secs="$1"; shift
    if [ -n "$_TIMEOUT" ]; then "$_TIMEOUT" "$secs" "$@"; else "$@"; fi
}
# Bounded-download curl flags — reused by every release-binary / tarball / model
# download. Defined here (early) so the Haruspex block below can use it too.
# --speed-limit/--speed-time abort a transfer that stalls under 1 KB/s for 30s
# (the actual "install got stuck" symptom), while --max-time is a generous
# absolute ceiling that will not truncate a slow-but-progressing large file.
DL_FLAGS="--connect-timeout 15 --speed-limit 1024 --speed-time 30 --max-time 900 --retry 2 --retry-delay 2"

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

# ── Preflight: OS-first toolchain check ─────────────────────────────
# OS is detected above; now verify THIS platform's package manager + build
# toolchain BEFORE any install runs, so a missing prerequisite fails fast with
# the exact fix instead of erroring halfway through Phase 1.
preflight() {
    if [ "$PLATFORM" = "macos" ]; then
        if ! has brew; then
            fail "Homebrew is required on macOS. Install it, then re-run ./setup.sh:"
            echo '    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
            exit 1
        fi
        # Xcode Command Line Tools compile the Go tools and the lxml/Pillow C
        # extensions — the #1 macOS build failure when absent.
        if ! xcode-select -p &>/dev/null; then
            warn "Xcode Command Line Tools not found — Go/lxml/Pillow builds will fail."
            info "Install with:  xcode-select --install   (then re-run ./setup.sh)"
        fi
        info "Plan (macOS): brew for system tools · go install for ProjectDiscovery · uv for Python."
    else
        local pkg=""
        has apt-get && pkg=apt; [ -z "$pkg" ] && has dnf && pkg=dnf; [ -z "$pkg" ] && has pacman && pkg=pacman
        if [ -z "$pkg" ]; then
            fail "No supported package manager (apt/dnf/pacman) found on this Linux host — install one or install deps manually."
            exit 1
        fi
        info "Plan (Linux/$pkg): $pkg for system tools · go install for ProjectDiscovery · uv for Python."
    fi
}
preflight

# ════════════════════════════════════════════════════════════════════
