#!/usr/bin/env bash
# Phase 2: build the Burp extension + burp-expedition, install the MCP server, optional Haruspex, CloakBrowser/Playwright, chrome-devtools-mcp.
# Sourced by ../../setup.sh in order — do not run this file directly, it has
# no shebang-level set -e/colors/has() of its own; those come from lib.sh.

# ════════════════════════════════════════════════════════════════════
# PHASE 2: Build the Project
# ════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════"
echo "  Phase 2: Build the Project"
echo "════════════════════════════════════════════════════"

# SCRIPT_DIR is set by setup.sh (the orchestrator) before this file is
# sourced — ${BASH_SOURCE[0]} in a sourced file resolves to ITS OWN path,
# not setup.sh's, so it must not be recomputed here.

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

# ── burp-expedition: non-HTTP TCP/UDP lane (tcp_* tools) ─────────────
# A second Burp extension (TyrusRC/burp-expedition) — core, not optional. It adds
# a Netty TCP/UDP/SOCKS5 proxy with per-protocol dissectors + a Control API on
# :18112. Praetor drives it through the tcp_* tools for DB / Redis / MQTT /
# Modbus / DNP3 / gRPC / custom-binary testing (skill: non-http-protocol-testing.md).
# Cloned next to the praetor extension, built to build/libs/ with its gradlew.
# Load the jar in Burp the same way as the praetor extension (step 2 of Next steps).
EXPEDITION_DIR="$SCRIPT_DIR/../burp-expedition"
EXP_JAR=""
if has git; then
    if [ -d "$EXPEDITION_DIR/.git" ]; then
        info "Updating burp-expedition..."
        run_to "$GIT_TIMEOUT" git -C "$EXPEDITION_DIR" pull --ff-only >/dev/null 2>&1 \
            || warn "burp-expedition update failed — pull manually in $EXPEDITION_DIR"
    elif [ -d "$EXPEDITION_DIR" ]; then
        warn "burp-expedition dir exists but is not a git clone — leaving as-is ($EXPEDITION_DIR)"
    else
        info "Cloning burp-expedition (TyrusRC/burp-expedition)..."
        run_to "$GIT_TIMEOUT" git clone --depth 1 https://github.com/TyrusRC/burp-expedition.git "$EXPEDITION_DIR" >/dev/null 2>&1 \
            || warn "burp-expedition clone failed — clone manually: git clone https://github.com/TyrusRC/burp-expedition.git \"$EXPEDITION_DIR\""
    fi
    if [ -d "$EXPEDITION_DIR" ]; then
        info "Building burp-expedition (./gradlew shadowJar)..."
        if (cd "$EXPEDITION_DIR" && ./gradlew shadowJar >/dev/null 2>&1); then
            EXP_JAR="$(ls -t "$EXPEDITION_DIR"/build/libs/burp-expedition-*.jar 2>/dev/null | grep -v -- '-sources.jar' | head -1)"
            [ -n "$EXP_JAR" ] && ok "burp-expedition built: $EXP_JAR" \
                || warn "burp-expedition build reported no jar under build/libs/"
        else
            warn "burp-expedition build failed — build manually: (cd \"$EXPEDITION_DIR\" && ./gradlew shadowJar)"
        fi
    fi
else
    warn "git not found — skipping burp-expedition (clone+build manually: git clone https://github.com/TyrusRC/burp-expedition.git && ./gradlew shadowJar)"
fi

# ── Install Python MCP server ──────────────────────────────────────
info "Setting up Python MCP server..."
cd "$SCRIPT_DIR/mcp-server"
# macOS: lxml/Pillow are C extensions that fail to build without the system
# libraries + Xcode command-line tools. Kali/apt ships prebuilt wheels/libs, so
# only macOS needs this. Install them BEFORE `uv pip install -e .` so the build
# of those deps succeeds instead of silently leaving the tool surface broken.
if [ "$PLATFORM" = "macos" ]; then
    has xcode-select && ! xcode-select -p &>/dev/null && \
        warn "Xcode CLT missing — run 'xcode-select --install' if the build below fails"
    info "Installing C-extension build libs (libxml2, libxslt, jpeg)..."
    pkg_install libxml2 libxslt jpeg 2>&1 | tail -1 \
        || warn "brew build libs failed — lxml/Pillow may not compile"
fi
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

# ── Haruspex decision model (calibrated verdict enrichment) ───────────
# Praetor's _decision.py auto-detects a local Haruspex on 127.0.0.1:3000.
# Pre-trained adapters (~30MB each) are downloaded from HuggingFace. Existing
# adapters are kept — a plain run only downloads what is missing. Re-run with
# `./setup.sh --update` to re-pull every adapter and pick up a newer model.
# To retrain from custom data: cd ../haruspex && uv run python -m haruspex.train \
#   --train data/security_train.jsonl --out runs/web --epochs 5
if ! ask_optional "Haruspex decision model (optional verdict enrichment, ~150MB adapter downloads)" PRAETOR_SKIP_HARUSPEX; then
    info "Praetor runs fine without it — _decision.py falls back to deterministic ordering."
else
HARUSPEX_DIR="$SCRIPT_DIR/../haruspex"
HARUSPEX_HF_REPO="TyrusRC/haruspex"
# Praetor routes every decision with domain="web" (the root security adapter); the
# other per-domain adapters are fetched for keyword-routed fallback. On HF, "web" is
# the repo ROOT (final/ + calibrator.json + ood.json); the rest are same-repo subfolders.
HARUSPEX_DOMAINS="web cloud llm mobile network"

# HF path prefix for a domain: empty (repo root) for web, else "<domain>/".
_hx_prefix() { [ "$1" = "web" ] && printf '' || printf '%s/' "$1"; }

if [ -d "$HARUSPEX_DIR/.git" ]; then
    info "Updating Haruspex..."
    run_to "$GIT_TIMEOUT" git -C "$HARUSPEX_DIR" pull --ff-only --quiet 2>/dev/null \
        || warn "Haruspex update failed — pull manually in $HARUSPEX_DIR"
elif [ -d "$HARUSPEX_DIR" ]; then
    info "Haruspex dir exists (not a git clone) — leaving as-is"
else
    info "Cloning Haruspex (TyrusRC/haruspex)..."
    run_to "$GIT_TIMEOUT" git clone --depth 1 https://github.com/TyrusRC/haruspex.git "$HARUSPEX_DIR" >/dev/null 2>&1 \
        || warn "Haruspex clone failed — clone manually: git clone https://github.com/TyrusRC/haruspex.git \"$HARUSPEX_DIR\""
fi
if [ -d "$HARUSPEX_DIR" ] && [ -f "$HARUSPEX_DIR/pyproject.toml" ]; then
    (cd "$HARUSPEX_DIR" && uv venv 2>/dev/null || true && uv pip install -e . 2>&1 | tail -1)
    if (cd "$HARUSPEX_DIR" && uv run python -c "import haruspex" 2>/dev/null); then
        ok "Haruspex installed"
        mkdir -p "$HARUSPEX_DIR/runs"

        # Download pre-trained adapters from HuggingFace (skip existing).
        HARUSPEX_DOWNLOADED=0
        HARUSPEX_SKIPPED=0
        HARUSPEX_FAILED=0
        for domain in $HARUSPEX_DOMAINS; do
            adapter_dir="$HARUSPEX_DIR/runs/$domain"
            prefix=$(_hx_prefix "$domain")
            # Require the adapter AND its calibrator — Haruspex must never serve a
            # bare/uncalibrated model (no accept/abstain risk control). On a plain
            # run a present+calibrated adapter is kept; `--update` forces a
            # re-download so a newer trained adapter on HF replaces the local one.
            had_adapter=0
            [ -f "$adapter_dir/final/adapter_model.safetensors" ] && had_adapter=1
            if [ "$FORCE_UPDATE" = 0 ] && [ "$had_adapter" = 1 ] && [ -f "$adapter_dir/calibrator.json" ]; then
                HARUSPEX_SKIPPED=$((HARUSPEX_SKIPPED + 1))
            else
                [ "$had_adapter" = 1 ] && info "Refreshing Haruspex adapter: $domain..." \
                    || info "Downloading Haruspex adapter: $domain (~30MB)..."
                mkdir -p "$adapter_dir/final"
                hx_ok=0
                if has hf; then
                    # hf CLI: fetch adapter + calibrator + novelty gate. web = repo root
                    # (no subfolder); other domains are same-repo subfolders.
                    if [ "$domain" = "web" ]; then
                        run_to "$HF_TIMEOUT" hf download "$HARUSPEX_HF_REPO" --include "final/**" "calibrator.json" "ood.json" "ood_train.npy" "haruspex.json" \
                            --local-dir "$adapter_dir" --quiet 2>/dev/null && hx_ok=1
                    else
                        run_to "$HF_TIMEOUT" hf download "$HARUSPEX_HF_REPO" --include "$domain/**" \
                            --local-dir "$HARUSPEX_DIR/runs" --quiet 2>/dev/null && hx_ok=1
                    fi
                else
                    # Fallback: curl from the HuggingFace CDN (no hf CLI needed).
                    # $DL_FLAGS bounds each transfer so a stalled CDN socket cannot hang setup.
                    info "hf CLI not found — downloading $domain via curl..."
                    HF_RES="https://huggingface.co/$HARUSPEX_HF_REPO/resolve/main/${prefix}"
                    curl -sL $DL_FLAGS -o "$adapter_dir/final/adapter_model.safetensors" "${HF_RES}final/adapter_model.safetensors" 2>/dev/null
                    curl -sL $DL_FLAGS -o "$adapter_dir/final/adapter_config.json"       "${HF_RES}final/adapter_config.json" 2>/dev/null
                    # Metadata + calibrator + novelty gate (calibrator is required to serve).
                    curl -sL $DL_FLAGS -o "$adapter_dir/haruspex.json"   "${HF_RES}haruspex.json"   2>/dev/null || true
                    curl -sL $DL_FLAGS -o "$adapter_dir/calibrator.json" "${HF_RES}calibrator.json" 2>/dev/null || true
                    curl -sL $DL_FLAGS -o "$adapter_dir/ood.json"        "${HF_RES}ood.json"        2>/dev/null || true
                    curl -sL $DL_FLAGS -o "$adapter_dir/ood_train.npy"   "${HF_RES}ood_train.npy"   2>/dev/null || true
                    [ -s "$adapter_dir/final/adapter_model.safetensors" ] && hx_ok=1
                fi
                if [ "$hx_ok" = 1 ] && [ -f "$adapter_dir/final/adapter_model.safetensors" ]; then
                    HARUSPEX_DOWNLOADED=$((HARUSPEX_DOWNLOADED + 1))
                else
                    # Only remove a partial NEW download — never destroy a working
                    # adapter because a --update refresh failed to reach HF.
                    [ "$had_adapter" = 0 ] && rm -rf "$adapter_dir"
                    HARUSPEX_FAILED=$((HARUSPEX_FAILED + 1))
                fi
            fi
        done
        [ $HARUSPEX_SKIPPED -gt 0 ] && ok "Haruspex: $HARUSPEX_SKIPPED adapters already present (kept)"
        [ $HARUSPEX_DOWNLOADED -gt 0 ] && ok "Haruspex: $HARUSPEX_DOWNLOADED adapters downloaded"
        [ $HARUSPEX_FAILED -gt 0 ] && warn "Haruspex: $HARUSPEX_FAILED adapters failed — download manually or train locally"

        # Build the --adapters arg: only domains with BOTH an adapter and a calibrator
        # (a model without its calibrator would serve verdicts with no risk control).
        HARUSPEX_ADAPTERS=""
        HARUSPEX_UNCAL=""
        for domain in $HARUSPEX_DOMAINS; do
            d="$HARUSPEX_DIR/runs/$domain"
            if [ -f "$d/final/adapter_model.safetensors" ]; then
                if [ -f "$d/calibrator.json" ]; then
                    [ -n "$HARUSPEX_ADAPTERS" ] && HARUSPEX_ADAPTERS="$HARUSPEX_ADAPTERS,"
                    HARUSPEX_ADAPTERS="${HARUSPEX_ADAPTERS}${domain}=$d"
                else
                    HARUSPEX_UNCAL="$HARUSPEX_UNCAL $domain"
                fi
            fi
        done
        [ -n "$HARUSPEX_UNCAL" ] && warn "Haruspex: skipping uncalibrated adapters (no calibrator.json):$HARUSPEX_UNCAL"

        # Set PRAETOR_DECISION_BASE_URL in .env if not already present
        PRAETOR_ENV="$SCRIPT_DIR/.env"
        if ! grep -q "PRAETOR_DECISION_BASE_URL" "$PRAETOR_ENV" 2>/dev/null; then
            echo "PRAETOR_DECISION_BASE_URL=http://127.0.0.1:3000" >> "$PRAETOR_ENV"
            ok "Added PRAETOR_DECISION_BASE_URL=http://127.0.0.1:3000 to .env"
        else
            ok "PRAETOR_DECISION_BASE_URL already in .env"
        fi

        if [ -n "$HARUSPEX_ADAPTERS" ]; then
            ok "Haruspex ready — start with:"
            echo "    cd $HARUSPEX_DIR && uv run python -m haruspex.serve --port 3000 --default-domain web --adapters $HARUSPEX_ADAPTERS"
        else
            warn "No calibrated adapters available — download: hf download $HARUSPEX_HF_REPO --local-dir $HARUSPEX_DIR/runs"
            warn "Or train locally: cd $HARUSPEX_DIR && uv run python -m haruspex.train --train data/security_train.jsonl --out runs/web"
        fi
    else
        warn "Haruspex install failed — install manually: cd $HARUSPEX_DIR && uv venv && uv pip install -e ."
    fi
fi
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

# Playwright browser binary — CloakBrowser drives Chromium through Playwright, and
# the pip package ships NO browser; `playwright install chromium` fetches it. Skipped
# by a plain pip install, so the browser_* surface is dead until this runs (the macOS
# blocker). Idempotent — a no-op once the browser is cached.
info "Installing Playwright Chromium (browser_* tools)..."
if uv run playwright install chromium >/dev/null 2>&1; then
    ok "Playwright Chromium ready"
else
    warn "playwright install chromium failed — run it manually: (cd mcp-server && uv run playwright install chromium)"
fi

# chrome-devtools-mcp — the VISIBLE co-pilot Chrome lane (OAuth / account / login
# flows + observed testing). Node MCP server; the .mcp.json `chrome-devtools`
# entry attaches to a real Chrome on :9222. Install it globally so npx does not
# re-fetch it every launch, and make sure a real Chrome/Chromium exists for it to
# drive. Launch that Chrome with scripts/launch-test-chrome.sh (persistent profile
# -> logins survive; routed through Burp -> traffic captured).
if has npm; then
    info "Installing chrome-devtools-mcp (visible co-pilot browser lane)..."
    if run_to "$GIT_TIMEOUT" npm i -g chrome-devtools-mcp@latest >/dev/null 2>&1; then
        ok "chrome-devtools-mcp ready"
    else
        warn "chrome-devtools-mcp install failed — .mcp.json still fetches it via npx on first use"
    fi
else
    warn "chrome-devtools-mcp not installed — needs npm (Node.js >= 20); .mcp.json falls back to npx"
fi
if has google-chrome || has google-chrome-stable || has chromium || has chromium-browser; then
    ok "Real Chrome/Chromium present for the co-pilot lane"
else
    warn "No Chrome/Chromium for the co-pilot lane — install one: sudo apt install -y chromium"
fi

