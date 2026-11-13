#!/usr/bin/env bash
# Phase 4: generate .mcp.json + .claude/settings.local.json, print the install summary and WSL notes.
# Sourced by ../../setup.sh in order — do not run this file directly, it has
# no shebang-level set -e/colors/has() of its own; those come from lib.sh.

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

# Resolve vigil to an ABSOLUTE path, same treatment as $VENV_PYTHON above.
# A bare "vigil" command relies on the MCP HOST process's own PATH at spawn
# time, not this script's — go install puts the binary in $BIN_DIR
# (~/go/bin), which setup.sh exports into ITS OWN shell (line ~290) but
# never persists to .bashrc/.profile. A host process started before that
# PATH was ever set (the common case: Claude Code already running when you
# run setup.sh) still has the old PATH and fails to spawn "vigil" with
# ENOENT. An absolute path removes the dependency on the host's PATH
# entirely — same reason $VENV_PYTHON is already absolute, not "python3".
VIGIL_BIN="$(command -v vigil 2>/dev/null || echo "$BIN_DIR/vigil")"

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
    },
    "vigil": {
      "command": "$VIGIL_BIN",
      "args": ["mcp"]
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
    },
    "vigil": {
      "command": "$VIGIL_BIN",
      "args": ["mcp"]
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
    # Idempotently add vigil (Praetor's web-scan engine) to an existing config
    # without touching anything the user has customised. Also repairs a
    # bare "vigil" command left by an older setup.sh into the absolute
    # path (the ENOENT-on-reconnect fix) without touching any other field
    # the user customised on that entry (e.g. --state-file).
    python3 - "$MCP_JSON" "$VIGIL_BIN" <<'PYEOF'
import json, sys
p, vigil_bin = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(p))
except Exception:
    sys.exit(0)  # not JSON we recognise — leave it alone
servers = d.setdefault("mcpServers", {})
changed = False
if "vigil" not in servers:
    servers["vigil"] = {"command": vigil_bin, "args": ["mcp"]}
    changed = True
    print("added vigil MCP server to existing .mcp.json")
elif servers["vigil"].get("command") == "vigil":
    servers["vigil"]["command"] = vigil_bin
    changed = True
    print(f"repaired vigil MCP server command to absolute path ({vigil_bin}) — "
          "a bare 'vigil' command fails with ENOENT when the MCP host's own "
          "PATH predates this install")
if changed:
    json.dump(d, open(p, "w"), indent=2)
PYEOF
fi

# Ensure Claude Code is allowed to start the project MCP servers: drop them from
# any disabledMcpjsonServers list and add them to enabledMcpjsonServers. Without
# this, a project MCP server can sit disabled and never connect.
SETTINGS_LOCAL="$SCRIPT_DIR/.claude/settings.local.json"
mkdir -p "$SCRIPT_DIR/.claude"
python3 - "$SETTINGS_LOCAL" <<'PYEOF'
import json, os, sys
p = sys.argv[1]
try:
    d = json.load(open(p)) if os.path.exists(p) else {}
except Exception:
    d = {}
want = ["praetor", "vigil"]
d["disabledMcpjsonServers"] = [s for s in d.get("disabledMcpjsonServers", []) if s not in want]
enabled = d.get("enabledMcpjsonServers", [])
for s in want:
    if s not in enabled:
        enabled.append(s)
d["enabledMcpjsonServers"] = enabled
json.dump(d, open(p, "w"), indent=2)
PYEOF
ok "praetor + vigil MCP servers enabled in .claude/settings.local.json"

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

# check_any <label> <bin>... — ✓ if ANY of the binaries is present. For tools
# whose executable name differs by install source (impacket: Debian
# `impacket-secretsdump` vs PyPI `secretsdump.py`).
check_any() {
    local label="$1"; shift
    local b
    for b in "$@"; do
        if has "$b"; then echo -e "  ${GREEN}✓${NC} $label"; return; fi
    done
    echo -e "  ${RED}✗${NC} $label (not found)"
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
check groma
check gowitness
check osv-scanner
check trivy
check grype
check syft
check garak
check snyk-agent-scan
check prowler
check checkov
check kubescape
echo "  (run ./doctor.sh for the full per-tool inventory)"

echo ""
echo "Core red-team / network lane:"
check nmap
check nxc
check_any "impacket (secretsdump)" impacket-secretsdump secretsdump.py
check responder
check bloodhound-python
check_any "certipy" certipy certipy-ad
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

if [ -n "$EXP_JAR" ] && [ -f "$EXP_JAR" ]; then
    echo -e "  ${GREEN}✓${NC} burp-expedition JAR built (tcp_* lane)"
else
    echo -e "  ${YELLOW}○${NC} burp-expedition JAR not built (tcp_* lane — build: cd ../burp-expedition && ./gradlew shadowJar)"
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

if [ -d "$HARUSPEX_DIR" ] && (cd "$HARUSPEX_DIR" && uv run python -c "import haruspex" 2>/dev/null); then
    HARUSPEX_ADAPTER_COUNT=$(find "$HARUSPEX_DIR/runs" -name "adapter_model.safetensors" 2>/dev/null | wc -l)
    if [ "$HARUSPEX_ADAPTER_COUNT" -gt 0 ]; then
        echo -e "  ${GREEN}✓${NC} Haruspex installed + ${HARUSPEX_ADAPTER_COUNT} domain adapters trained (~$((HARUSPEX_ADAPTER_COUNT * 30))MB)"
    else
        echo -e "  ${YELLOW}○${NC} Haruspex installed (no adapters — rerun setup or: cd ../haruspex && uv run python -m haruspex.train --train data/security_train.jsonl --out runs/security)"
    fi
    if grep -q "PRAETOR_DECISION_BASE_URL" "$SCRIPT_DIR/.env" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} PRAETOR_DECISION_BASE_URL configured in .env"
    else
        echo -e "  ${YELLOW}○${NC} PRAETOR_DECISION_BASE_URL not in .env — add: PRAETOR_DECISION_BASE_URL=http://127.0.0.1:3000"
    fi
else
    echo -e "  ${YELLOW}○${NC} Haruspex not installed (decision engine runs in deterministic/off mode)"
fi

echo ""
echo "Next steps:"
echo "  1. Open Burp Suite"
echo "  2. Extensions → Add → Java → Select: $JAR_PATH"
if [ -n "$EXP_JAR" ] && [ -f "$EXP_JAR" ]; then
    echo "     Add the second extension the same way → Select: $EXP_JAR"
    echo "     (burp-expedition — the tcp_* non-HTTP lane, Control API on :18112)"
    echo "     NOTE: the Control API is OPT-IN — start Burp with EXPEDITION_API_ENABLE=1"
    echo "           in its environment, or the tcp_* tools get connection-refused on :18112."
    echo "           (EXPEDITION_API_DISABLE=1 force-disables; EXPEDITION_API_PORT overrides.)"
fi
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
