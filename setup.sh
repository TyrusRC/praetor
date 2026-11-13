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
#
# This file is a thin orchestrator. The actual work is split across
# scripts/setup/ (shared helpers + one file per phase) — each `source`d in
# order so they share this shell's variables/functions with no re-export
# needed. Edit the phase file for the thing you're changing, not this file.
#   scripts/setup/lib.sh                 shared helpers + preflight
#   scripts/setup/phase1-dependencies.sh Java/Maven/Python/uv/Go
#   scripts/setup/phase2-build.sh        build extension + expedition + MCP server
#   scripts/setup/phase3-recon-tools.sh  web/network/mobile tool install (+ optional Ghostwriter/BloodHound CE)
#   scripts/setup/phase4-finish.sh       .mcp.json + settings.local.json + summary

set -euo pipefail

# SCRIPT_DIR must be computed HERE, not in a sourced phase file:
# ${BASH_SOURCE[0]} inside a sourced script resolves to THAT script's own
# path, not this orchestrator's, which would point every phase at
# scripts/setup/ instead of the repo root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_DIR="$SCRIPT_DIR/scripts/setup"

source "$SETUP_DIR/lib.sh"
source "$SETUP_DIR/phase1-dependencies.sh"
source "$SETUP_DIR/phase2-build.sh"
source "$SETUP_DIR/phase3-recon-tools.sh"
source "$SETUP_DIR/phase4-finish.sh"
