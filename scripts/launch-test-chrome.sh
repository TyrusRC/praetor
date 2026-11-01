#!/usr/bin/env bash
# Launch the visible co-pilot Chrome that chrome-devtools-mcp attaches to.
#
# Why this script: the `chrome-devtools` MCP server in .mcp.json attaches to a
# Chrome on --browser-url=http://127.0.0.1:9222. It does NOT launch one. A Chrome
# started normally has no debug port, and a Chrome started with a throwaway
# --user-data-dir shows a FRESH profile every run — so OAuth / account logins
# must be redone each time. This launches ONE Chrome that fixes both:
#
#   * --remote-debugging-port=9222  -> chrome-devtools-mcp can attach
#   * --user-data-dir=<real profile> -> your logins PERSIST across runs
#   * --proxy-server=<Burp>          -> test traffic lands in Burp proxy history
#                                       (keeps the proxy_history_index evidence)
#
# Idempotent: if 9222 is already serving, it does nothing. The real profile is a
# singleton — quit any other Chrome on that profile first, or pass a different
# PRAETOR_TEST_CHROME_PROFILE.
#
# Env overrides:
#   PRAETOR_TEST_CHROME_PORT     (default 9222)
#   PRAETOR_TEST_CHROME_PROXY    (default http://127.0.0.1:8080 — Burp)
#   PRAETOR_TEST_CHROME_PROFILE  (default: your real Chrome/Chromium profile)
#   PRAETOR_TEST_CHROME_BIN      (default: first chrome/chromium found)
# Flags:
#   --insecure   add --ignore-certificate-errors (use only if Burp's CA is NOT
#                imported into this profile; prefer importing the CA)
#   -h|--help    this help
set -euo pipefail

PORT="${PRAETOR_TEST_CHROME_PORT:-9222}"
PROXY="${PRAETOR_TEST_CHROME_PROXY:-http://127.0.0.1:8080}"
INSECURE=0
for a in "$@"; do
  case "$a" in
    --insecure) INSECURE=1 ;;
    -h|--help) sed -n '2,33p' "$0"; exit 0 ;;
    *) echo "unknown arg: $a (see --help)" >&2; exit 2 ;;
  esac
done

# Already up? Do nothing — attach to what is there.
if ss -ltn 2>/dev/null | grep -qE "[:.]${PORT}\b"; then
  echo "Chrome debug port ${PORT} already serving — chrome-devtools-mcp can attach. Nothing to do."
  exit 0
fi

# Find a Chrome/Chromium binary.
BIN="${PRAETOR_TEST_CHROME_BIN:-}"
if [ -z "$BIN" ]; then
  for c in google-chrome google-chrome-stable chromium chromium-browser chrome; do
    if command -v "$c" >/dev/null 2>&1; then BIN="$(command -v "$c")"; break; fi
  done
fi
if [ -z "$BIN" ]; then
  echo "No Chrome/Chromium found. Install one (e.g. sudo apt install chromium) or set PRAETOR_TEST_CHROME_BIN." >&2
  exit 1
fi

# Default to the REAL profile for that binary family, so existing logins are present.
PROFILE="${PRAETOR_TEST_CHROME_PROFILE:-}"
if [ -z "$PROFILE" ]; then
  case "$BIN" in
    *chromium*) PROFILE="$HOME/.config/chromium" ;;
    *)          PROFILE="$HOME/.config/google-chrome" ;;
  esac
fi
mkdir -p "$PROFILE"

ARGS=(
  --remote-debugging-port="$PORT"
  --remote-debugging-address=127.0.0.1
  --user-data-dir="$PROFILE"
  --proxy-server="$PROXY"
  --no-first-run
  --no-default-browser-check
)
[ "$INSECURE" = 1 ] && ARGS+=(--ignore-certificate-errors)

echo "Launching ${BIN##*/}"
echo "  profile : $PROFILE   (logins persist here)"
echo "  proxy   : $PROXY     (Burp — test traffic is captured)"
echo "  debug   : 127.0.0.1:$PORT   (chrome-devtools-mcp attaches)"
[ "$INSECURE" = 1 ] && echo "  TLS     : --ignore-certificate-errors (import Burp's CA to drop this)"
echo "If a window does not appear, quit any other Chrome on this profile first."

exec "$BIN" "${ARGS[@]}" >/dev/null 2>&1
