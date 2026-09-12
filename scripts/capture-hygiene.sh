#!/usr/bin/env bash
# Session-start capture hygiene: POST the same body set_capture_hygiene() sends to
# the Praetor Burp extension, so the HTTP-history view is filtered to in-scope-only
# and static/media + tracker hosts are excluded from the very first request of a
# session — before the model runs Phase 0.
#
# Fails GRACEFULLY when Burp isn't running (port 8111 closed): fast timeout, always
# exit 0, no stderr noise. A SessionStart hook must never block or fail startup.
#
# SOURCE OF TRUTH for the default lists below:
#   mcp-server/src/praetor/tools/proxy_control/_config.py
#     (_DEFAULT_STATIC_EXTS / _DEFAULT_NOISE_HOSTS)
# The Java handler defaults the three booleans to true but leaves the lists EMPTY
# when omitted, so they are sent explicitly here. Keep the two in sync on change.
set -u

ENDPOINT="http://127.0.0.1:8111/api/proxy/capture-hygiene"

read -r -d '' BODY <<'JSON' || true
{
  "record_in_scope_only": true,
  "exclude_static": true,
  "exclude_noise": true,
  "static_extensions": ["js","mjs","css","map","png","jpg","jpeg","gif","svg","ico","webp","avif","bmp","woff","woff2","ttf","eot","otf","mp4","webm","mp3","wav","ogg","pdf","wasm"],
  "noise_hosts": ["google-analytics.com","analytics.google.com","googletagmanager.com","doubleclick.net","google-analytics.l.google.com","stats.g.doubleclick.net","connect.facebook.net","facebook.com","fbcdn.net","hotjar.com","mixpanel.com","segment.com","segment.io","sentry.io","bugsnag.com","newrelic.com","nr-data.net","cloudflareinsights.com","gstatic.com","fonts.googleapis.com","fonts.gstatic.com","clarity.ms","bing.com"]
}
JSON

curl -sS -o /dev/null \
  --connect-timeout 1 --max-time 4 \
  -X POST -H "Content-Type: application/json" \
  --data "$BODY" "$ENDPOINT" 2>/dev/null || true

exit 0
