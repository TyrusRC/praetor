"""postMessage instrumentation JS + malicious probe payloads (data)."""

# 1. Wrap addEventListener so we know every 'message' handler
# 2. Return a list of {source: <handler-source>, has_origin_check: bool}
# Heuristics for "has origin check" — look for common idioms in handler src.
_INSTRUMENT_JS = r"""
(() => {
  const handlers = [];
  const origAdd = window.addEventListener;
  window.addEventListener = function(type, listener, opts) {
    if (type === 'message' && typeof listener === 'function') {
      let src = '';
      try { src = listener.toString(); } catch (_) {}
      const lower = src.toLowerCase();
      const has_origin_strict = (
        lower.includes('event.origin ===') ||
        lower.includes('event.origin !==') ||
        lower.includes('e.origin ===') ||
        lower.includes('e.origin !==') ||
        lower.includes('msg.origin ===') ||
        lower.includes('msg.origin !==')
      );
      const has_origin_loose = (
        lower.includes('.origin.includes') ||
        lower.includes('.origin.startswith') ||
        lower.includes('.origin.endswith') ||
        lower.includes('.origin.indexof') ||
        lower.includes('.origin.match')
      );
      const has_any_origin = lower.includes('.origin');
      handlers.push({
        source_excerpt: src.length > 800 ? src.slice(0, 800) + '...' : src,
        has_origin_strict,
        has_origin_loose,
        has_any_origin,
        length: src.length,
      });
    }
    return origAdd.apply(this, arguments);
  };

  // Re-trigger inline registration by reloading any deferred scripts
  // — not always feasible; user should call this BEFORE navigate.

  return JSON.stringify(handlers);
})()
""".strip()


# Read-after-navigation script — pull whatever handlers got registered
_READ_HANDLERS_JS = r"""
JSON.stringify((() => {
  // If we instrumented before navigate, handlers live in closure; otherwise
  // we have to enumerate via the browser-extension hook (not available here).
  // Best-effort: dump from the window-level array we stashed.
  try { return window.__praetor_pm_handlers__ || []; } catch (_) { return []; }
})())
""".strip()


# Probe: fire a crafted postMessage and observe whether the page reacted
# (DOM mutation, error, or new network call). Done from inside the page
# context — handler runs synchronously so we capture DOM-mutation count.
_PROBE_TEMPLATE = r"""
(() => {
  const before = document.documentElement.innerHTML.length;
  const errors = [];
  const orig_err = window.onerror;
  window.onerror = (m, _src, _ln, _col, _e) => { errors.push(String(m)); return false; };
  try {
    window.postMessage(__PAYLOAD__, '*');
  } catch (e) {
    errors.push(String(e));
  }
  // Allow handlers to run synchronously (postMessage is async — sleep)
  const after = document.documentElement.innerHTML.length;
  window.onerror = orig_err;
  return JSON.stringify({
    dom_delta: after - before,
    errors: errors,
  });
})()
""".strip()


# Canonical malicious payloads for handler analysis
_MALICIOUS_PAYLOADS = [
    {"type": "command", "value": "execute", "code": "alert(1)"},
    {"action": "navigate", "url": "https://attacker.example/"},
    {"setHTML": "<img src=x onerror=__praetor_canary__=1>"},
    {"eval": "window.__praetor_eval_canary__=1"},
    {"postMessage_chain": {"target": "parent", "msg": "rce"}},
]


