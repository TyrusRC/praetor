package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.util.JsonUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * POST /api/proxy/capture-hygiene — keep the .burp project lean at CAPTURE time.
 *
 * Burp's Montoya API cannot delete proxy history or scanner issues after the
 * fact, so the only real lever is to stop recording noise in the first place.
 * This handler:
 *   1. excludes static-asset URLs and known noise hosts from Burp scope
 *      (api.scope().excludeFromScope + advanced-scope regex), which also stops
 *      Praetor's own tools touching / annotating them;
 *   2. best-effort enables "record Proxy history only for in-scope items" via
 *      importProjectOptionsFromJson (unknown keys are ignored by Burp, so this
 *      is safe across versions — the operator toggle in the response is the
 *      fallback);
 *   3. exports the resulting proxy + target-scope options so the caller can
 *      verify what actually took effect.
 */
public class CaptureHygieneHandler extends BaseHandler {

    private final MontoyaApi api;

    public CaptureHygieneHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "POST only");
            return;
        }
        Map<String, Object> body = readJsonBody(exchange);

        boolean recordInScopeOnly = asBool(body.get("record_in_scope_only"), true);
        boolean excludeStatic = asBool(body.get("exclude_static"), true);
        boolean excludeNoise = asBool(body.get("exclude_noise"), true);
        List<String> staticExts = asStrings(body.get("static_extensions"));
        List<String> noiseHosts = asStrings(body.get("noise_hosts"));

        List<String> applied = new ArrayList<>();
        List<Map<String, Object>> excludeRules = new ArrayList<>();

        if (excludeNoise) {
            for (String host : noiseHosts) {
                String h = host.trim();
                if (h.isEmpty()) continue;
                try {
                    api.scope().excludeFromScope("https://" + h + "/");
                    api.scope().excludeFromScope("http://" + h + "/");
                } catch (RuntimeException ignore) { /* best effort */ }
                excludeRules.add(scopeRule("host", "^(.*\\.)?" + java.util.regex.Pattern.quote(h) + "$"));
            }
            applied.add("excluded " + noiseHosts.size() + " noise host(s) from scope");
        }

        if (excludeStatic && !staticExts.isEmpty()) {
            String alt = String.join("|", staticExts.stream().map(this::extToken).toList());
            excludeRules.add(scopeRule("file", "^.*\\.(" + alt + ")(\\?.*)?$"));
            applied.add("excluded static assets (" + staticExts.size() + " extensions) from scope");
        }

        String options = buildOptionsJson(recordInScopeOnly, excludeRules);
        boolean imported = false;
        String importErr = "";
        try {
            api.burpSuite().importProjectOptionsFromJson(options);
            imported = true;
            if (recordInScopeOnly) applied.add("requested record-Proxy-history-only-in-scope (verify toggle)");
        } catch (RuntimeException e) {
            importErr = e.getClass().getSimpleName() + ": " + e.getMessage();
        }

        String proxyOpts = "";
        try {
            proxyOpts = api.burpSuite().exportProjectOptionsAsJson("proxy");
            if (proxyOpts != null && proxyOpts.length() > 4000) proxyOpts = proxyOpts.substring(0, 4000) + "…";
        } catch (RuntimeException ignore) { /* older Burp */ }

        Map<String, Object> out = new java.util.LinkedHashMap<>();
        out.put("applied", applied);
        out.put("options_imported", imported);
        if (!importErr.isEmpty()) out.put("import_error", importErr);
        out.put("proxy_options_excerpt", proxyOpts);
        out.put("note", "Burp cannot delete existing history/issues — this only affects NEW capture. "
            + "If history still grows, enable Burp: Settings → Tools → Proxy → \"Don't send items to "
            + "Proxy history … if out of scope\" (one-time). Scanner issues from Burp's audit and other "
            + "extensions cannot be deleted via API — filter them with get_issues_dashboard (Certain/Firm, High+).");
        sendJson(exchange, JsonUtil.toJson(out));
    }

    private String buildOptionsJson(boolean recordInScopeOnly, List<Map<String, Object>> excludeRules) {
        // Hand-built to match Burp's project-options schema (JsonUtil has no
        // nested-builder sugar; a literal is clearest and stays under review).
        StringBuilder ex = new StringBuilder("[");
        for (int i = 0; i < excludeRules.size(); i++) {
            if (i > 0) ex.append(",");
            ex.append(JsonUtil.toJson(excludeRules.get(i)));
        }
        ex.append("]");
        return "{\"target\":{\"scope\":{\"advanced_mode\":true,\"exclude\":" + ex + "}},"
             + "\"proxy\":{\"http_history\":{\"record_only_in_scope\":" + recordInScopeOnly + "}}}";
    }

    private Map<String, Object> scopeRule(String field, String regex) {
        Map<String, Object> r = new java.util.LinkedHashMap<>();
        r.put("enabled", true);
        r.put(field, regex);
        r.put("protocol", "any");
        return r;
    }

    private String extToken(String e) {
        String t = e.trim();
        if (t.startsWith(".")) t = t.substring(1);
        return t.replaceAll("[^A-Za-z0-9]", "");
    }

    private boolean asBool(Object v, boolean dflt) {
        if (v instanceof Boolean b) return b;
        if (v instanceof String s) return "true".equalsIgnoreCase(s);
        return dflt;
    }

    @SuppressWarnings("unchecked")
    private List<String> asStrings(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof List<?> l) for (Object o : l) if (o != null) out.add(String.valueOf(o));
        return out;
    }
}
