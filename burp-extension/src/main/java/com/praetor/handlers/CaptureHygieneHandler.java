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

        String options = buildOptionsJson(recordInScopeOnly, excludeStatic, staticExts, excludeRules);
        boolean imported = false;
        String importErr = "";
        try {
            api.burpSuite().importProjectOptionsFromJson(options);
            imported = true;
            if (recordInScopeOnly) applied.add("HTTP-history view filtered to in-scope-only (display filter)");
            if (excludeStatic) applied.add("HTTP-history view hides static-asset extensions + images/css");
        } catch (RuntimeException e) {
            importErr = e.getClass().getSimpleName() + ": " + e.getMessage();
        }

        String proxyOpts = "";
        try {
            proxyOpts = api.burpSuite().exportProjectOptionsAsJson("proxy.http_history_display_filter");
            if (proxyOpts != null && proxyOpts.length() > 3000) proxyOpts = proxyOpts.substring(0, 3000) + "…";
        } catch (RuntimeException ignore) { /* older Burp */ }

        Map<String, Object> out = new java.util.LinkedHashMap<>();
        out.put("applied", applied);
        out.put("options_imported", imported);
        if (!importErr.isEmpty()) out.put("import_error", importErr);
        out.put("history_display_filter", proxyOpts);
        out.put("note", "Two different problems: (1) NOISE — this sets Burp's HTTP-history DISPLAY "
            + "filter to show only in-scope items and hide static/media, so the view is clean (verify "
            + "the excerpt: by_request_type.show_only_in_scope_items should be true). (2) FILE SIZE — "
            + "Burp still RECORDS all proxied traffic to the project regardless of the display filter, and "
            + "Montoya cannot delete it; shrink the .burp file with snapshot_and_rotate (export signal, "
            + "start a fresh project). Scanner issues from Burp's audit + other extensions can't be "
            + "deleted via API — filter with get_issues_dashboard (Certain/Firm, High+).");
        sendJson(exchange, JsonUtil.toJson(out));
    }

    private String buildOptionsJson(boolean inScopeOnly, boolean hideStatic,
                                    List<String> staticExts, List<Map<String, Object>> excludeRules) {
        // Real keys confirmed from a live Burp exportProjectOptionsAsJson("proxy"):
        // proxy.http_history_display_filter controls the HTTP-history VIEW; the
        // target.scope.exclude entries also keep Praetor's own tools off the noise.
        StringBuilder ex = new StringBuilder("[");
        for (int i = 0; i < excludeRules.size(); i++) {
            if (i > 0) ex.append(",");
            ex.append(JsonUtil.toJson(excludeRules.get(i)));
        }
        ex.append("]");

        String extFilter = "";
        if (hideStatic && !staticExts.isEmpty()) {
            StringBuilder hide = new StringBuilder("[");
            for (int i = 0; i < staticExts.size(); i++) {
                if (i > 0) hide.append(",");
                hide.append("\"").append(extToken(staticExts.get(i))).append("\"");
            }
            hide.append("]");
            extFilter = "\"by_file_extension\":{\"hide_specific\":true,\"hide_items\":" + hide + "},"
                      + "\"by_mime_type\":{\"show_images\":false,\"show_css\":false},";
        }

        String displayFilter = "\"http_history_display_filter\":{"
            + "\"filter_disabled\":false,\"filter_mode\":\"SETTINGS\","
            + extFilter
            + "\"by_request_type\":{\"show_only_in_scope_items\":" + inScopeOnly + "}}";

        return "{\"target\":{\"scope\":{\"advanced_mode\":true,\"exclude\":" + ex + "}},"
             + "\"proxy\":{" + displayFilter + "}}";
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
