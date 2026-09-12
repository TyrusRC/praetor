package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.util.JsonUtil;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * GET  /api/scope              - get scope info and tracked rules
 * POST /api/scope/check        - check if URL is in scope: {"url": "..."}
 * POST /api/scope/add          - add URL to scope: {"url": "..."}
 * POST /api/scope/remove       - remove URL from scope: {"url": "..."}
 * POST /api/scope/configure    - bulk configure scope with auto-filter
 */
public class ScopeHandler extends BaseHandler {

    private final MontoyaApi api;
    private final List<String> includeRules = new CopyOnWriteArrayList<>();
    private final List<String> excludeRules = new CopyOnWriteArrayList<>();
    private volatile boolean autoFilterEnabled = false;

    // Volatile so the requireInScope read in BaseHandler sees writes from this handler.
    public static volatile String currentMode = "operator";

    // Cold-start: read .burp-intel/_scope_mode.json (the Python source of truth)
    // so a Burp restart doesn't silently downgrade a strict-mode engagement back
    // to operator. Failure here is non-fatal — keep the default and continue.
    static {
        reloadMode();
    }

    /**
     * Re-read the scope-mode state file and refresh {@link #currentMode}.
     * Package-private hook for tests (the static initializer cannot be re-run
     * once the class is loaded, so cold-start coverage uses this entry point).
     * Production callers should not invoke this directly — mode is owned by
     * {@code handleConfigure}.
     */
    static void reloadMode() {
        try {
            java.nio.file.Path stateFile = java.nio.file.Path.of(".burp-intel", "_scope_mode.json");
            if (java.nio.file.Files.isReadable(stateFile)) {
                String raw = java.nio.file.Files.readString(stateFile);
                Map<String, Object> obj = JsonUtil.parseObject(raw);
                Object m = obj.get("mode");
                if (m instanceof String s && ("operator".equals(s) || "strict".equals(s))) {
                    currentMode = s;
                }
            }
        } catch (Throwable ignored) {
            // Filesystem / parse / classloader issue — keep operator default.
        }
    }


    public ScopeHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if ("POST".equalsIgnoreCase(method)) {
            switch (path) {
                case "/api/scope/check" -> handleCheck(exchange);
                case "/api/scope/add" -> handleAddToScope(exchange);
                case "/api/scope/remove" -> handleRemoveFromScope(exchange);
                case "/api/scope/configure" -> handleConfigure(exchange);
                default -> sendError(exchange, 404, "Not found");
            }
        } else if (path.equals("/api/scope") && "GET".equalsIgnoreCase(method)) {
            handleGetScope(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    private void handleGetScope(HttpExchange exchange) throws Exception {
        // Collect in-scope hosts from sitemap for backwards compatibility
        var sitemapItems = api.siteMap().requestResponses();
        Set<String> inScopeHosts = new LinkedHashSet<>();
        int totalInScope = 0;

        for (var item : sitemapItems) {
            String url = item.request().url();
            if (api.scope().isInScope(url)) {
                try {
                    java.net.URI uri = new java.net.URI(url);
                    inScopeHosts.add(uri.getScheme() + "://" + uri.getHost()
                        + (uri.getPort() > 0 ? ":" + uri.getPort() : ""));
                } catch (Exception ignored) {}
                totalInScope++;
            }
        }

        sendJson(exchange, JsonUtil.object(
            "include_rules", new ArrayList<>(includeRules),
            "exclude_rules", new ArrayList<>(excludeRules),
            "auto_filter_enabled", autoFilterEnabled,
            "auto_filter_count", ScopeMatcher.AUTO_FILTER_DOMAINS.size(),
            "in_scope_hosts", new ArrayList<>(inScopeHosts),
            "total_in_scope_urls", totalInScope
        ));
    }

    private void handleConfigure(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);

        // Parse options
        Boolean autoFilter = body.get("auto_filter") instanceof Boolean b ? b : true;
        Boolean replace = body.get("replace") instanceof Boolean b ? b : false;

        // Scope-gate mode: "operator" (default, warn-and-log on OOS) or
        // "strict" (block OOS with 403). Surfaced in BaseHandler.requireInScope.
        String mode = body.get("mode") instanceof String s ? s : "operator";
        if (!"operator".equals(mode) && !"strict".equals(mode)) {
            sendError(exchange, 400, "mode must be operator|strict", "validation_failed",
                "Pass mode='operator' or mode='strict'.");
            return;
        }
        currentMode = mode;

        @SuppressWarnings("unchecked")
        List<String> includeList = body.get("include") instanceof List<?> list
            ? (List<String>) (List<?>) list : List.of();
        @SuppressWarnings("unchecked")
        List<String> excludeList = body.get("exclude") instanceof List<?> list
            ? (List<String>) (List<?>) list : List.of();

        // If replace mode, clear previously tracked rules. Engagement boundary
        // also drops the shared Collaborator client so payload IDs from the
        // previous target don't bleed into the new one's interaction polls.
        if (replace) {
            includeRules.clear();
            excludeRules.clear();
            autoFilterEnabled = false;
            com.praetor.collaborator.CollaboratorPool.reset();
        }

        int includedCount = 0;
        int excludedCount = 0;
        int autoFilteredCount = 0;

        // Process includes
        for (String pattern : includeList) {
            String url = ScopeMatcher.normalizeToUrl(pattern);
            api.scope().includeInScope(url);
            includeRules.add(url);
            includedCount++;
        }

        // Process excludes
        for (String pattern : excludeList) {
            String url = ScopeMatcher.normalizeToUrl(pattern);
            api.scope().excludeFromScope(url);
            excludeRules.add(url);
            excludedCount++;
        }

        // Per-domain whitelist that bypasses auto-filter. Use case: target's
        // own CDN subdomain, OAuth provider being tested (apis.google.com),
        // asset host serving sensitive JS bundles, or any cdn-pattern domain
        // that's explicitly in scope. Values are matched as substrings against
        // the auto-filter list.
        @SuppressWarnings("unchecked")
        List<String> keepInScopeRaw = body.get("keep_in_scope") instanceof List<?> list
            ? (List<String>) (List<?>) list : List.of();
        Set<String> keepInScope = new java.util.HashSet<>();
        for (String s : keepInScopeRaw) {
            if (s != null && !s.isEmpty()) keepInScope.add(s.toLowerCase().trim());
        }

        // Auto-filter noise domains
        int keptInScope = 0;
        if (autoFilter) {
            autoFilterEnabled = true;
            for (String domain : ScopeMatcher.AUTO_FILTER_DOMAINS) {
                // Skip if operator explicitly kept it in-scope. Match exactly
                // or on a domain-suffix boundary so a pattern like "cdn"
                // doesn't match every cdnjs.* / cdn-anything host. The
                // operator can still pass an explicit "cdn." or full domain
                // suffix when that's the intent.
                boolean keep = false;
                for (String pattern : keepInScope) {
                    if (ScopeMatcher.matchesDomainPattern(domain, pattern)) {
                        keep = true;
                        break;
                    }
                }
                if (keep) {
                    keptInScope++;
                    continue;
                }
                String httpsUrl = "https://" + domain;
                String httpUrl = "http://" + domain;
                api.scope().excludeFromScope(httpsUrl);
                api.scope().excludeFromScope(httpUrl);
                autoFilteredCount++;
            }
        }

        sendJson(exchange, JsonUtil.object(
            "status", "ok",
            "included", includedCount,
            "excluded", excludedCount,
            "auto_filtered", autoFilteredCount,
            "kept_in_scope", keptInScope,
            "include_rules", new ArrayList<>(includeRules),
            "exclude_rules", new ArrayList<>(excludeRules),
            "auto_filter_enabled", autoFilterEnabled,
            "mode", currentMode
        ));
    }

    /**
     * Match an auto-filter domain against an operator-supplied keep-in-scope
     * pattern using domain-suffix semantics. Avoids the bidirectional
     * substring match that previously matched "cdn" against every CDN host.
     *
     * Rules:
     *   - exact (case-insensitive) match
     *   - pattern matches as a host suffix on a label boundary
     *     ("apis.google.com" pattern matches "apis.google.com" only, not
     *     "evilapis.google.com"; "*.google.com" matches any subdomain)
     */

    private void handleAddToScope(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String url = (String) body.get("url");
        if (url == null || url.isEmpty()) {
            sendError(exchange, 400, "Missing 'url' field");
            return;
        }

        api.scope().includeInScope(url);
        sendJson(exchange, JsonUtil.object("status", "ok", "message", "Added to scope: " + url, "url", url));
    }

    private void handleRemoveFromScope(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String url = (String) body.get("url");
        if (url == null || url.isEmpty()) {
            sendError(exchange, 400, "Missing 'url' field");
            return;
        }

        api.scope().excludeFromScope(url);
        sendJson(exchange, JsonUtil.object("status", "ok", "message", "Removed from scope: " + url, "url", url));
    }

    private void handleCheck(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String url = (String) body.get("url");
        if (url == null || url.isEmpty()) {
            sendError(exchange, 400, "Missing 'url' field");
            return;
        }

        boolean inScope = api.scope().isInScope(url);
        sendJson(exchange, JsonUtil.object("url", url, "in_scope", inScope));
    }
}
