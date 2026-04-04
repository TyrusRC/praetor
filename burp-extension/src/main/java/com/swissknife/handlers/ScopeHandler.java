package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

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
    private boolean autoFilterEnabled = false;

    private static final List<String> AUTO_FILTER_DOMAINS = List.of(
        // Trackers
        "google-analytics.com", "analytics.google.com", "mixpanel.com",
        "hotjar.com", "segment.io", "segment.com", "amplitude.com",
        "heap.io", "heapanalytics.com", "pendo.io",
        // Ad networks
        "googlesyndication.com", "doubleclick.net", "adroll.com",
        "criteo.com", "criteo.net", "amazon-adsystem.com", "adnxs.com",
        "adsrvr.org", "taboola.com", "outbrain.com",
        // CDN
        "cloudflare.com", "cdnjs.cloudflare.com", "fastly.net",
        "akamai.net", "akamaized.net", "cloudfront.net", "jsdelivr.net",
        "unpkg.com", "cdnjs.com",
        // Fonts
        "fonts.googleapis.com", "fonts.gstatic.com", "use.typekit.net",
        "use.fontawesome.com",
        // Social
        "connect.facebook.net", "platform.twitter.com",
        "platform.linkedin.com", "apis.google.com",
        // Analytics
        "googletagmanager.com", "tealiumiq.com", "tags.tiqcdn.com",
        "assets.adobedtm.com", "bat.bing.com",
        // Error tracking
        "sentry.io", "bugsnag.com", "browser-intake-datadoghq.com",
        "js-agent.newrelic.com", "bam.nr-data.net", "clarity.ms",
        "fullstory.com", "mouseflow.com", "crazyegg.com", "inspectlet.com",
        // Misc
        "recaptcha.net", "gstatic.com", "gravatar.com", "wp.com",
        "stats.wp.com", "pixel.wp.com", "cookielaw.org", "onetrust.com",
        "trustarc.com", "intercom.io", "intercomcdn.com", "pusher.com",
        "pusherapp.com", "stripe.com", "js.stripe.com",
        "maps.googleapis.com", "maps.gstatic.com"
    );

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
            "auto_filter_count", AUTO_FILTER_DOMAINS.size(),
            "in_scope_hosts", new ArrayList<>(inScopeHosts),
            "total_in_scope_urls", totalInScope
        ));
    }

    private void handleConfigure(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);

        // Parse options
        Boolean autoFilter = body.get("auto_filter") instanceof Boolean b ? b : true;
        Boolean replace = body.get("replace") instanceof Boolean b ? b : false;

        @SuppressWarnings("unchecked")
        List<String> includeList = body.get("include") instanceof List<?> list
            ? (List<String>) (List<?>) list : List.of();
        @SuppressWarnings("unchecked")
        List<String> excludeList = body.get("exclude") instanceof List<?> list
            ? (List<String>) (List<?>) list : List.of();

        // If replace mode, clear previously tracked rules
        if (replace) {
            includeRules.clear();
            excludeRules.clear();
            autoFilterEnabled = false;
        }

        int includedCount = 0;
        int excludedCount = 0;
        int autoFilteredCount = 0;

        // Process includes
        for (String pattern : includeList) {
            String url = normalizeToUrl(pattern);
            api.scope().includeInScope(url);
            includeRules.add(url);
            includedCount++;
        }

        // Process excludes
        for (String pattern : excludeList) {
            String url = normalizeToUrl(pattern);
            api.scope().excludeFromScope(url);
            excludeRules.add(url);
            excludedCount++;
        }

        // Auto-filter noise domains
        if (autoFilter) {
            autoFilterEnabled = true;
            for (String domain : AUTO_FILTER_DOMAINS) {
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
            "include_rules", new ArrayList<>(includeRules),
            "exclude_rules", new ArrayList<>(excludeRules),
            "auto_filter_enabled", autoFilterEnabled
        ));
    }

    /**
     * Normalizes a scope pattern to a URL suitable for the Montoya scope API.
     * - Already http/https: returned as-is
     * - Starts with *.: strip wildcard prefix, prepend https://
     * - Bare domain: prepend https://
     */
    private String normalizeToUrl(String pattern) {
        if (pattern.startsWith("http://") || pattern.startsWith("https://")) {
            return pattern;
        }
        if (pattern.startsWith("*.")) {
            return "https://" + pattern.substring(2);
        }
        return "https://" + pattern;
    }

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
