package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * GET  /api/scope           - get scope info
 * POST /api/scope/check     - check if URL is in scope: {"url": "..."}
 * POST /api/scope/add       - add URL to scope: {"url": "..."}
 * POST /api/scope/remove    - remove URL from scope: {"url": "..."}
 */
public class ScopeHandler extends BaseHandler {

    private final MontoyaApi api;

    public ScopeHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();

        String method = exchange.getRequestMethod();

        if (path.equals("/api/scope/check") && "POST".equalsIgnoreCase(method)) {
            handleCheck(exchange);
        } else if (path.equals("/api/scope/add") && "POST".equalsIgnoreCase(method)) {
            handleAddToScope(exchange);
        } else if (path.equals("/api/scope/remove") && "POST".equalsIgnoreCase(method)) {
            handleRemoveFromScope(exchange);
        } else if (path.equals("/api/scope")) {
            handleGetScope(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    private void handleGetScope(HttpExchange exchange) throws Exception {
        // Get scope by checking sitemap URLs
        // Montoya API doesn't expose scope rules directly, but we can report
        // which known URLs are in scope
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
            "in_scope_hosts", new ArrayList<>(inScopeHosts),
            "total_in_scope_urls", totalInScope
        ));
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
