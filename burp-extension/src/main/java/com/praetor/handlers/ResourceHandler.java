package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.util.JsonUtil;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * GET  /api/resources?url_prefix=...&type=js|css|all  — list static resources from proxy history
 * POST /api/resources/fetch                           — fetch a specific resource URL through Burp
 * POST /api/resources/fetch-page                      — fetch all static resources linked from a page
 */
public class ResourceHandler extends BaseHandler {

    private final MontoyaApi api;

    static final int MAX_RESOURCE_SIZE = com.praetor.server.ResponseLimits.MAX_RESOURCE_BODY;

    static final Set<String> JS_EXTENSIONS = Set.of(".js", ".mjs", ".jsx", ".ts", ".tsx");
    static final Set<String> CSS_EXTENSIONS = Set.of(".css");
    static final Set<String> MAP_EXTENSIONS = Set.of(".js.map", ".css.map", ".map");
    static final Set<String> CSS_MIME_TYPES = Set.of("text/css");

    static final Pattern SOURCEMAP_PATTERN = Pattern.compile(
            "//[#@]\\s*sourceMappingURL=([^\\s]+)", Pattern.CASE_INSENSITIVE);

    public ResourceHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if ("GET".equalsIgnoreCase(method) && path.equals("/api/resources")) {
            handleList(exchange);
            return;
        }

        if ("POST".equalsIgnoreCase(method)) {
            Map<String, Object> body = readJsonBody(exchange);
            switch (path) {
                case "/api/resources/fetch" -> handleFetch(exchange, body);
                case "/api/resources/fetch-page" -> handleFetchPage(exchange, body);
                default -> sendError(exchange, 404, "Not found");
            }
            return;
        }

        sendError(exchange, method.equals("GET") ? 404 : 405,
                method.equals("GET") ? "Not found" : "Method not allowed");
    }

    // ── List static resources from proxy history ──────────────────

    private void handleList(HttpExchange exchange) throws Exception {
        Map<String, String> params = queryParams(exchange);
        String urlPrefix = params.getOrDefault("url_prefix", "");
        String type = params.getOrDefault("type", "all").toLowerCase();
        int limit = intParam(params, "limit", 200);

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        List<Map<String, Object>> items = new ArrayList<>();

        for (int i = history.size() - 1; i >= 0 && items.size() < limit; i--) {
            ProxyHttpRequestResponse item = history.get(i);
            HttpRequest req = item.finalRequest();
            HttpResponse resp = item.originalResponse();
            String url = req.url();

            if (!urlPrefix.isEmpty() && !url.startsWith(urlPrefix)) continue;

            String resourceType = ResourceFetcher.classifyResource(url, resp);
            if (resourceType == null) continue;
            if (!"all".equals(type) && !type.equals(resourceType)) continue;

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("index", i);
            entry.put("url", url);
            entry.put("type", resourceType);
            entry.put("size", resp != null ? resp.body().length() : 0);
            entry.put("status_code", resp != null ? resp.statusCode() : 0);
            items.add(entry);
        }

        sendJson(exchange, JsonUtil.object(
                "total", items.size(),
                "url_prefix", urlPrefix,
                "type_filter", type,
                "items", items
        ));
    }

    // ── Fetch a specific resource URL ─────────────────────────────

    private void handleFetch(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String url = (String) body.get("url");
        if (url == null || url.isEmpty()) {
            sendError(exchange, 400, "Missing 'url'");
            return;
        }

        if (!requireInScope(api, exchange, url)) return;

        // Check proxy history first
        String content = ResourceFetcher.findInHistory(api, url);
        if (content != null) {
            sendResourceResponse(exchange, url, content, "proxy_history");
            return;
        }

        // Fetch through Burp
        HttpRequestResponse result = ResourceFetcher.fetchUrl(api, url);
        if (result == null || result.response() == null) {
            String why = com.praetor.http.ProxyTunnel.lastSendError();
            sendError(exchange, 502,
                "Failed to fetch resource: " + url + (why.isEmpty() ? "" : " — " + why),
                "send_failed",
                "Verify the URL is reachable from Burp's host.");
            return;
        }

        String respBody = result.response().bodyToString();
        sendResourceResponse(exchange, url, respBody, "fetched");
    }

    // ── Fetch all static resources from a page ────────────────────

    private void handleFetchPage(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String pageBody;
        String pageUrl;

        // Get page by index or URL
        Object indexObj = body.get("index");
        String urlStr = (String) body.get("url");

        if (indexObj instanceof Number n) {
            int index = n.intValue();
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            if (index < 0 || index >= history.size()) {
                sendError(exchange, 404, "Index out of range");
                return;
            }
            ProxyHttpRequestResponse item = history.get(index);
            HttpResponse resp = item.originalResponse();
            if (resp == null) {
                sendError(exchange, 400, "No response available for index " + index);
                return;
            }
            pageBody = resp.bodyToString();
            pageUrl = item.finalRequest().url();
        } else if (urlStr != null && !urlStr.isEmpty()) {
            if (!requireInScope(api, exchange, urlStr)) return;

            // Try history first, then fetch
            String fromHistory = ResourceFetcher.findInHistory(api, urlStr);
            if (fromHistory != null) {
                pageBody = fromHistory;
                pageUrl = urlStr;
            } else {
                HttpRequestResponse result = ResourceFetcher.fetchUrl(api, urlStr);
                if (result == null || result.response() == null) {
                    sendError(exchange, 502, "Failed to fetch page: " + urlStr);
                    return;
                }
                pageBody = result.response().bodyToString();
                pageUrl = urlStr;
            }
        } else {
            sendError(exchange, 400, "Missing 'index' or 'url'");
            return;
        }

        // Extract resource URLs from HTML
        Set<String> resourceUrls = ResourceFetcher.extractResourceUrls(pageBody, pageUrl);

        // Also look for source maps in JS/CSS bodies
        Set<String> sourceMapUrls = new LinkedHashSet<>();

        List<Map<String, Object>> resources = new ArrayList<>();
        for (String resUrl : resourceUrls) {
            // Check history first
            String content = ResourceFetcher.findInHistory(api, resUrl);
            String source;
            if (content != null) {
                source = "proxy_history";
            } else {
                // Scope gate (Rule 1 HARD). Static-resource sweep can pull
                // hundreds of CDN URLs; out-of-scope ones are recorded with
                // an explicit marker rather than 403-ing the whole batch.
                if (!isInScopeQuiet(api, resUrl)) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("url", resUrl);
                    entry.put("error", "out_of_scope");
                    resources.add(entry);
                    continue;
                }
                // Fetch through Burp
                HttpRequestResponse result = ResourceFetcher.fetchUrl(api, resUrl);
                if (result == null || result.response() == null) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("url", resUrl);
                    entry.put("error", "Failed to fetch");
                    resources.add(entry);
                    continue;
                }
                content = result.response().bodyToString();
                source = "fetched";
            }

            // Check for source map references in JS/CSS
            Matcher mapMatcher = SOURCEMAP_PATTERN.matcher(content);
            if (mapMatcher.find()) {
                String mapRef = mapMatcher.group(1);
                String mapUrl = ResourceFetcher.resolveUrl(mapRef, resUrl);
                if (mapUrl != null) {
                    sourceMapUrls.add(mapUrl);
                }
            }

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("url", resUrl);
            entry.put("type", ResourceFetcher.classifyByUrl(resUrl));
            entry.put("source", source);
            entry.put("size", content.length());
            if (content.length() > MAX_RESOURCE_SIZE) {
                content = content.substring(0, MAX_RESOURCE_SIZE)
                        + "\n\n[... TRUNCATED at " + MAX_RESOURCE_SIZE + " chars, total: " + content.length() + " ...]";
            }
            entry.put("content", content);
            resources.add(entry);
        }

        // Fetch source maps
        for (String mapUrl : sourceMapUrls) {
            if (resourceUrls.contains(mapUrl)) continue;

            String content = ResourceFetcher.findInHistory(api, mapUrl);
            String source;
            if (content != null) {
                source = "proxy_history";
            } else {
                if (!isInScopeQuiet(api, mapUrl)) continue;
                HttpRequestResponse result = ResourceFetcher.fetchUrl(api, mapUrl);
                if (result == null || result.response() == null) continue;
                content = result.response().bodyToString();
                source = "fetched";
            }

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("url", mapUrl);
            entry.put("type", "sourcemap");
            entry.put("source", source);
            entry.put("size", content.length());
            if (content.length() > MAX_RESOURCE_SIZE) {
                content = content.substring(0, MAX_RESOURCE_SIZE)
                        + "\n\n[... TRUNCATED at " + MAX_RESOURCE_SIZE + " chars, total: " + content.length() + " ...]";
            }
            entry.put("content", content);
            resources.add(entry);
        }

        sendJson(exchange, JsonUtil.object(
                "page_url", pageUrl,
                "total_resources", resources.size(),
                "resources", resources
        ));
    }

    // ── Classification helpers ────────────────────────────────────

    /**
     * Classify a proxy history entry as js, css, sourcemap, or null (not a static resource).
     */
    private void sendResourceResponse(HttpExchange exchange, String url, String content, String source) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("url", url);
        result.put("source", source);
        result.put("size", content.length());
        if (content.length() > MAX_RESOURCE_SIZE) {
            content = content.substring(0, MAX_RESOURCE_SIZE)
                    + "\n\n[... TRUNCATED at " + MAX_RESOURCE_SIZE + " chars, total: " + content.length() + " ...]";
        }
        result.put("content", content);
        sendJson(exchange, JsonUtil.toJson(result));
    }
}
