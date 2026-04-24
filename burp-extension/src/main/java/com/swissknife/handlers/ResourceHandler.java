package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

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

    private static final int MAX_RESOURCE_SIZE = 50000;

    private static final Set<String> JS_EXTENSIONS = Set.of(".js", ".mjs", ".jsx", ".ts", ".tsx");
    private static final Set<String> CSS_EXTENSIONS = Set.of(".css");
    private static final Set<String> MAP_EXTENSIONS = Set.of(".js.map", ".css.map", ".map");
    private static final Set<String> JS_MIME_TYPES = Set.of(
            "application/javascript", "application/x-javascript", "text/javascript",
            "application/ecmascript", "text/ecmascript"
    );
    private static final Set<String> CSS_MIME_TYPES = Set.of("text/css");

    private static final Pattern SCRIPT_SRC_PATTERN = Pattern.compile(
            "<script[^>]+src=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern LINK_HREF_PATTERN = Pattern.compile(
            "<link[^>]+rel=[\"']stylesheet[\"'][^>]+href=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern LINK_HREF_ALT_PATTERN = Pattern.compile(
            "<link[^>]+href=[\"']([^\"']+)[\"'][^>]+rel=[\"']stylesheet[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern SOURCEMAP_PATTERN = Pattern.compile(
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

            String resourceType = classifyResource(url, resp);
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

        // Check proxy history first
        String content = findInHistory(url);
        if (content != null) {
            sendResourceResponse(exchange, url, content, "proxy_history");
            return;
        }

        // Fetch through Burp
        HttpRequestResponse result = fetchUrl(url);
        if (result == null || result.response() == null) {
            sendError(exchange, 502, "Failed to fetch resource: " + url);
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
            // Try history first, then fetch
            String fromHistory = findInHistory(urlStr);
            if (fromHistory != null) {
                pageBody = fromHistory;
                pageUrl = urlStr;
            } else {
                HttpRequestResponse result = fetchUrl(urlStr);
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
        Set<String> resourceUrls = extractResourceUrls(pageBody, pageUrl);

        // Also look for source maps in JS/CSS bodies
        Set<String> sourceMapUrls = new LinkedHashSet<>();

        List<Map<String, Object>> resources = new ArrayList<>();
        for (String resUrl : resourceUrls) {
            // Check history first
            String content = findInHistory(resUrl);
            String source;
            if (content != null) {
                source = "proxy_history";
            } else {
                // Fetch through Burp
                HttpRequestResponse result = fetchUrl(resUrl);
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
                String mapUrl = resolveUrl(mapRef, resUrl);
                if (mapUrl != null) {
                    sourceMapUrls.add(mapUrl);
                }
            }

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("url", resUrl);
            entry.put("type", classifyByUrl(resUrl));
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

            String content = findInHistory(mapUrl);
            String source;
            if (content != null) {
                source = "proxy_history";
            } else {
                HttpRequestResponse result = fetchUrl(mapUrl);
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
    private String classifyResource(String url, HttpResponse resp) {
        String urlLower = url.toLowerCase();

        // Check by URL extension
        for (String ext : MAP_EXTENSIONS) {
            if (urlLower.contains(ext + "?") || urlLower.endsWith(ext)) return "sourcemap";
        }
        for (String ext : JS_EXTENSIONS) {
            if (urlLower.contains(ext + "?") || urlLower.endsWith(ext)) return "js";
        }
        for (String ext : CSS_EXTENSIONS) {
            if (urlLower.contains(ext + "?") || urlLower.endsWith(ext)) return "css";
        }

        // Check by MIME type from response
        if (resp != null) {
            String mimeType = getMimeType(resp);
            if (JS_MIME_TYPES.contains(mimeType)) return "js";
            if (CSS_MIME_TYPES.contains(mimeType)) return "css";
        }

        return null;
    }

    private String classifyByUrl(String url) {
        String lower = url.toLowerCase();
        for (String ext : MAP_EXTENSIONS) {
            if (lower.contains(ext + "?") || lower.endsWith(ext)) return "sourcemap";
        }
        for (String ext : JS_EXTENSIONS) {
            if (lower.contains(ext + "?") || lower.endsWith(ext)) return "js";
        }
        for (String ext : CSS_EXTENSIONS) {
            if (lower.contains(ext + "?") || lower.endsWith(ext)) return "css";
        }
        return "unknown";
    }

    private String getMimeType(HttpResponse resp) {
        for (HttpHeader h : resp.headers()) {
            if ("Content-Type".equalsIgnoreCase(h.name())) {
                return h.value().split(";")[0].trim().toLowerCase();
            }
        }
        return "";
    }

    // ── History search ────────────────────────────────────────────

    /**
     * Search proxy history for a URL and return the response body, or null if not found.
     */
    private String findInHistory(String url) {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        for (int i = history.size() - 1; i >= 0; i--) {
            ProxyHttpRequestResponse item = history.get(i);
            if (item.finalRequest().url().equals(url)) {
                HttpResponse resp = item.originalResponse();
                if (resp != null) {
                    return resp.bodyToString();
                }
            }
        }
        return null;
    }

    // ── HTTP fetch ────────────────────────────────────────────────

    private HttpRequestResponse fetchUrl(String url) {
        try {
            HttpService service = HttpService.httpService(url);
            String path = extractPath(url);

            HttpRequest request = HttpRequest.httpRequest()
                    .withMethod("GET")
                    .withPath(path)
                    .withService(service)
                    .withHeader("Host", service.host())
                    .withHeader("User-Agent", "Mozilla/5.0 (compatible; BurpSuite SwissKnife)");

            return com.swissknife.http.ProxyTunnel.sendOrFallback(api, request);
        } catch (Exception e) {
            return null;
        }
    }

    private String extractPath(String url) {
        try {
            URI uri = new URI(url);
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) path = "/";
            if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
            return path;
        } catch (Exception e) {
            return "/";
        }
    }

    // ── HTML parsing for resource references ──────────────────────

    private Set<String> extractResourceUrls(String html, String pageUrl) {
        Set<String> urls = new LinkedHashSet<>();

        // Extract <script src="...">
        Matcher scriptMatcher = SCRIPT_SRC_PATTERN.matcher(html);
        while (scriptMatcher.find()) {
            String resolved = resolveUrl(scriptMatcher.group(1), pageUrl);
            if (resolved != null) urls.add(resolved);
        }

        // Extract <link rel="stylesheet" href="...">
        Matcher linkMatcher = LINK_HREF_PATTERN.matcher(html);
        while (linkMatcher.find()) {
            String resolved = resolveUrl(linkMatcher.group(1), pageUrl);
            if (resolved != null) urls.add(resolved);
        }

        // Handle reversed attribute order: <link href="..." rel="stylesheet">
        Matcher linkAltMatcher = LINK_HREF_ALT_PATTERN.matcher(html);
        while (linkAltMatcher.find()) {
            String resolved = resolveUrl(linkAltMatcher.group(1), pageUrl);
            if (resolved != null) urls.add(resolved);
        }

        return urls;
    }

    /**
     * Resolve a potentially relative URL against a base URL.
     */
    private String resolveUrl(String ref, String baseUrl) {
        if (ref == null || ref.isEmpty() || ref.startsWith("data:")) return null;
        try {
            URI base = new URI(baseUrl);
            URI resolved = base.resolve(ref);
            return resolved.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // ── Response helpers ──────────────────────────────────────────

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
