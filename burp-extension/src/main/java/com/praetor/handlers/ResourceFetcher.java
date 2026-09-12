package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Resource classification, fetching, and link-extraction helpers, split from ResourceHandler. */
final class ResourceFetcher {

    private ResourceFetcher() {}

    static final Set<String> JS_MIME_TYPES = Set.of(
            "application/javascript", "application/x-javascript", "text/javascript",
            "application/ecmascript", "text/ecmascript"
    );
    static final Pattern SCRIPT_SRC_PATTERN = Pattern.compile(
            "<script[^>]+src=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    static final Pattern LINK_HREF_PATTERN = Pattern.compile(
            "<link[^>]+rel=[\"']stylesheet[\"'][^>]+href=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    static final Pattern LINK_HREF_ALT_PATTERN = Pattern.compile(
            "<link[^>]+href=[\"']([^\"']+)[\"'][^>]+rel=[\"']stylesheet[\"']", Pattern.CASE_INSENSITIVE);

    static String classifyResource(String url, HttpResponse resp) {
        String urlLower = url.toLowerCase();

        // Check by URL extension
        for (String ext : ResourceHandler.MAP_EXTENSIONS) {
            if (urlLower.contains(ext + "?") || urlLower.endsWith(ext)) return "sourcemap";
        }
        for (String ext : ResourceHandler.JS_EXTENSIONS) {
            if (urlLower.contains(ext + "?") || urlLower.endsWith(ext)) return "js";
        }
        for (String ext : ResourceHandler.CSS_EXTENSIONS) {
            if (urlLower.contains(ext + "?") || urlLower.endsWith(ext)) return "css";
        }

        // Check by MIME type from response
        if (resp != null) {
            String mimeType = getMimeType(resp);
            if (JS_MIME_TYPES.contains(mimeType)) return "js";
            if (ResourceHandler.CSS_MIME_TYPES.contains(mimeType)) return "css";
        }

        return null;
    }

    static String classifyByUrl(String url) {
        String lower = url.toLowerCase();
        for (String ext : ResourceHandler.MAP_EXTENSIONS) {
            if (lower.contains(ext + "?") || lower.endsWith(ext)) return "sourcemap";
        }
        for (String ext : ResourceHandler.JS_EXTENSIONS) {
            if (lower.contains(ext + "?") || lower.endsWith(ext)) return "js";
        }
        for (String ext : ResourceHandler.CSS_EXTENSIONS) {
            if (lower.contains(ext + "?") || lower.endsWith(ext)) return "css";
        }
        return "unknown";
    }

    static String getMimeType(HttpResponse resp) {
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
    static String findInHistory(MontoyaApi api, String url) {
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

    static HttpRequestResponse fetchUrl(MontoyaApi api, String url) {
        try {
            HttpService service = HttpService.httpService(url);
            String path = extractPath(url);

            HttpRequest request = HttpRequest.httpRequest()
                    .withMethod("GET")
                    .withPath(path)
                    .withService(service)
                    .withHeader("Host", service.host())
                    .withHeader("User-Agent", "Mozilla/5.0 (compatible; Praetor)");

            return com.praetor.http.ProxyTunnel.sendOrFallback(api, request);
        } catch (Exception e) {
            return null;
        }
    }

    static String extractPath(String url) {
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

    static Set<String> extractResourceUrls(String html, String pageUrl) {
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
    static String resolveUrl(String ref, String baseUrl) {
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

}
