package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * Traffic statistics, live polling, and monitor endpoints.
 *
 * GET    /api/traffic/stats
 * GET    /api/traffic/live?since_index=N
 * POST   /api/traffic/monitor/register
 * GET    /api/traffic/monitor/check?tag=X
 * DELETE /api/traffic/monitor/{tag}
 */
public class TrafficMonitorHandler extends BaseHandler {

    private final MontoyaApi api;
    private final ConcurrentHashMap<String, MonitorRule> monitors = new ConcurrentHashMap<>();

    // ── Inner types ───────────────────────────────────────────────

    static final class MonitorHit {
        final int index;
        final String matchedText;
        final long timestamp;

        MonitorHit(int index, String matchedText, long timestamp) {
            this.index = index;
            this.matchedText = matchedText;
            this.timestamp = timestamp;
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("index", index);
            m.put("matched_text", matchedText);
            m.put("timestamp", timestamp);
            return m;
        }
    }

    static final class MonitorRule {
        final String tag;
        final List<MonitorPattern> patterns;
        final CopyOnWriteArrayList<MonitorHit> hits = new CopyOnWriteArrayList<>();
        volatile int lastCheckedIndex;

        MonitorRule(String tag, List<MonitorPattern> patterns) {
            this.tag = tag;
            this.patterns = patterns;
            this.lastCheckedIndex = -1;
        }
    }

    static final class MonitorPattern {
        final String location; // "url", "request_body", "response_body", "request_header", "response_header"
        final Pattern regex;

        MonitorPattern(String location, Pattern regex) {
            this.location = location;
            this.regex = regex;
        }
    }

    // ── Constructor ───────────────────────────────────────────────

    public TrafficMonitorHandler(MontoyaApi api) {
        this.api = api;
    }

    // ── Route dispatch ────────────────────────────────────────────

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if (path.equals("/api/traffic/stats") && "GET".equalsIgnoreCase(method)) {
            handleStats(exchange);
        } else if (path.equals("/api/traffic/live") && "GET".equalsIgnoreCase(method)) {
            handleLive(exchange);
        } else if (path.equals("/api/traffic/monitor/register") && "POST".equalsIgnoreCase(method)) {
            handleMonitorRegister(exchange);
        } else if (path.equals("/api/traffic/monitor/check") && "GET".equalsIgnoreCase(method)) {
            handleMonitorCheck(exchange);
        } else if (path.startsWith("/api/traffic/monitor/") && "DELETE".equalsIgnoreCase(method)) {
            handleMonitorDelete(exchange, path);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    // ── Stats handler ─────────────────────────────────────────────

    private void handleStats(HttpExchange exchange) throws Exception {
        List<ProxyHttpRequestResponse> history = api.proxy().history();

        Set<String> uniqueHosts = new LinkedHashSet<>();
        Map<String, Integer> methodDist = new LinkedHashMap<>();
        Map<Integer, Integer> statusDist = new LinkedHashMap<>();

        for (ProxyHttpRequestResponse item : history) {
            HttpRequest req = item.finalRequest();
            HttpResponse resp = item.originalResponse();

            // Host
            String url = req.url();
            try {
                java.net.URI uri = new java.net.URI(url);
                String host = uri.getHost();
                if (host != null) uniqueHosts.add(host);
            } catch (Exception ignored) {
                // Malformed URL — skip host extraction
            }

            // Method distribution
            methodDist.merge(req.method(), 1, Integer::sum);

            // Status code distribution
            if (resp != null) {
                statusDist.merge((int) resp.statusCode(), 1, Integer::sum);
            }
        }

        sendJson(exchange, JsonUtil.object(
            "total_requests", history.size(),
            "unique_hosts", uniqueHosts.size(),
            "hosts", new ArrayList<>(uniqueHosts),
            "method_distribution", methodDist,
            "status_code_distribution", statusDist
        ));
    }

    // ── Live polling handler ──────────────────────────────────────

    private void handleLive(HttpExchange exchange) throws Exception {
        Map<String, String> params = queryParams(exchange);
        int sinceIndex = intParam(params, "since_index", -1);

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        int total = history.size();

        List<Map<String, Object>> items = new ArrayList<>();
        int startIndex = sinceIndex + 1;

        for (int i = startIndex; i < total; i++) {
            ProxyHttpRequestResponse item = history.get(i);
            HttpRequest req = item.finalRequest();
            HttpResponse resp = item.originalResponse();

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("index", i);
            entry.put("method", req.method());
            entry.put("url", req.url());
            entry.put("status_code", resp != null ? resp.statusCode() : 0);
            items.add(entry);
        }

        sendJson(exchange, JsonUtil.object(
            "since_index", sinceIndex,
            "new_items", items.size(),
            "latest_index", total > 0 ? total - 1 : -1,
            "items", items
        ));
    }

    // ── Monitor handlers ──────────────────────────────────────────

    private void handleMonitorRegister(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String tag = stringVal(body, "tag", "");
        if (tag.isEmpty()) {
            sendError(exchange, 400, "Missing 'tag'");
            return;
        }

        Object patternsObj = body.get("patterns");
        if (!(patternsObj instanceof List<?> patternsList)) {
            sendError(exchange, 400, "Missing or invalid 'patterns' array");
            return;
        }

        List<MonitorPattern> compiled = new ArrayList<>();
        for (Object item : patternsList) {
            if (!(item instanceof Map<?, ?> patMap)) continue;
            String location = stringVal(patMap, "location", "url");
            String regex = stringVal(patMap, "regex", "");
            if (regex.isEmpty()) continue;

            try {
                compiled.add(new MonitorPattern(location, Pattern.compile(regex)));
            } catch (PatternSyntaxException e) {
                sendError(exchange, 400, "Invalid regex: " + regex + " — " + e.getMessage());
                return;
            }
        }

        if (compiled.isEmpty()) {
            sendError(exchange, 400, "No valid patterns provided");
            return;
        }

        MonitorRule rule = new MonitorRule(tag, compiled);
        // Set lastCheckedIndex to current end of history so we only monitor new traffic
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        rule.lastCheckedIndex = history.size() - 1;

        monitors.put(tag, rule);
        sendOk(exchange, "Monitor '" + tag + "' registered with " + compiled.size() + " patterns");
    }

    private void handleMonitorCheck(HttpExchange exchange) throws Exception {
        Map<String, String> params = queryParams(exchange);
        String tag = params.get("tag");
        if (tag == null || tag.isEmpty()) {
            sendError(exchange, 400, "Missing 'tag' query parameter");
            return;
        }

        MonitorRule rule = monitors.get(tag);
        if (rule == null) {
            sendError(exchange, 404, "Monitor not found: " + tag);
            return;
        }

        // Scan proxy history from lastCheckedIndex forward
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        int total = history.size();
        int startIndex = rule.lastCheckedIndex + 1;

        for (int i = startIndex; i < total; i++) {
            ProxyHttpRequestResponse item = history.get(i);
            HttpRequest req = item.finalRequest();
            HttpResponse resp = item.originalResponse();

            for (MonitorPattern mp : rule.patterns) {
                String content = extractContent(req, resp, mp.location);
                if (content == null) continue;

                Matcher matcher = mp.regex.matcher(content);
                if (matcher.find()) {
                    String snippet = matcher.group();
                    // Limit snippet length
                    if (snippet.length() > 200) {
                        snippet = snippet.substring(0, 200) + "...";
                    }
                    rule.hits.add(new MonitorHit(i, snippet, System.currentTimeMillis()));
                    break; // One hit per history item is enough
                }
            }
        }

        rule.lastCheckedIndex = total - 1;

        // Build response
        List<Map<String, Object>> hitMaps = new ArrayList<>();
        for (MonitorHit hit : rule.hits) {
            hitMaps.add(hit.toMap());
        }

        sendJson(exchange, JsonUtil.object(
            "tag", tag,
            "total_hits", rule.hits.size(),
            "scanned_to_index", rule.lastCheckedIndex,
            "hits", hitMaps
        ));
    }

    private void handleMonitorDelete(HttpExchange exchange, String path) throws Exception {
        // Path: /api/traffic/monitor/{tag}
        String tag = path.substring("/api/traffic/monitor/".length());
        if (tag.isEmpty()) {
            sendError(exchange, 400, "Missing monitor tag");
            return;
        }

        MonitorRule removed = monitors.remove(tag);
        if (removed != null) {
            sendOk(exchange, "Monitor '" + tag + "' removed");
        } else {
            sendError(exchange, 404, "Monitor not found: " + tag);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────

    private String extractContent(HttpRequest req, HttpResponse resp, String location) {
        return switch (location) {
            case "url" -> req.url();
            case "request_body" -> req.bodyToString();
            case "response_body" -> resp != null ? resp.bodyToString() : null;
            case "request_header" -> headersToString(req.headers());
            case "response_header" -> resp != null ? headersToString(resp.headers()) : null;
            default -> null;
        };
    }

    private String headersToString(List<burp.api.montoya.http.message.HttpHeader> headers) {
        if (headers == null) return "";
        StringBuilder sb = new StringBuilder();
        for (var h : headers) {
            sb.append(h.name()).append(": ").append(h.value()).append("\n");
        }
        return sb.toString();
    }

    private String stringVal(Map<?, ?> map, String key, String defaultVal) {
        Object val = map.get(key);
        return val instanceof String s ? s : defaultVal;
    }
}
