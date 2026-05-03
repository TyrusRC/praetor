package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracked Repeater tabs — send proxy history items to Repeater AND track them
 * locally so Claude can iterate on requests (modify, resend, compare).
 *
 * POST   /api/repeater/send      — send proxy item to Repeater + track it
 * GET    /api/repeater/tabs      — list all tracked tabs
 * POST   /api/repeater/resend    — resend a tracked tab with modifications
 * DELETE /api/repeater/{name}    — remove a tracked tab from our map
 */
public class RepeaterHandler extends BaseHandler {

    private static final int MAX_RESPONSE_SIZE = com.swissknife.server.ResponseLimits.MAX_RESPONSE_BODY;

    private final MontoyaApi api;
    private final ConcurrentHashMap<String, RepeaterTab> tabs = new ConcurrentHashMap<>();

    public RepeaterHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        switch (method.toUpperCase()) {
            case "GET" -> {
                if ("/api/repeater/tabs".equals(path)) {
                    handleListTabs(exchange);
                } else {
                    sendError(exchange, 404, "Not found");
                }
            }
            case "POST" -> {
                Map<String, Object> body = readJsonBody(exchange);
                switch (path) {
                    case "/api/repeater/send" -> handleSend(exchange, body);
                    case "/api/repeater/resend" -> handleResend(exchange, body);
                    default -> sendError(exchange, 404, "Not found");
                }
            }
            case "DELETE" -> {
                // /api/repeater/{name} — name is path segment index 2
                String name = pathSegment(exchange, 2); // api=0, repeater=1, {name}=2
                if (name != null) {
                    handleDelete(exchange, name);
                } else {
                    sendError(exchange, 400, "Missing tab name in path");
                }
            }
            default -> sendError(exchange, 405, "Method not allowed");
        }
    }

    // ── POST /api/repeater/send ───────────────────────────────────

    private void handleSend(HttpExchange exchange, Map<String, Object> body) throws Exception {
        Object indexObj = body.get("index");
        if (!(indexObj instanceof Number)) {
            sendError(exchange, 400, "Missing or invalid 'index'");
            return;
        }
        int index = ((Number) indexObj).intValue();

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index < 0 || index >= history.size()) {
            sendError(exchange, 404, "Index out of range: " + index);
            return;
        }

        HttpRequest request = history.get(index).finalRequest();
        String name = (String) body.getOrDefault("name", "MCP-" + index);

        // Send to Burp Repeater UI
        api.repeater().sendToRepeater(request, name);

        // Track locally
        RepeaterTab tab = new RepeaterTab(name, request);
        tabs.put(name, tab);

        String url = request.url();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("tab", name);
        out.put("url", url);
        out.put("method", request.method());
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── GET /api/repeater/tabs ────────────────────────────────────

    private void handleListTabs(HttpExchange exchange) throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        for (RepeaterTab tab : tabs.values()) {
            synchronized (tab) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", tab.name);
                m.put("method", tab.currentRequest.method());
                m.put("url", tab.currentRequest.url());
                m.put("send_count", tab.sendCount.get());
                m.put("created_at", tab.createdAt);
                m.put("has_response", tab.lastResponse != null);
                list.add(m);
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tabs", list);
        out.put("total", list.size());
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── POST /api/repeater/resend ─────────────────────────────────

    private void handleResend(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String name = (String) body.get("name");
        if (name == null || name.isEmpty()) {
            sendError(exchange, 400, "Missing 'name'");
            return;
        }

        RepeaterTab tab = tabs.get(name);
        if (tab == null) {
            sendError(exchange, 404, "No tracked tab: " + name);
            return;
        }

        HttpRequest modified = tab.currentRequest;

        // Apply optional modifications
        String newMethod = (String) body.get("modify_method");
        if (newMethod != null) modified = modified.withMethod(newMethod);

        String newPath = (String) body.get("modify_path");
        if (newPath != null) modified = modified.withPath(newPath);

        @SuppressWarnings("unchecked")
        Map<String, Object> newHeaders = (Map<String, Object>) body.get("modify_headers");
        if (newHeaders != null) {
            for (var entry : newHeaders.entrySet()) {
                modified = modified.withHeader(entry.getKey(), String.valueOf(entry.getValue()));
            }
        }

        String newBody = (String) body.get("modify_body");
        if (newBody != null) modified = modified.withBody(newBody);

        // Send through Burp HTTP stack
        HttpRequestResponse result = com.swissknife.http.ProxyTunnel.sendOrFallback(api, modified);

        // Update tracked state (thread-safe)
        tab.updateAfterSend(modified, result);

        // Build response
        sendResponseJson(exchange, result, tab);
    }

    // ── DELETE /api/repeater/{name} ───────────────────────────────

    private void handleDelete(HttpExchange exchange, String name) throws Exception {
        RepeaterTab removed = tabs.remove(name);
        if (removed == null) {
            sendError(exchange, 404, "No tracked tab: " + name);
            return;
        }
        sendOk(exchange, "Removed tracked tab: " + name);
    }

    // ── Helpers ───────────────────────────────────────────────────

    private void sendResponseJson(HttpExchange exchange, HttpRequestResponse result, RepeaterTab tab) throws Exception {
        if (result == null) {
            sendError(exchange, 502, "No response from target");
            return;
        }

        HttpResponse resp = result.response();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tab", tab.name);
        out.put("send_count", tab.sendCount.get());
        out.put("status_code", resp != null ? resp.statusCode() : 0);

        if (resp != null) {
            List<Map<String, Object>> headers = new ArrayList<>();
            for (HttpHeader h : resp.headers()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", h.name());
                m.put("value", h.value());
                headers.add(m);
            }
            out.put("response_headers", headers);

            String body = resp.bodyToString();
            if (body.length() > MAX_RESPONSE_SIZE) {
                int half = MAX_RESPONSE_SIZE / 2;
                body = body.substring(0, half)
                    + "\n\n[... TRUNCATED " + (body.length() - MAX_RESPONSE_SIZE) + " chars ...]\n\n"
                    + body.substring(body.length() - half);
            }
            out.put("response_body", body);
            out.put("response_length", resp.body().length());
        }

        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── Inner class ───────────────────────────────────────────────

    /**
     * Tracks a single Repeater tab's state: the current request (possibly modified),
     * last response, and how many times it has been sent.
     */
    private static class RepeaterTab {
        final String name;
        volatile HttpRequest currentRequest;
        volatile HttpRequestResponse lastResponse;
        final java.util.concurrent.atomic.AtomicInteger sendCount = new java.util.concurrent.atomic.AtomicInteger(0);
        final long createdAt;

        RepeaterTab(String name, HttpRequest request) {
            this.name = name;
            this.currentRequest = request;
            this.lastResponse = null;
            this.createdAt = System.currentTimeMillis();
        }

        synchronized void updateAfterSend(HttpRequest req, HttpRequestResponse resp) {
            this.currentRequest = req;
            this.lastResponse = resp;
            this.sendCount.incrementAndGet();
        }
    }
}
