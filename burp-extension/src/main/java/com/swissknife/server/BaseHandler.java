package com.swissknife.server;

import com.swissknife.http.HttpExchange;
import com.swissknife.http.HttpHandler;
import com.swissknife.util.JsonUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public abstract class BaseHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // CORS for localhost MCP server
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "http://127.0.0.1");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");

        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return;
        }

        // Log API call to activity log (skip health checks to reduce noise)
        String path = exchange.getRequestURI().getPath();
        if (!"/api/health".equals(path)) {
            com.swissknife.ui.ConfigTab.log(
                exchange.getRequestMethod() + " " + path
            );
        }

        try {
            handleRequest(exchange);
        } catch (Exception e) {
            com.swissknife.ui.ConfigTab.log("ERROR: " + path + " -> " + e.getMessage());
            sendError(exchange, 500, "Internal error: " + e.getMessage());
        }
    }

    protected abstract void handleRequest(HttpExchange exchange) throws Exception;

    // ── Request helpers ────────────────────────────────────────────

    protected String readBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    protected Map<String, Object> readJsonBody(HttpExchange exchange) throws IOException {
        String body = readBody(exchange);
        if (body == null || body.isBlank()) return Map.of();
        return JsonUtil.parseObject(body);
    }

    protected Map<String, String> queryParams(HttpExchange exchange) {
        Map<String, String> params = new LinkedHashMap<>();
        URI uri = exchange.getRequestURI();
        String query = uri.getRawQuery();
        if (query == null || query.isEmpty()) return params;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                params.put(
                    java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8)
                );
            }
        }
        return params;
    }

    protected String pathSegment(HttpExchange exchange, int index) {
        String path = exchange.getRequestURI().getPath();
        String[] parts = path.split("/");
        // parts[0] is empty (leading slash), so index 0 = parts[1]
        int adjusted = index + 1;
        if (adjusted < parts.length) return parts[adjusted];
        return null;
    }

    protected int intParam(Map<String, String> params, String key, int defaultVal) {
        String val = params.get(key);
        if (val == null) return defaultVal;
        try { return Integer.parseInt(val); } catch (NumberFormatException e) { return defaultVal; }
    }

    // ── Response helpers ───────────────────────────────────────────

    protected void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    protected void sendJson(HttpExchange exchange, String json) throws IOException {
        sendJson(exchange, 200, json);
    }

    protected void sendError(HttpExchange exchange, int status, String message) throws IOException {
        sendError(exchange, status, message, codeFromStatus(status), "");
    }

    /**
     * Standardized error envelope (R18). Includes a stable error code and an
     * actionable hint so Python tools can surface guidance to the operator
     * instead of opaque "HTTP 500".
     *
     * @param exchange HTTP exchange
     * @param status   HTTP status code
     * @param message  Human-readable message
     * @param code     Stable machine code: out_of_scope, missing_index, burp_pro_required, validation_failed, server_error, ...
     * @param hint     Actionable next step the operator/Claude can take
     */
    protected void sendError(HttpExchange exchange, int status, String message, String code, String hint) throws IOException {
        sendJson(exchange, status, JsonUtil.object(
            "error", message,
            "code", code == null ? "" : code,
            "hint", hint == null ? "" : hint
        ));
    }

    private static String codeFromStatus(int status) {
        return switch (status) {
            case 400 -> "validation_failed";
            case 401 -> "unauthorized";
            case 403 -> "forbidden";
            case 404 -> "not_found";
            case 405 -> "method_not_allowed";
            case 409 -> "conflict";
            case 422 -> "unprocessable";
            case 500 -> "server_error";
            case 501 -> "not_implemented";
            case 503 -> "unavailable";
            default -> "error";
        };
    }

    protected void sendOk(HttpExchange exchange, String message) throws IOException {
        sendJson(exchange, 200, JsonUtil.object("status", "ok", "message", message));
    }
}
