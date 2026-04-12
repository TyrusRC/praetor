package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

/**
 * POST /api/extract-data/json-path  - simple JSON path extraction from response body
 * POST /api/extract-data/headers    - extract specific headers from request or response
 * POST /api/extract-data/hash       - hash response body (md5, sha1, sha256)
 */
public class ExtractDataHandler extends BaseHandler {

    private final MontoyaApi api;

    public ExtractDataHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();

        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        switch (path) {
            case "/api/extract-data/json-path" -> handleJsonPath(exchange);
            case "/api/extract-data/headers" -> handleHeaders(exchange);
            case "/api/extract-data/hash" -> handleHash(exchange);
            default -> sendError(exchange, 404, "Not found");
        }
    }

    // ── Helpers ──────────────────────────────────────────────────

    private ProxyHttpRequestResponse getHistoryItem(int index) {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index < 0 || index >= history.size()) return null;
        return history.get(index);
    }

    private int readIndex(Map<String, Object> body) {
        Object val = body.get("index");
        return val instanceof Number n ? n.intValue() : -1;
    }

    private String getResponseBody(int index) {
        ProxyHttpRequestResponse item = getHistoryItem(index);
        if (item == null) return null;
        HttpResponse resp = item.originalResponse();
        if (resp == null) return null;
        return resp.bodyToString();
    }

    // ── 1. JSON path extraction ─────────────────────────────────

    private void handleJsonPath(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        int index = readIndex(body);
        String path = (String) body.get("path");

        if (path == null || path.isEmpty()) {
            sendError(exchange, 400, "Missing 'path' field");
            return;
        }

        String responseBody = getResponseBody(index);
        if (responseBody == null) {
            sendError(exchange, 400, "Invalid index or no response at index " + index);
            return;
        }

        responseBody = responseBody.trim();
        if (responseBody.isEmpty()) {
            sendError(exchange, 400, "Response body is empty");
            return;
        }

        Object root;
        try {
            if (responseBody.startsWith("{")) {
                root = JsonUtil.parseObject(responseBody);
            } else if (responseBody.startsWith("[")) {
                root = JsonUtil.parseArray(responseBody);
            } else {
                sendError(exchange, 400, "Response body is not valid JSON");
                return;
            }
        } catch (Exception e) {
            sendError(exchange, 400, "Failed to parse response as JSON: " + e.getMessage());
            return;
        }

        // Parse path: strip leading "$." and split
        String pathExpr = path;
        if (pathExpr.startsWith("$.")) {
            pathExpr = pathExpr.substring(2);
        } else if (pathExpr.equals("$")) {
            sendJson(exchange, JsonUtil.object("value", root, "path", path));
            return;
        }

        Object result;
        try {
            result = traverseJsonPath(root, pathExpr);
        } catch (Exception e) {
            sendError(exchange, 400, "JSON path traversal failed: " + e.getMessage());
            return;
        }

        sendJson(exchange, JsonUtil.object("value", result, "path", path));
    }

    private Object traverseJsonPath(Object current, String pathExpr) {
        String[] segments = splitPathSegments(pathExpr);

        for (String segment : segments) {
            if (current == null) return null;

            // Handle array wildcard: field[*]
            if (segment.contains("[*]")) {
                String fieldName = segment.substring(0, segment.indexOf("[*]"));
                if (!fieldName.isEmpty() && current instanceof Map<?, ?> map) {
                    current = map.get(fieldName);
                }
                // current should be a list — will be expanded by next segment
                continue;
            }

            // Handle array index: field[N]
            Matcher arrayMatcher = Pattern.compile("^(.+?)\\[(\\d+)]$").matcher(segment);
            if (arrayMatcher.matches()) {
                String fieldName = arrayMatcher.group(1);
                int arrayIndex = Integer.parseInt(arrayMatcher.group(2));
                if (current instanceof Map<?, ?> map) {
                    current = map.get(fieldName);
                }
                if (current instanceof List<?> list) {
                    if (arrayIndex >= 0 && arrayIndex < list.size()) {
                        current = list.get(arrayIndex);
                    } else {
                        return null;
                    }
                } else {
                    return null;
                }
                continue;
            }

            // Handle bare array index: [N]
            Matcher bareIndex = Pattern.compile("^\\[(\\d+)]$").matcher(segment);
            if (bareIndex.matches()) {
                int idx = Integer.parseInt(bareIndex.group(1));
                if (current instanceof List<?> list) {
                    if (idx >= 0 && idx < list.size()) {
                        current = list.get(idx);
                    } else {
                        return null;
                    }
                } else {
                    return null;
                }
                continue;
            }

            // If current is a list (from wildcard), extract field from each element
            if (current instanceof List<?> list) {
                List<Object> collected = new ArrayList<>();
                for (Object item : list) {
                    if (item instanceof Map<?, ?> map) {
                        Object val = map.get(segment);
                        if (val != null) collected.add(val);
                    }
                }
                current = collected;
                continue;
            }

            // Simple key access
            if (current instanceof Map<?, ?> map) {
                current = map.get(segment);
            } else {
                return null;
            }
        }

        return current;
    }

    /**
     * Split a JSON path expression into segments, respecting brackets.
     * "data.users[0].name" -> ["data", "users[0]", "name"]
     * "data.items[*].id"   -> ["data", "items[*]", "id"]
     */
    private String[] splitPathSegments(String pathExpr) {
        List<String> segments = new ArrayList<>();
        StringBuilder current = new StringBuilder();

        for (int i = 0; i < pathExpr.length(); i++) {
            char c = pathExpr.charAt(i);
            if (c == '.' && !isInsideBracket(current.toString())) {
                if (!current.isEmpty()) {
                    segments.add(current.toString());
                    current.setLength(0);
                }
            } else {
                current.append(c);
            }
        }
        if (!current.isEmpty()) {
            segments.add(current.toString());
        }

        return segments.toArray(new String[0]);
    }

    private boolean isInsideBracket(String s) {
        int open = 0;
        for (char c : s.toCharArray()) {
            if (c == '[') open++;
            if (c == ']') open--;
        }
        return open > 0;
    }

    // ── 2. Headers extraction ───────────────────────────────────

    private void handleHeaders(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        int index = readIndex(body);
        @SuppressWarnings("unchecked")
        List<String> names = (List<String>) body.get("names");
        String from = (String) body.getOrDefault("from", "response");

        ProxyHttpRequestResponse item = getHistoryItem(index);
        if (item == null) {
            sendError(exchange, 400, "Invalid index: " + index);
            return;
        }

        List<HttpHeader> sourceHeaders;
        if ("request".equalsIgnoreCase(from)) {
            sourceHeaders = item.finalRequest().headers();
        } else {
            HttpResponse resp = item.originalResponse();
            if (resp == null) {
                sendError(exchange, 400, "No response at index " + index);
                return;
            }
            sourceHeaders = resp.headers();
        }

        boolean filterByName = names != null && !names.isEmpty();
        Set<String> nameSet = new HashSet<>();
        if (filterByName) {
            for (String n : names) {
                nameSet.add(n.toLowerCase());
            }
        }

        List<Map<String, Object>> headers = new ArrayList<>();
        for (HttpHeader h : sourceHeaders) {
            if (filterByName && !nameSet.contains(h.name().toLowerCase())) continue;
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", h.name());
            entry.put("value", h.value());
            headers.add(entry);
        }

        sendJson(exchange, JsonUtil.object("headers", headers, "count", headers.size()));
    }

    // ── 3. Hash ─────────────────────────────────────────────────

    private void handleHash(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        int index = readIndex(body);
        String algorithm = (String) body.getOrDefault("algorithm", "sha256");

        String responseBody = getResponseBody(index);
        if (responseBody == null) {
            sendError(exchange, 400, "Invalid index or no response at index " + index);
            return;
        }

        String algoName;
        switch (algorithm.toLowerCase()) {
            case "md5" -> algoName = "MD5";
            case "sha1", "sha-1" -> algoName = "SHA-1";
            case "sha256", "sha-256" -> algoName = "SHA-256";
            default -> {
                sendError(exchange, 400, "Unsupported algorithm: " + algorithm + ". Use md5, sha1, or sha256");
                return;
            }
        }

        MessageDigest digest = MessageDigest.getInstance(algoName);
        byte[] hashBytes = digest.digest(responseBody.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : hashBytes) {
            hex.append(String.format("%02x", b));
        }

        sendJson(exchange, JsonUtil.object(
            "hash", hex.toString(),
            "algorithm", algorithm.toLowerCase(),
            "body_length", responseBody.length()
        ));
    }
}
