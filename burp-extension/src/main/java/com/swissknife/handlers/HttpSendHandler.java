package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;
import java.util.Base64;

/**
 * POST /api/http/send     - send a crafted request through Burp (appears in HTTP history)
 * POST /api/http/raw      - send raw HTTP request string through Burp
 * POST /api/http/resend   - resend a proxy history item with modifications
 * POST /api/http/repeater - send a proxy history item to Repeater tab
 * POST /api/http/intruder - send a proxy history item to Intruder
 * POST /api/http/curl     - curl-like request with redirect following, auth, multi-request
 */
public class HttpSendHandler extends BaseHandler {

    private final MontoyaApi api;

    public HttpSendHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String path = exchange.getRequestURI().getPath();
        Map<String, Object> body = readJsonBody(exchange);

        switch (path) {
            case "/api/http/send" -> handleSend(exchange, body);
            case "/api/http/raw" -> handleRawSend(exchange, body);
            case "/api/http/resend" -> handleResend(exchange, body);
            case "/api/http/repeater" -> handleRepeater(exchange, body);
            case "/api/http/intruder" -> handleIntruder(exchange, body);
            case "/api/http/curl" -> handleCurl(exchange, body);
            default -> sendError(exchange, 404, "Not found");
        }
    }

    /**
     * Send a structured HTTP request through Burp.
     * Body: {"method":"GET","url":"https://example.com/path","headers":{"X-Custom":"val"},"body":"..."}
     * The request goes through Burp's HTTP stack and appears in proxy history.
     */
    private void handleSend(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String method = (String) body.get("method");
        String url = (String) body.get("url");

        if (method == null || url == null) {
            sendError(exchange, 400, "Missing 'method' and/or 'url'");
            return;
        }

        // Build the request
        HttpRequest request = HttpRequest.httpRequest()
            .withMethod(method)
            .withPath(extractPath(url));

        // Parse host/port/https from URL
        HttpService service = HttpService.httpService(url);
        request = request.withService(service);
        request = request.withHeader("Host", service.host());

        // Add custom headers
        @SuppressWarnings("unchecked")
        Map<String, Object> headers = (Map<String, Object>) body.get("headers");
        if (headers != null) {
            for (var entry : headers.entrySet()) {
                request = request.withHeader(entry.getKey(), String.valueOf(entry.getValue()));
            }
        }

        // Add body
        String reqBody = (String) body.get("body");
        if (reqBody != null && !reqBody.isEmpty()) {
            request = request.withBody(reqBody);
        }

        // Send through Burp — this makes it appear in HTTP history
        HttpRequestResponse result = api.http().sendRequest(request);
        sendResponseJson(exchange, result);
    }

    /**
     * Send a raw HTTP request string through Burp.
     * Body: {"raw":"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n","host":"example.com","port":443,"https":true}
     * This is for when Claude Code needs precise control over the raw request bytes.
     */
    private void handleRawSend(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String raw = (String) body.get("raw");
        String host = (String) body.get("host");
        Object portObj = body.get("port");
        Object httpsObj = body.get("https");

        if (raw == null || host == null) {
            sendError(exchange, 400, "Missing 'raw' and/or 'host'");
            return;
        }

        int port = portObj instanceof Number n ? n.intValue() : 443;
        boolean useHttps = httpsObj instanceof Boolean b ? b : true;

        HttpService service = HttpService.httpService(host, port, useHttps);
        HttpRequest request = HttpRequest.httpRequest(service, raw);

        HttpRequestResponse result = api.http().sendRequest(request);
        sendResponseJson(exchange, result);
    }

    /**
     * Resend a proxy history item with modifications.
     * Body: {"index":42,"modify_headers":{"X-New":"val"},"modify_body":"new body","modify_path":"/new/path","modify_method":"POST"}
     */
    private void handleResend(HttpExchange exchange, Map<String, Object> body) throws Exception {
        int index = getIndex(body);
        if (index < 0) { sendError(exchange, 400, "Missing or invalid 'index'"); return; }

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index >= history.size()) { sendError(exchange, 404, "Index out of range"); return; }

        HttpRequest original = history.get(index).finalRequest();
        HttpRequest modified = original;

        // Apply modifications
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

        HttpRequestResponse result = api.http().sendRequest(modified);
        sendResponseJson(exchange, result);
    }

    /**
     * Send a proxy history item to Repeater.
     * Body: {"index":42,"tab_name":"SQLi Test"}
     */
    private void handleRepeater(HttpExchange exchange, Map<String, Object> body) throws Exception {
        int index = getIndex(body);
        if (index < 0) { sendError(exchange, 400, "Missing or invalid 'index'"); return; }

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index >= history.size()) { sendError(exchange, 404, "Index out of range"); return; }

        HttpRequest request = history.get(index).finalRequest();
        String tabName = (String) body.getOrDefault("tab_name", "MCP-" + index);

        api.repeater().sendToRepeater(request, tabName);
        sendOk(exchange, "Sent to Repeater tab: " + tabName);
    }

    /**
     * Send a proxy history item to Intruder.
     * Body: {"index":42}
     */
    private void handleIntruder(HttpExchange exchange, Map<String, Object> body) throws Exception {
        int index = getIndex(body);
        if (index < 0) { sendError(exchange, 400, "Missing or invalid 'index'"); return; }

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index >= history.size()) { sendError(exchange, 404, "Index out of range"); return; }

        HttpRequest request = history.get(index).finalRequest();
        api.intruder().sendToIntruder(request);
        sendOk(exchange, "Sent to Intruder");
    }

    /**
     * Curl-like HTTP request with redirect following, auth, and content-type shortcuts.
     * Body: {
     *   "method": "GET", "url": "https://example.com",
     *   "headers": {}, "body": "", "data": "", "json": {},
     *   "auth_user": "", "auth_pass": "", "bearer_token": "",
     *   "follow_redirects": true, "max_redirects": 10,
     *   "cookies": {"name": "value"}
     * }
     */
    private void handleCurl(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String method = (String) body.getOrDefault("method", "GET");
        String url = (String) body.get("url");

        if (url == null || url.isEmpty()) {
            sendError(exchange, 400, "Missing 'url'");
            return;
        }

        boolean followRedirects = body.get("follow_redirects") instanceof Boolean b ? b : true;
        int maxRedirects = body.get("max_redirects") instanceof Number n ? n.intValue() : 10;

        // Build request
        HttpRequest request = HttpRequest.httpRequest()
            .withMethod(method.toUpperCase())
            .withPath(extractPath(url));

        HttpService service = HttpService.httpService(url);
        request = request.withService(service);
        request = request.withHeader("Host", service.host());

        // Custom headers
        @SuppressWarnings("unchecked")
        Map<String, Object> headers = (Map<String, Object>) body.get("headers");
        if (headers != null) {
            for (var entry : headers.entrySet()) {
                request = request.withHeader(entry.getKey(), String.valueOf(entry.getValue()));
            }
        }

        // Auth: Basic
        String authUser = (String) body.get("auth_user");
        String authPass = (String) body.get("auth_pass");
        if (authUser != null && authPass != null) {
            String credentials = Base64.getEncoder().encodeToString(
                (authUser + ":" + authPass).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            request = request.withHeader("Authorization", "Basic " + credentials);
        }

        // Auth: Bearer token
        String bearerToken = (String) body.get("bearer_token");
        if (bearerToken != null) {
            request = request.withHeader("Authorization", "Bearer " + bearerToken);
        }

        // Cookies
        @SuppressWarnings("unchecked")
        Map<String, Object> cookies = (Map<String, Object>) body.get("cookies");
        if (cookies != null && !cookies.isEmpty()) {
            StringBuilder cookieHeader = new StringBuilder();
            for (var entry : cookies.entrySet()) {
                if (cookieHeader.length() > 0) cookieHeader.append("; ");
                cookieHeader.append(entry.getKey()).append("=").append(entry.getValue());
            }
            request = request.withHeader("Cookie", cookieHeader.toString());
        }

        // Body: JSON shortcut
        @SuppressWarnings("unchecked")
        Map<String, Object> jsonBody = (Map<String, Object>) body.get("json");
        if (jsonBody != null) {
            request = request.withHeader("Content-Type", "application/json");
            request = request.withBody(JsonUtil.toJson(jsonBody));
        }
        // Body: form data shortcut
        else {
            String data = (String) body.get("data");
            if (data != null && !data.isEmpty()) {
                if (!hasHeader(headers, "Content-Type")) {
                    request = request.withHeader("Content-Type", "application/x-www-form-urlencoded");
                }
                request = request.withBody(data);
            }
            // Body: raw
            else {
                String reqBody = (String) body.get("body");
                if (reqBody != null && !reqBody.isEmpty()) {
                    request = request.withBody(reqBody);
                }
            }
        }

        // Send with redirect following
        List<Map<String, Object>> redirectChain = new ArrayList<>();
        HttpRequestResponse result = api.http().sendRequest(request);
        int redirectCount = 0;

        while (followRedirects && redirectCount < maxRedirects && result.response() != null) {
            int status = result.response().statusCode();
            if (status < 300 || status >= 400) break;

            String location = null;
            for (HttpHeader h : result.response().headers()) {
                if ("Location".equalsIgnoreCase(h.name())) {
                    location = h.value();
                    break;
                }
            }
            if (location == null) break;

            // Record redirect
            Map<String, Object> hop = new LinkedHashMap<>();
            hop.put("status", status);
            hop.put("location", location);
            redirectChain.add(hop);

            // Resolve relative URL
            if (!location.startsWith("http")) {
                String base = service.secure() ? "https" : "http";
                location = base + "://" + service.host()
                    + (service.port() != 80 && service.port() != 443 ? ":" + service.port() : "")
                    + location;
            }

            // Follow redirect
            HttpService nextService = HttpService.httpService(location);
            HttpRequest nextRequest = HttpRequest.httpRequest()
                .withMethod("GET")
                .withPath(extractPath(location))
                .withService(nextService)
                .withHeader("Host", nextService.host());

            result = api.http().sendRequest(nextRequest);
            service = nextService;
            redirectCount++;
        }

        // Build response with redirect chain info
        Map<String, Object> out = new LinkedHashMap<>();
        HttpResponse resp = result.response();
        out.put("status_code", resp != null ? resp.statusCode() : 0);
        out.put("redirects_followed", redirectCount);
        if (!redirectChain.isEmpty()) {
            out.put("redirect_chain", redirectChain);
        }

        if (resp != null) {
            List<Map<String, Object>> respHeaders = new ArrayList<>();
            for (HttpHeader h : resp.headers()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", h.name());
                m.put("value", h.value());
                respHeaders.add(m);
            }
            out.put("response_headers", respHeaders);

            String respBody = resp.bodyToString();
            if (respBody.length() > 50000) {
                respBody = respBody.substring(0, 25000)
                    + "\n\n[... TRUNCATED " + (respBody.length() - 50000) + " chars ...]\n\n"
                    + respBody.substring(respBody.length() - 25000);
            }
            out.put("response_body", respBody);
            out.put("response_length", resp.body().length());
        }

        sendJson(exchange, JsonUtil.toJson(out));
    }

    private boolean hasHeader(Map<String, Object> headers, String name) {
        if (headers == null) return false;
        for (String key : headers.keySet()) {
            if (key.equalsIgnoreCase(name)) return true;
        }
        return false;
    }

    // ── Helpers ────────────────────────────────────────────────

    private void sendResponseJson(HttpExchange exchange, HttpRequestResponse result) throws Exception {
        if (result == null) { sendError(exchange, 502, "No response from target"); return; }
        HttpResponse resp = result.response();
        Map<String, Object> out = new LinkedHashMap<>();
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
            if (body.length() > 50000) {
                body = body.substring(0, 25000)
                    + "\n\n[... TRUNCATED " + (body.length() - 50000) + " chars ...]\n\n"
                    + body.substring(body.length() - 25000);
            }
            out.put("response_body", body);
            out.put("response_length", resp.body().length());
        }

        sendJson(exchange, JsonUtil.toJson(out));
    }

    private int getIndex(Map<String, Object> body) {
        Object idx = body.get("index");
        if (idx instanceof Number n) return n.intValue();
        return -1;
    }

    private String extractPath(String url) {
        try {
            java.net.URI uri = new java.net.URI(url);
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) path = "/";
            if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
            return path;
        } catch (Exception e) {
            return "/";
        }
    }
}
