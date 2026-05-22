package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.swissknife.handlers.http.CurlSender;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

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
    private final CurlSender curlSender;

    public HttpSendHandler(MontoyaApi api) {
        this.api = api;
        this.curlSender = new CurlSender(api);
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
            case "/api/http/curl" -> curlSender.handle(exchange, body);
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

        if (!requireInScope(api, exchange, url)) return;

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
        int preSize = api.proxy().history().size();
        HttpRequestResponse result = com.swissknife.http.ProxyTunnel.sendOrFallback(api, request);
        sendResponseJson(exchange, result, preSize);
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

        // Scope check: synthesize URL from host/port/https for the gate.
        String synthUrl = (useHttps ? "https://" : "http://") + host
            + (port != (useHttps ? 443 : 80) ? ":" + port : "") + "/";
        if (!requireInScope(api, exchange, synthUrl)) return;

        HttpService service = HttpService.httpService(host, port, useHttps);
        HttpRequest request = HttpRequest.httpRequest(service, raw);

        int preSize = api.proxy().history().size();
        HttpRequestResponse result = com.swissknife.http.ProxyTunnel.sendOrFallback(api, request);
        sendResponseJson(exchange, result, preSize);
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

        // Scope check on the (possibly modified) target URL. If the caller
        // changes the path, scope still gates by host so the original URL is
        // a sufficient proxy for "where the resend lands".
        if (!requireInScope(api, exchange, original.url())) return;

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

        int preSize = api.proxy().history().size();
        HttpRequestResponse result = com.swissknife.http.ProxyTunnel.sendOrFallback(api, modified);
        sendResponseJson(exchange, result, preSize);
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

    // ── Helpers ────────────────────────────────────────────────

    private void sendResponseJson(HttpExchange exchange, HttpRequestResponse result, int preSendHistorySize) throws Exception {
        if (result == null) {
            String why = com.swissknife.http.ProxyTunnel.lastSendError();
            sendError(exchange, 502,
                "No response from target" + (why.isEmpty() ? "" : " — " + why),
                "send_failed",
                "Check target reachability and Burp proxy listener at 127.0.0.1:8080.");
            return;
        }
        HttpResponse resp = result.response();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status_code", resp != null ? resp.statusCode() : 0);

        // Resolve proxy history index: new entry should be at preSendHistorySize
        int postSize = api.proxy().history().size();
        if (postSize > preSendHistorySize) {
            out.put("history_index", postSize - 1);
        } else {
            out.put("history_index", -1);
            out.put("history_note", "Request did not appear in proxy history (sent via HTTP client, visible in Logger)");
        }

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
            int cap = com.swissknife.server.ResponseLimits.MAX_RESPONSE_BODY;
            if (body.length() > cap) {
                int half = cap / 2;
                body = body.substring(0, half)
                    + "\n\n[... TRUNCATED " + (body.length() - cap) + " chars ...]\n\n"
                    + body.substring(body.length() - half);
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
