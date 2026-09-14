package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.praetor.handlers.http.CurlSender;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.util.JsonUtil;

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
        HttpRequestResponse result = com.praetor.http.ProxyTunnel.sendOrFallback(api, request);
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
        String httpVersion = (String) body.get("http_version");

        if (raw == null || host == null) {
            sendError(exchange, 400, "Missing 'raw' and/or 'host'");
            return;
        }

        int port = portObj instanceof Number n ? n.intValue() : 443;
        boolean useHttps = httpsObj instanceof Boolean b ? b : true;

        // Raw HTTP requires CRLF line endings. Callers routinely paste LF-only
        // bodies (JSON tool args, heredocs), which Montoya forwards verbatim —
        // and an LF-framed request line breaks Burp's upstream HTTP/2
        // translation ("Stream failed to close correctly"). Normalise to CRLF.
        raw = normalizeCrlf(raw);

        // Auto-attach the target's cookies from Burp's cookie jar when the raw
        // request carries no Cookie header of its own (default on; disable with
        // cookie_jar=false). A routing-SSRF / host-header raw send addresses the
        // internal target in the Host header, but the SESSION cookie that gets
        // it past the front-end belongs to the real service host — easy to omit
        // by hand and then misread the resulting auth 403 as a delivery failure.
        boolean useCookieJar = !Boolean.FALSE.equals(body.get("cookie_jar"));
        String cookieNote = null;
        if (useCookieJar && !hasHeader(raw, "Cookie")) {
            String jar = cookieHeaderFromJar(host);
            if (!jar.isEmpty()) {
                raw = insertHeaderBeforeBody(raw, "Cookie: " + jar);
                cookieNote = "auto-attached " + (jar.split("; ").length)
                    + " cookie(s) from Burp jar for " + host
                    + " (raw had no Cookie header; disable with cookie_jar=false)";
            } else {
                cookieNote = "no cookies in Burp jar for " + host
                    + " — sent unauthenticated (browse the target through Burp first, "
                    + "or pass a Cookie header)";
            }
        }

        // Scope check: synthesize URL from host/port/https for the gate.
        String synthUrl = (useHttps ? "https://" : "http://") + host
            + (port != (useHttps ? 443 : 80) ? ":" + port : "") + "/";
        if (!requireInScope(api, exchange, synthUrl)) return;

        HttpService service = HttpService.httpService(host, port, useHttps);
        HttpRequest request = HttpRequest.httpRequest(service, raw);

        int preSize = api.proxy().history().size();
        HttpMode mode = parseHttpMode(httpVersion);
        String target = requestTarget(raw);
        boolean absoluteTarget = target != null
            && (target.startsWith("http://") || target.startsWith("https://"));

        HttpRequestResponse result;
        if (absoluteTarget) {
            // Routing-based SSRF / host-header attack: the request-target is an
            // absolute URI (GET https://target/path) and the Host header may
            // diverge from it — that divergence IS the payload. Every path
            // through Burp normalises the absolute target to origin-form (GET
            // /path) — Montoya's api.http()/toByteArray() re-serialize it, and
            // the proxy listener rewrites it even inside a CONNECT tunnel —
            // silently degrading the attack to a plain modified-Host request the
            // target blocks. Only a direct HTTP/1 socket to the target delivers
            // the exact bytes on the wire. Direct send => Logger-style, not
            // Proxy history (documented on the tool).
            byte[] wireBytes = raw.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
            result = com.praetor.http.ProxyTunnel.sendDirectVerbatim(api, service, wireBytes, request);
            if (result == null) {
                result = com.praetor.http.ProxyTunnel.sendOrFallback(api, request);
            }
        } else if (mode != null) {
            // Caller pinned the wire protocol on an origin-form request. Burp
            // controls the wire protocol only on its own HTTP stack, so a
            // pinned version goes direct via api.http() (Logger-visible).
            result = api.http().sendRequest(request, mode);
        } else {
            result = com.praetor.http.ProxyTunnel.sendOrFallback(api, request);
        }
        maybeWarnHttp2(result);
        sendResponseJson(exchange, result, preSize, cookieNote);
    }

    /** True when the raw request already carries a header with this name (case-insensitive). */
    static boolean hasHeader(String raw, String name) {
        int sep = raw.indexOf("\r\n\r\n");
        String headerBlock = sep < 0 ? raw : raw.substring(0, sep);
        for (String line : headerBlock.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase(name)) return true;
        }
        return false;
    }

    /**
     * Insert a full header line ("Name: value") just before the blank line that
     * ends the header block. Returns the input unchanged if it has no proper
     * "\r\n\r\n" terminator (nothing safe to do).
     */
    static String insertHeaderBeforeBody(String raw, String headerLine) {
        int sep = raw.indexOf("\r\n\r\n");
        if (sep < 0) return raw;
        return raw.substring(0, sep) + "\r\n" + headerLine + raw.substring(sep);
    }

    /**
     * Build a "name=value; name2=value2" Cookie header from Burp's cookie jar
     * for cookies whose domain covers {@code host} (exact, leading-dot, or
     * parent-domain suffix). Empty string when the jar has nothing for the host.
     */
    private String cookieHeaderFromJar(String host) {
        StringBuilder sb = new StringBuilder();
        for (var c : api.http().cookieJar().cookies()) {
            String d = c.domain();
            if (d == null || d.isEmpty()) continue;
            String bare = d.startsWith(".") ? d.substring(1) : d;
            if (host.equals(bare) || host.endsWith("." + bare)) {
                if (sb.length() > 0) sb.append("; ");
                sb.append(c.name()).append("=").append(c.value());
            }
        }
        return sb.toString();
    }

    /**
     * Burp answers "Stream failed to close correctly" (HTTP 200, tiny HTML)
     * when it upgraded the upstream leg to HTTP/2 and the request could not be
     * expressed there — the classic case being a Host header that diverges
     * from the connection authority (routing-based SSRF / host-header
     * attacks), which HTTP/2 binds to the SNI. Surface the exact operator
     * remedy instead of returning the opaque error body.
     */
    private void maybeWarnHttp2(HttpRequestResponse result) {
        if (result == null || result.response() == null) return;
        String body = result.response().bodyToString();
        if (body != null && body.contains("Stream failed to close correctly")) {
            api.logging().logToOutput(
                "Praetor: upstream HTTP/2 rejected this request (\"Stream failed to close correctly\"). "
                + "For routing-based SSRF / host-header attacks with a divergent Host, turn OFF "
                + "Burp Settings → Network → HTTP → \"Default to HTTP/2 if the server supports it\" "
                + "so the upstream leg uses HTTP/1, then resend.");
        }
    }

    /**
     * Extract the request-target (2nd token of the request line) from a raw
     * HTTP request. Returns null if the request line is malformed. May be an
     * absolute URI (GET https://host/path ...) or origin-form (GET /path ...).
     */
    static String requestTarget(String raw) {
        if (raw == null || raw.isEmpty()) return null;
        int nl = raw.indexOf('\n');
        String line = (nl >= 0 ? raw.substring(0, nl) : raw).trim();
        String[] parts = line.split(" ");
        return parts.length >= 2 ? parts[1] : null;
    }

    /**
     * Map a caller-supplied HTTP version string to a Montoya {@link HttpMode}.
     * Returns null when unspecified/blank — the caller then keeps the default
     * proxy-tunnel path (AUTO negotiation, Proxy-history visible).
     */
    static HttpMode parseHttpMode(String version) {
        if (version == null) return null;
        String v = version.trim().toLowerCase();
        return switch (v) {
            case "auto" -> HttpMode.AUTO;
            case "1", "1.0", "1.1", "http/1", "http/1.1" -> HttpMode.HTTP_1;
            case "2", "2.0", "http/2", "http/2.0" -> HttpMode.HTTP_2;
            default -> null;
        };
    }

    /** Normalise any mix of CR, LF, CRLF to CRLF. Idempotent on well-formed input. */
    static String normalizeCrlf(String s) {
        return s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n");
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
        HttpRequestResponse result = com.praetor.http.ProxyTunnel.sendOrFallback(api, modified);
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
        sendResponseJson(exchange, result, preSendHistorySize, null);
    }

    private void sendResponseJson(HttpExchange exchange, HttpRequestResponse result, int preSendHistorySize, String note) throws Exception {
        if (result == null) {
            String why = com.praetor.http.ProxyTunnel.lastSendError();
            sendError(exchange, 502,
                "No response from target" + (why.isEmpty() ? "" : " — " + why),
                "send_failed",
                "Check target reachability and Burp proxy listener at 127.0.0.1:8080.");
            return;
        }
        HttpResponse resp = result.response();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status_code", resp != null ? resp.statusCode() : 0);
        if (note != null && !note.isEmpty()) out.put("cookie_jar", note);

        // Resolve the proxy history index by matching the request we actually
        // sent against the entries added since the send — not history.size()-1,
        // which is the wrong entry whenever concurrent traffic landed after it.
        int idx = com.praetor.util.ProxyHistoryLocator.locate(api, result.request(), preSendHistorySize);
        if (idx >= 0) {
            out.put("history_index", idx);
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
            int cap = com.praetor.server.ResponseLimits.MAX_RESPONSE_BODY;
            if (body.length() > cap) {
                int half = cap / 2;
                body = body.substring(0, half)
                    + "\n\n[... TRUNCATED " + (body.length() - cap) + " chars ...]\n\n"
                    + body.substring(body.length() - half);
            }
            out.put("response_body", body);
            out.put("response_length", resp.body().length());
            if (body.contains("Stream failed to close correctly")) {
                out.put("http2_hint", "Burp upgraded the upstream leg to HTTP/2 and could not "
                    + "express this request (a divergent Host is bound to the SNI over HTTP/2). "
                    + "For routing-based SSRF / host-header attacks, turn OFF Burp Settings -> "
                    + "Network -> HTTP -> \"Default to HTTP/2 if the server supports it\", then resend.");
            }
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
