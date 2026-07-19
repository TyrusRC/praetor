package com.praetor.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.praetor.handlers.Session;
import com.praetor.http.HttpExchange;
import static com.praetor.http.HttpResponses.sendJson;
import static com.praetor.http.HttpResponses.sendError;
import com.praetor.server.BaseHandler;
import com.praetor.store.SessionStore;
import com.praetor.ui.ConfigTab;
import com.praetor.util.JsonUtil;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Owns the actual HTTP-send work for sessions: cookie jar merge,
 * Authorization injection, body resolution, redirect-following, response-map
 * construction. Extracted verbatim from SessionHandler.
 *
 * Exposes:
 *  - {@link #send(Session, Map)} — pure sender used by every collaborator
 *  - {@link #handle(HttpExchange, Map, SessionStore)} — full route handler
 *    for {@code POST /api/session/request}
 *  - {@link #updateCookiesFromResponse(Session, HttpRequestResponse)} —
 *    cookie-jar update used by every collaborator after each send
 *  - {@link #buildResponseMap(HttpRequestResponse)} — response-shape builder
 *  - {@link #extractTitle(String)} — shared helper for batch/discover
 */
public final class SessionRequestExecutor {

    private static final int MAX_RESPONSE_SIZE = com.praetor.server.ResponseLimits.MAX_RESPONSE_BODY;

    private final MontoyaApi api;

    public SessionRequestExecutor(MontoyaApi api) {
        this.api = api;
    }

    public MontoyaApi api() {
        return api;
    }

    // ── POST /api/session/request route ──────────────────────────────

    public void handle(HttpExchange exchange, Map<String, Object> body, SessionStore store) throws Exception {
        String name = (String) body.get("session");
        if (name == null) {
            sendError(exchange, 400, "Missing 'session' name");
            return;
        }

        Session session = store.getSession(name);
        if (session == null) {
            sendError(exchange, 404, "Session not found: " + name);
            return;
        }

        synchronized (session) {
            long startNanos = System.nanoTime();
            HttpRequestResponse result = send(session, body);
            long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;

            if (result == null) {
                sendError(exchange, 500, "Failed to send request");
                return;
            }

            session.lastResponse = result;
            updateCookiesFromResponse(session, result);

            Map<String, String> extracted = new LinkedHashMap<>();
            List<String> extractWarnings = Collections.emptyList();
            @SuppressWarnings("unchecked")
            Map<String, Object> extractRules = (Map<String, Object>) body.get("extract");
            if (extractRules != null) {
                extracted = VariableExtractor.extractFromResponse(result, extractRules);
                extractWarnings = new ArrayList<>(VariableExtractor.LAST_EXTRACT_WARNINGS.get());
                VariableExtractor.LAST_EXTRACT_WARNINGS.remove();
                VariableExtractor.mergeVariables(session, extracted);
            }

            Map<String, Object> out = buildResponseMap(result);
            out.put("response_time_ms", elapsedMs);
            ConfigTab.log("session_request: " + body.getOrDefault("method", "GET") + " " + body.getOrDefault("path", "/") + " -> " + (result.response() != null ? result.response().statusCode() : 0) + " (" + elapsedMs + "ms)");
            out.put("extracted", extracted);
            if (!extractWarnings.isEmpty()) {
                out.put("extract_warnings", extractWarnings);
            }
            out.put("session_cookies", new LinkedHashMap<>(session.cookies));
            out.put("session_variables", new LinkedHashMap<>(session.variables));

            Object analyzeFlag = body.get("analyze");
            if (analyzeFlag instanceof Boolean b && b && result.response() != null) {
                Map<String, Object> analysis = new LinkedHashMap<>();
                HttpRequest req = result.request();
                HttpResponse resp = result.response();
                analysis.put("tech_stack", com.praetor.analysis.TechStackDetector.detect(resp));
                analysis.put("injection_points", com.praetor.analysis.InjectionPointDetector.detect(req, resp));
                analysis.put("parameters", com.praetor.analysis.ParameterExtractor.extract(req));
                String contentType = resp.headerValue("Content-Type") != null ? resp.headerValue("Content-Type") : "";
                if (contentType.contains("html")) {
                    String bodyStr = resp.bodyToString();
                    analysis.put("forms", com.praetor.analysis.FormExtractor.extract(bodyStr));
                    analysis.put("endpoints", com.praetor.analysis.EndpointExtractor.extract(bodyStr, req.url()));
                }
                if (contentType.contains("javascript") || contentType.contains("html")) {
                    analysis.put("secrets", com.praetor.analysis.JsSecretExtractor.extract(resp.bodyToString()));
                }
                out.put("analysis", analysis);
            }

            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

    // ── Core send (used by handleSessionRequest + flow + probes + batch + discover + auto-probe) ──

    public HttpRequestResponse send(Session session, Map<String, Object> params) {
        Object methodObj = params.get("method");
        String method = (methodObj instanceof String s && !s.isBlank()) ? s : "GET";
        Object pathObj = params.get("path");
        String path = (pathObj instanceof String p && !p.isBlank()) ? p : "/";
        String url = (String) params.get("url");

        String fullUrl;
        if (url != null && !url.isBlank()) {
            fullUrl = url;
        } else if (!session.baseUrl.isEmpty()) {
            String base = session.baseUrl;
            if (base.endsWith("/") && path.startsWith("/")) {
                base = base.substring(0, base.length() - 1);
            }
            fullUrl = base + path;
        } else {
            fullUrl = path;
        }

        // Scope gate (Rule 1 HARD): all session-driven outbound goes through this.
        if (!ScopeGate.isInScopeQuiet(api, fullUrl)) {
            ConfigTab.log("session_request: dropped out-of-scope URL " + fullUrl);
            return null;
        }

        try {
            URI uri;
            try {
                uri = new URI(fullUrl);
            } catch (java.net.URISyntaxException e) {
                uri = buildSafeUri(fullUrl);
            }
            String host = uri.getHost();
            int port = uri.getPort();
            boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());
            if (port == -1) port = isHttps ? 443 : 80;

            String requestPath = uri.getRawPath();
            if (requestPath == null || requestPath.isEmpty()) requestPath = "/";
            String rawQuery = uri.getRawQuery();
            if (rawQuery != null) {
                requestPath += "?" + rawQuery;
            } else {
                int qIdx = fullUrl.indexOf('?');
                if (qIdx > 0) {
                    String queryPart = fullUrl.substring(qIdx + 1);
                    if (!queryPart.isEmpty()) requestPath += "?" + queryPart;
                }
            }

            HttpService service = HttpService.httpService(host, port, isHttps);

            HttpRequest request = HttpRequest.httpRequest()
                .withMethod(method.toUpperCase())
                .withPath(requestPath)
                .withService(service)
                .withHeader("Host", host);

            for (var entry : session.headers.entrySet()) {
                request = request.withHeader(entry.getKey(), entry.getValue());
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> reqHeaders = (Map<String, Object>) params.get("headers");
            if (reqHeaders != null) {
                for (var entry : reqHeaders.entrySet()) {
                    request = request.withHeader(entry.getKey(), String.valueOf(entry.getValue()));
                }
            }

            if (!session.bearerToken.isEmpty()) {
                request = request.withHeader("Authorization", "Bearer " + session.bearerToken);
            } else if (!session.authUser.isEmpty()) {
                String creds = Base64.getEncoder().encodeToString(
                    (session.authUser + ":" + session.authPass).getBytes(StandardCharsets.UTF_8));
                request = request.withHeader("Authorization", "Basic " + creds);
            }

            Map<String, String> mergedCookies = new LinkedHashMap<>(session.cookies);
            @SuppressWarnings("unchecked")
            Map<String, Object> reqCookies = (Map<String, Object>) params.get("cookies");
            if (reqCookies != null) {
                reqCookies.forEach((k, v) -> mergedCookies.put(k, String.valueOf(v)));
            }
            if (!mergedCookies.isEmpty()) {
                StringBuilder cookieHeader = new StringBuilder();
                for (var entry : mergedCookies.entrySet()) {
                    if (cookieHeader.length() > 0) cookieHeader.append("; ");
                    cookieHeader.append(entry.getKey()).append("=").append(entry.getValue());
                }
                request = request.withHeader("Cookie", cookieHeader.toString());
            }

            request = resolveBody(request, params, session.variables);

            HttpRequestResponse result = com.praetor.http.ProxyTunnel.sendOrFallback(api, request);

            Object followFlag = params.get("follow_redirects");
            boolean followRedirects = followFlag instanceof Boolean b && b;
            int maxRedirects = 10;
            int redirectCount = 0;

            while (followRedirects && result != null && result.response() != null && redirectCount < maxRedirects) {
                int statusCode = result.response().statusCode();
                if (statusCode < 300 || statusCode >= 400) break;

                String location = null;
                for (HttpHeader h : result.response().headers()) {
                    if ("Location".equalsIgnoreCase(h.name())) {
                        location = h.value();
                        break;
                    }
                }
                if (location == null || location.isEmpty()) break;

                if (location.startsWith("/")) {
                    location = (redirectCount == 0 ? uri.getScheme() : (isHttps ? "https" : "http"))
                        + "://" + host + (port != 80 && port != 443 ? ":" + port : "") + location;
                } else if (!location.startsWith("http")) {
                    String basePath = requestPath.contains("/") ? requestPath.substring(0, requestPath.lastIndexOf('/') + 1) : "/";
                    location = uri.getScheme() + "://" + host + (port != 80 && port != 443 ? ":" + port : "") + basePath + location;
                }

                updateCookiesFromResponse(session, result);

                URI redirectUri = new URI(location);
                String redirPath = redirectUri.getRawPath();
                if (redirPath == null || redirPath.isEmpty()) redirPath = "/";
                if (redirectUri.getRawQuery() != null) redirPath += "?" + redirectUri.getRawQuery();

                String redirHost = redirectUri.getHost() != null ? redirectUri.getHost() : host;
                int redirPort = redirectUri.getPort() > 0 ? redirectUri.getPort() : port;
                boolean redirHttps = "https".equalsIgnoreCase(redirectUri.getScheme());

                String origMethod = result.request() != null ? result.request().method() : method;
                String redirMethod;
                boolean preserveBody;
                if (statusCode == 307 || statusCode == 308) {
                    redirMethod = origMethod;
                    preserveBody = true;
                } else if (statusCode == 303) {
                    redirMethod = "GET";
                    preserveBody = false;
                } else {
                    redirMethod = ("GET".equalsIgnoreCase(origMethod) || "HEAD".equalsIgnoreCase(origMethod)) ? origMethod : "GET";
                    preserveBody = !"GET".equalsIgnoreCase(redirMethod);
                }

                boolean sameOrigin = redirHost.equalsIgnoreCase(host)
                    && redirPort == port
                    && redirHttps == isHttps;

                HttpRequest redirReq = HttpRequest.httpRequest()
                    .withMethod(redirMethod)
                    .withPath(redirPath)
                    .withService(HttpService.httpService(redirHost, redirPort, redirHttps))
                    .withHeader("Host", redirHost);

                if (result.request() != null) {
                    for (HttpHeader h : result.request().headers()) {
                        String name = h.name();
                        if ("Host".equalsIgnoreCase(name) || "Content-Length".equalsIgnoreCase(name)) continue;
                        if (!sameOrigin && (
                                "Authorization".equalsIgnoreCase(name)
                                || "Cookie".equalsIgnoreCase(name)
                                || "Cookie2".equalsIgnoreCase(name)
                                || "Proxy-Authorization".equalsIgnoreCase(name)
                                || name.toLowerCase().startsWith("x-auth")
                                || name.toLowerCase().startsWith("x-api")
                                || name.toLowerCase().startsWith("x-csrf"))) {
                            continue;
                        }
                        redirReq = redirReq.withHeader(name, h.value());
                    }
                    if (preserveBody && result.request().body() != null && result.request().body().length() > 0) {
                        redirReq = redirReq.withBody(result.request().body());
                    }
                }

                if (sameOrigin && !session.cookies.isEmpty()) {
                    StringBuilder cb = new StringBuilder();
                    for (var e2 : session.cookies.entrySet()) {
                        if (cb.length() > 0) cb.append("; ");
                        cb.append(e2.getKey()).append("=").append(e2.getValue());
                    }
                    redirReq = redirReq.withHeader("Cookie", cb.toString());
                }

                result = com.praetor.http.ProxyTunnel.sendOrFallback(api, redirReq);
                host = redirHost;
                port = redirPort;
                isHttps = redirHttps;
                redirectCount++;
            }

            return result;
        } catch (Exception e) {
            return null;
        }
    }

    // ── Cookie jar updates ──

    public void updateCookiesFromResponse(Session session, HttpRequestResponse result) {
        HttpResponse resp = result.response();
        if (resp == null) return;

        for (HttpHeader header : resp.headers()) {
            if ("Set-Cookie".equalsIgnoreCase(header.name())) {
                String value = header.value();
                if (value == null || value.isEmpty()) continue;

                int semi = value.indexOf(';');
                String nameValue = semi > 0 ? value.substring(0, semi).trim() : value.trim();
                int eq = nameValue.indexOf('=');
                if (eq > 0) {
                    String cookieName = nameValue.substring(0, eq).trim();
                    String cookieVal = nameValue.substring(eq + 1).trim();
                    session.cookies.put(cookieName, cookieVal);
                }
            }
        }

        while (session.cookies.size() > 200) {
            String oldest = session.cookies.keySet().iterator().next();
            session.cookies.remove(oldest);
        }
    }

    // ── Body resolution ──

    private HttpRequest resolveBody(HttpRequest request, Map<String, Object> params, Map<String, String> variables) {
        @SuppressWarnings("unchecked")
        Map<String, Object> jsonBody = (Map<String, Object>) params.get("json_body");
        if (jsonBody != null) {
            request = request.withHeader("Content-Type", "application/json");
            return request.withBody(JsonUtil.toJson(jsonBody));
        }

        String data = (String) params.get("data");
        if (data != null && !data.isEmpty()) {
            request = request.withHeader("Content-Type", "application/x-www-form-urlencoded");
            return request.withBody(VariableExtractor.interpolateString(data, variables));
        }

        String body = (String) params.get("body");
        if (body != null && !body.isEmpty()) {
            return request.withBody(VariableExtractor.interpolateString(body, variables));
        }

        return request;
    }

    // ── Response formatting ──

    public Map<String, Object> buildResponseMap(HttpRequestResponse result) {
        Map<String, Object> out = new LinkedHashMap<>();
        HttpRequest req = result.request();
        if (req != null) {
            out.put("url", req.url());
        }
        HttpResponse resp = result.response();

        out.put("status", resp != null ? resp.statusCode() : 0);
        out.put("response_length", resp != null ? resp.body().length() : 0);

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
        }

        return out;
    }

    public static String extractTitle(String html) {
        if (html == null) return null;
        int start = html.indexOf("<title>");
        if (start < 0) start = html.indexOf("<TITLE>");
        if (start < 0) return null;
        start += 7;
        int end = html.indexOf("</title>", start);
        if (end < 0) end = html.indexOf("</TITLE>", start);
        if (end < 0 || end - start > 200) return null;
        return html.substring(start, end).trim();
    }

    /**
     * Build a URI from a URL string that may contain unencoded special chars.
     */
    private URI buildSafeUri(String fullUrl) throws java.net.URISyntaxException {
        int schemeEnd = fullUrl.indexOf("://");
        if (schemeEnd < 0) throw new java.net.URISyntaxException(fullUrl, "No scheme");
        String scheme = fullUrl.substring(0, schemeEnd);
        String rest = fullUrl.substring(schemeEnd + 3);

        int pathStart = rest.indexOf('/');
        String hostPort = pathStart >= 0 ? rest.substring(0, pathStart) : rest;
        String pathAndQuery = pathStart >= 0 ? rest.substring(pathStart) : "/";

        String host;
        int port = -1;
        int colonIdx = hostPort.lastIndexOf(':');
        if (colonIdx > 0) {
            host = hostPort.substring(0, colonIdx);
            try { port = Integer.parseInt(hostPort.substring(colonIdx + 1)); }
            catch (NumberFormatException e) { host = hostPort; }
        } else {
            host = hostPort;
        }

        String path = pathAndQuery;
        String query = null;
        int qIdx = pathAndQuery.indexOf('?');
        if (qIdx >= 0) {
            path = pathAndQuery.substring(0, qIdx);
            query = pathAndQuery.substring(qIdx + 1);
        }

        String encodedPath = java.net.URLEncoder.encode(path, java.nio.charset.StandardCharsets.UTF_8)
                .replace("%2F", "/")
                .replace("+", "%20");

        return new URI(scheme, null, host, port, encodedPath, query, null);
    }

    // ── Local error/JSON helpers (mirrors BaseHandler envelope) ──

}
