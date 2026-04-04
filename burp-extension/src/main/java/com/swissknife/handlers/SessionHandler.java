package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Manages persistent attack sessions with cookie jar, auth token storage,
 * variable extraction, and multi-step flow execution.
 *
 * POST   /api/session/create   — create session
 * POST   /api/session/request  — send request with session state
 * POST   /api/session/extract  — extract values from last response
 * POST   /api/session/flow     — execute multi-step flow
 * GET    /api/session/list     — list all sessions
 * DELETE /api/session/{name}   — delete a session
 */
public class SessionHandler extends BaseHandler {

    private static final int MAX_RESPONSE_SIZE = 50000;

    private final MontoyaApi api;

    /** Package-accessible so AttackHandler can share sessions. */
    final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public SessionHandler(MontoyaApi api) {
        this.api = api;
    }

    /** Returns the shared sessions map for use by AttackHandler. */
    public Map<String, Session> getSessions() {
        return sessions;
    }

    // ── Session model ─────────────────────────────────────────────

    static class Session {
        String name;
        String baseUrl;
        Map<String, String> cookies = new LinkedHashMap<>();
        Map<String, String> headers = new LinkedHashMap<>();
        Map<String, String> variables = new LinkedHashMap<>();
        String bearerToken = "";
        String authUser = "";
        String authPass = "";
        HttpRequestResponse lastResponse;
    }

    // ── Routing ───────────────────────────────────────────────────

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();

        switch (method.toUpperCase()) {
            case "GET" -> {
                if ("/api/session/list".equals(path)) {
                    handleList(exchange);
                } else {
                    sendError(exchange, 404, "Not found");
                }
            }
            case "POST" -> {
                Map<String, Object> body = readJsonBody(exchange);
                switch (path) {
                    case "/api/session/create" -> handleCreate(exchange, body);
                    case "/api/session/request" -> handleSessionRequest(exchange, body);
                    case "/api/session/extract" -> handleExtract(exchange, body);
                    case "/api/session/flow" -> handleFlow(exchange, body);
                    default -> sendError(exchange, 404, "Not found");
                }
            }
            case "DELETE" -> {
                // /api/session/{name}
                String name = pathSegment(exchange, 2); // api=0, session=1, {name}=2
                if (name != null) {
                    handleDelete(exchange, name);
                } else {
                    sendError(exchange, 400, "Missing session name in path");
                }
            }
            default -> sendError(exchange, 405, "Method not allowed");
        }
    }

    // ── POST /api/session/create ──────────────────────────────────

    private void handleCreate(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String name = (String) body.get("name");
        if (name == null || name.isBlank()) {
            sendError(exchange, 400, "Missing 'name'");
            return;
        }

        Session session = new Session();
        session.name = name;
        session.baseUrl = (String) body.getOrDefault("base_url", "");

        @SuppressWarnings("unchecked")
        Map<String, Object> cookies = (Map<String, Object>) body.get("cookies");
        if (cookies != null) {
            cookies.forEach((k, v) -> session.cookies.put(k, String.valueOf(v)));
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> headers = (Map<String, Object>) body.get("headers");
        if (headers != null) {
            headers.forEach((k, v) -> session.headers.put(k, String.valueOf(v)));
        }

        String bearer = (String) body.get("bearer_token");
        if (bearer != null) session.bearerToken = bearer;

        String authUser = (String) body.get("auth_user");
        if (authUser != null) session.authUser = authUser;

        String authPass = (String) body.get("auth_pass");
        if (authPass != null) session.authPass = authPass;

        sessions.put(name, session);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("session", name);
        out.put("base_url", session.baseUrl);
        out.put("cookies", session.cookies.size());
        out.put("headers", session.headers.size());
        out.put("has_auth", !session.bearerToken.isEmpty() || !session.authUser.isEmpty());
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── POST /api/session/request ─────────────────────────────────

    private void handleSessionRequest(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String name = (String) body.get("session");
        if (name == null) {
            sendError(exchange, 400, "Missing 'session' name");
            return;
        }

        Session session = sessions.get(name);
        if (session == null) {
            sendError(exchange, 404, "Session not found: " + name);
            return;
        }

        synchronized (session) {
            HttpRequestResponse result = sendSessionRequest(session, body);
            if (result == null) {
                sendError(exchange, 500, "Failed to send request");
                return;
            }

            session.lastResponse = result;
            updateCookiesFromResponse(session, result);

            // Inline extraction
            Map<String, String> extracted = new LinkedHashMap<>();
            @SuppressWarnings("unchecked")
            Map<String, Object> extractRules = (Map<String, Object>) body.get("extract");
            if (extractRules != null) {
                extracted = extractFromResponse(result, extractRules);
                session.variables.putAll(extracted);
            }

            Map<String, Object> out = buildResponseMap(result);
            out.put("extracted", extracted);
            out.put("session_cookies", new LinkedHashMap<>(session.cookies));
            out.put("session_variables", new LinkedHashMap<>(session.variables));

            // Auto-analyze if requested (for quick_scan tool)
            Object analyzeFlag = body.get("analyze");
            if (analyzeFlag instanceof Boolean b && b && result.response() != null) {
                Map<String, Object> analysis = new LinkedHashMap<>();
                HttpRequest req = result.request();
                HttpResponse resp = result.response();
                analysis.put("tech_stack", com.swissknife.analysis.TechStackDetector.detect(resp));
                analysis.put("injection_points", com.swissknife.analysis.InjectionPointDetector.detect(req, resp));
                analysis.put("parameters", com.swissknife.analysis.ParameterExtractor.extract(req));
                String contentType = resp.headerValue("Content-Type") != null ? resp.headerValue("Content-Type") : "";
                if (contentType.contains("html")) {
                    String bodyStr = resp.bodyToString();
                    analysis.put("forms", com.swissknife.analysis.FormExtractor.extract(bodyStr));
                    analysis.put("endpoints", com.swissknife.analysis.EndpointExtractor.extract(bodyStr, req.url()));
                }
                if (contentType.contains("javascript") || contentType.contains("html")) {
                    analysis.put("secrets", com.swissknife.analysis.JsSecretExtractor.extract(resp.bodyToString()));
                }
                out.put("analysis", analysis);
            }

            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

    // ── POST /api/session/extract ─────────────────────────────────

    private void handleExtract(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String name = (String) body.get("session");
        if (name == null) {
            sendError(exchange, 400, "Missing 'session' name");
            return;
        }

        Session session = sessions.get(name);
        if (session == null) {
            sendError(exchange, 404, "Session not found: " + name);
            return;
        }

        synchronized (session) {
            if (session.lastResponse == null) {
                sendError(exchange, 400, "No previous response in session");
                return;
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> rules = (Map<String, Object>) body.get("extract");
            if (rules == null) {
                // Also accept "rules" for backwards compat
                rules = (Map<String, Object>) body.get("rules");
            }
            if (rules == null) {
                sendError(exchange, 400, "Missing 'extract'");
                return;
            }

            Map<String, String> extracted = extractFromResponse(session.lastResponse, rules);
            session.variables.putAll(extracted);

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("status", "ok");
            out.put("extracted", extracted);
            out.put("session_variables", new LinkedHashMap<>(session.variables));
            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

    // ── POST /api/session/flow ────────────────────────────────────

    private void handleFlow(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String name = (String) body.get("session");
        if (name == null) {
            sendError(exchange, 400, "Missing 'session' name");
            return;
        }

        Session session = sessions.get(name);
        if (session == null) {
            sendError(exchange, 404, "Session not found: " + name);
            return;
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> steps = (List<Map<String, Object>>) body.get("steps");
        if (steps == null || steps.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'steps'");
            return;
        }

        synchronized (session) {
            List<Map<String, Object>> results = new ArrayList<>();
            int stepsExecuted = 0;

            for (Map<String, Object> rawStep : steps) {
                stepsExecuted++;

                // Interpolate variables into step
                Map<String, Object> step = interpolateStep(rawStep, session.variables);

                HttpRequestResponse result = sendSessionRequest(session, step);
                if (result == null) {
                    Map<String, Object> stepResult = new LinkedHashMap<>();
                    stepResult.put("step", stepsExecuted);
                    stepResult.put("error", "Failed to send request");
                    results.add(stepResult);
                    break;
                }

                session.lastResponse = result;
                updateCookiesFromResponse(session, result);

                // Per-step extraction
                Map<String, String> extracted = new LinkedHashMap<>();
                @SuppressWarnings("unchecked")
                Map<String, Object> extractRules = (Map<String, Object>) step.get("extract");
                if (extractRules != null) {
                    extracted = extractFromResponse(result, extractRules);
                    session.variables.putAll(extracted);
                }

                Map<String, Object> stepResult = new LinkedHashMap<>();
                stepResult.put("step", stepsExecuted);
                stepResult.put("method", step.getOrDefault("method", "GET"));
                stepResult.put("path", step.getOrDefault("path", "/"));
                HttpResponse resp = result.response();
                stepResult.put("status", resp != null ? resp.statusCode() : 0);
                stepResult.put("response_length", resp != null ? resp.body().length() : 0);
                stepResult.put("extracted", extracted);
                results.add(stepResult);

                // Stop on 4xx/5xx errors unless continue_on_error
                // 3xx redirects are treated as success (login flows return 302)
                if (resp != null) {
                    int status = resp.statusCode();
                    if (status >= 400) {
                        Object continueFlag = step.get("continue_on_error");
                        boolean shouldContinue = continueFlag instanceof Boolean b && b;
                        if (!shouldContinue) break;
                    }
                }
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("steps_executed", stepsExecuted);
            out.put("total_steps", steps.size());
            out.put("results", results);
            out.put("session_variables", new LinkedHashMap<>(session.variables));
            out.put("session_cookies", new LinkedHashMap<>(session.cookies));
            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

    // ── GET /api/session/list ─────────────────────────────────────

    private void handleList(HttpExchange exchange) throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        for (Session s : sessions.values()) {
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", s.name);
            info.put("base_url", s.baseUrl);
            info.put("cookies", s.cookies.size());
            info.put("headers", s.headers.size());
            info.put("variables", s.variables.size());
            info.put("has_auth", !s.bearerToken.isEmpty() || !s.authUser.isEmpty());
            info.put("has_last_response", s.lastResponse != null);
            list.add(info);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sessions", list);
        out.put("total", list.size());
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── DELETE /api/session/{name} ────────────────────────────────

    private void handleDelete(HttpExchange exchange, String name) throws Exception {
        Session removed = sessions.remove(name);
        if (removed == null) {
            sendError(exchange, 404, "Session not found: " + name);
            return;
        }
        sendOk(exchange, "Session deleted: " + name);
    }

    // ── Request building (shared by handleSessionRequest & flow) ──

    private HttpRequestResponse sendSessionRequest(Session session, Map<String, Object> params) {
        String method = (String) params.getOrDefault("method", "GET");
        String path = (String) params.getOrDefault("path", "/");
        String url = (String) params.get("url");

        // Build full URL
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

        try {
            URI uri = new URI(fullUrl);
            String host = uri.getHost();
            int port = uri.getPort();
            boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());
            if (port == -1) port = isHttps ? 443 : 80;

            String requestPath = uri.getRawPath();
            if (requestPath == null || requestPath.isEmpty()) requestPath = "/";
            if (uri.getRawQuery() != null) requestPath += "?" + uri.getRawQuery();

            HttpService service = HttpService.httpService(host, port, isHttps);

            HttpRequest request = HttpRequest.httpRequest()
                .withMethod(method.toUpperCase())
                .withPath(requestPath)
                .withService(service)
                .withHeader("Host", host);

            // Apply session headers first
            for (var entry : session.headers.entrySet()) {
                request = request.withHeader(entry.getKey(), entry.getValue());
            }

            // Apply request-specific headers (override session)
            @SuppressWarnings("unchecked")
            Map<String, Object> reqHeaders = (Map<String, Object>) params.get("headers");
            if (reqHeaders != null) {
                for (var entry : reqHeaders.entrySet()) {
                    request = request.withHeader(entry.getKey(), String.valueOf(entry.getValue()));
                }
            }

            // Auth: Bearer takes precedence over Basic
            if (!session.bearerToken.isEmpty()) {
                request = request.withHeader("Authorization", "Bearer " + session.bearerToken);
            } else if (!session.authUser.isEmpty()) {
                String creds = Base64.getEncoder().encodeToString(
                    (session.authUser + ":" + session.authPass).getBytes(StandardCharsets.UTF_8));
                request = request.withHeader("Authorization", "Basic " + creds);
            }

            // Build Cookie header: merge session cookies + request cookies
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

            // Body handling
            request = resolveBody(request, params, session.variables);

            HttpRequestResponse result = api.http().sendRequest(request);

            // Follow redirects if requested (default: false to preserve raw behavior)
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

                // Resolve relative URLs
                if (location.startsWith("/")) {
                    location = uri.getScheme() + "://" + host + (port != 80 && port != 443 ? ":" + port : "") + location;
                } else if (!location.startsWith("http")) {
                    String basePath = requestPath.contains("/") ? requestPath.substring(0, requestPath.lastIndexOf('/') + 1) : "/";
                    location = uri.getScheme() + "://" + host + (port != 80 && port != 443 ? ":" + port : "") + basePath + location;
                }

                // Update cookies from redirect response
                updateCookiesFromResponse(session, result);

                // Build redirect request (GET, preserve cookies)
                URI redirectUri = new URI(location);
                String redirPath = redirectUri.getRawPath();
                if (redirPath == null || redirPath.isEmpty()) redirPath = "/";
                if (redirectUri.getRawQuery() != null) redirPath += "?" + redirectUri.getRawQuery();

                String redirHost = redirectUri.getHost() != null ? redirectUri.getHost() : host;
                int redirPort = redirectUri.getPort() > 0 ? redirectUri.getPort() : port;
                boolean redirHttps = "https".equalsIgnoreCase(redirectUri.getScheme());

                HttpRequest redirReq = HttpRequest.httpRequest()
                    .withMethod("GET")
                    .withPath(redirPath)
                    .withService(HttpService.httpService(redirHost, redirPort, redirHttps))
                    .withHeader("Host", redirHost);

                // Re-apply session cookies (updated from redirect)
                if (!session.cookies.isEmpty()) {
                    StringBuilder cb = new StringBuilder();
                    for (var e2 : session.cookies.entrySet()) {
                        if (cb.length() > 0) cb.append("; ");
                        cb.append(e2.getKey()).append("=").append(e2.getValue());
                    }
                    redirReq = redirReq.withHeader("Cookie", cb.toString());
                }

                result = api.http().sendRequest(redirReq);
                redirectCount++;
            }

            return result;
        } catch (Exception e) {
            return null;
        }
    }

    // ── Cookie jar updates ────────────────────────────────────────

    private void updateCookiesFromResponse(Session session, HttpRequestResponse result) {
        HttpResponse resp = result.response();
        if (resp == null) return;

        for (HttpHeader header : resp.headers()) {
            if ("Set-Cookie".equalsIgnoreCase(header.name())) {
                String value = header.value();
                if (value == null || value.isEmpty()) continue;

                // Parse name=value before first semicolon
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
    }

    // ── Value extraction ──────────────────────────────────────────

    /**
     * Extract values from a response.
     * Rules map: variable_name -> {source: "body"|"header"|"cookie", regex: "...", name: "...", json_path: "$.key"}
     */
    @SuppressWarnings("unchecked")
    private Map<String, String> extractFromResponse(HttpRequestResponse result, Map<String, Object> rules) {
        Map<String, String> extracted = new LinkedHashMap<>();
        HttpResponse resp = result.response();
        if (resp == null) return extracted;

        for (var entry : rules.entrySet()) {
            String varName = entry.getKey();
            Object ruleObj = entry.getValue();
            if (!(ruleObj instanceof Map)) continue;

            Map<String, Object> rule = (Map<String, Object>) ruleObj;
            // Accept both "from" (Python convention) and "source" (legacy)
            String source = (String) rule.getOrDefault("from", (String) rule.getOrDefault("source", "body"));
            String value = null;

            switch (source) {
                case "body" -> {
                    String bodyStr = resp.bodyToString();
                    String regex = (String) rule.get("regex");
                    String jsonPath = (String) rule.get("json_path");

                    if (regex != null) {
                        value = extractByRegex(bodyStr, regex);
                    } else if (jsonPath != null) {
                        value = simpleJsonExtract(bodyStr, jsonPath);
                    }
                }
                case "header" -> {
                    String headerName = (String) rule.get("name");
                    if (headerName != null) {
                        for (HttpHeader h : resp.headers()) {
                            if (headerName.equalsIgnoreCase(h.name())) {
                                value = h.value();
                                break;
                            }
                        }
                    }
                }
                case "cookie" -> {
                    String cookieName = (String) rule.get("name");
                    if (cookieName != null) {
                        for (HttpHeader h : resp.headers()) {
                            if ("Set-Cookie".equalsIgnoreCase(h.name())) {
                                String cv = h.value();
                                int semi = cv.indexOf(';');
                                String nv = semi > 0 ? cv.substring(0, semi).trim() : cv.trim();
                                int eq = nv.indexOf('=');
                                if (eq > 0 && nv.substring(0, eq).trim().equals(cookieName)) {
                                    value = nv.substring(eq + 1).trim();
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (value != null) {
                extracted.put(varName, value);
            }
        }

        return extracted;
    }

    private String extractByRegex(String text, String regex) {
        try {
            Matcher m = Pattern.compile(regex).matcher(text);
            if (m.find()) {
                return m.groupCount() >= 1 ? m.group(1) : m.group(0);
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Simple JSON path extraction supporting $.key and $.parent.child using regex.
     * Not a full JSON path implementation — handles the common cases.
     */
    private String simpleJsonExtract(String json, String path) {
        if (path == null || !path.startsWith("$.")) return null;

        String[] keys = path.substring(2).split("\\.");
        String current = json;

        for (String key : keys) {
            // Match "key": "value" or "key": number or "key": bool or "key": null
            String pattern = "\"" + Pattern.quote(key) + "\"\\s*:\\s*";
            Matcher m = Pattern.compile(pattern).matcher(current);
            if (!m.find()) return null;

            int valueStart = m.end();
            if (valueStart >= current.length()) return null;

            char first = current.charAt(valueStart);
            if (first == '"') {
                // String value — extract until closing unescaped quote
                int strStart = valueStart + 1;
                int strEnd = strStart;
                while (strEnd < current.length()) {
                    if (current.charAt(strEnd) == '\\') {
                        strEnd += 2;
                        continue;
                    }
                    if (current.charAt(strEnd) == '"') break;
                    strEnd++;
                }
                return current.substring(strStart, strEnd);
            } else if (first == '{' || first == '[') {
                // Nested object/array — slice for next iteration
                current = current.substring(valueStart);
            } else {
                // Number, bool, null — read until comma, }, or ]
                int end = valueStart;
                while (end < current.length() && current.charAt(end) != ',' && current.charAt(end) != '}' && current.charAt(end) != ']') {
                    end++;
                }
                return current.substring(valueStart, end).trim();
            }
        }

        return null;
    }

    // ── Variable interpolation ────────────────────────────────────

    /**
     * Deep-copy a step map, replacing {{variable}} in all string values.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> interpolateStep(Map<String, Object> step, Map<String, String> variables) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (var entry : step.entrySet()) {
            Object val = entry.getValue();
            if (val instanceof String s) {
                result.put(entry.getKey(), interpolateString(s, variables));
            } else if (val instanceof Map) {
                result.put(entry.getKey(), interpolateStep((Map<String, Object>) val, variables));
            } else if (val instanceof List) {
                List<Object> interpolated = new ArrayList<>();
                for (Object item : (List<Object>) val) {
                    if (item instanceof String s) {
                        interpolated.add(interpolateString(s, variables));
                    } else if (item instanceof Map) {
                        interpolated.add(interpolateStep((Map<String, Object>) item, variables));
                    } else {
                        interpolated.add(item);
                    }
                }
                result.put(entry.getKey(), interpolated);
            } else {
                result.put(entry.getKey(), val);
            }
        }
        return result;
    }

    private String interpolateString(String s, Map<String, String> variables) {
        if (s == null || !s.contains("{{")) return s;
        String result = s;
        for (var entry : variables.entrySet()) {
            result = result.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        return result;
    }

    // ── Body resolution ───────────────────────────────────────────

    private HttpRequest resolveBody(HttpRequest request, Map<String, Object> params, Map<String, String> variables) {
        // json_body takes priority
        @SuppressWarnings("unchecked")
        Map<String, Object> jsonBody = (Map<String, Object>) params.get("json_body");
        if (jsonBody != null) {
            request = request.withHeader("Content-Type", "application/json");
            return request.withBody(JsonUtil.toJson(jsonBody));
        }

        // data (form-encoded)
        String data = (String) params.get("data");
        if (data != null && !data.isEmpty()) {
            request = request.withHeader("Content-Type", "application/x-www-form-urlencoded");
            return request.withBody(interpolateString(data, variables));
        }

        // raw body
        String body = (String) params.get("body");
        if (body != null && !body.isEmpty()) {
            return request.withBody(interpolateString(body, variables));
        }

        return request;
    }

    // ── Response formatting ───────────────────────────────────────

    private Map<String, Object> buildResponseMap(HttpRequestResponse result) {
        Map<String, Object> out = new LinkedHashMap<>();
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
}
