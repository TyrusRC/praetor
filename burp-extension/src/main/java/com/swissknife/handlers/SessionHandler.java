package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.ui.ConfigTab;
import com.swissknife.util.JsonUtil;

import com.swissknife.store.FindingsStore;

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
 * POST   /api/session/create     — create session
 * POST   /api/session/request    — send request with session state
 * POST   /api/session/extract    — extract values from last response
 * POST   /api/session/flow       — execute multi-step flow
 * POST   /api/session/discover   — BFS crawl from session base URL
 * POST   /api/session/auto-probe — knowledge-driven parameter probing
 * GET    /api/session/list       — list all sessions
 * DELETE /api/session/{name}     — delete a session
 */
public class SessionHandler extends BaseHandler {

    private static final int MAX_RESPONSE_SIZE = 50000;

    private static final Map<String, String> CWE_MAP = Map.of(
        "sqli", "CWE-89",
        "xss", "CWE-79",
        "path_traversal", "CWE-22",
        "ssti", "CWE-1336",
        "command_injection", "CWE-78",
        "ssrf", "CWE-918",
        "xxe", "CWE-611",
        "idor", "CWE-639",
        "info_disclosure", "CWE-200"
    );

    private final MontoyaApi api;
    private final FindingsStore findingsStore;

    /** Package-accessible so AttackHandler can share sessions. */
    final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public SessionHandler(MontoyaApi api, FindingsStore findingsStore) {
        this.api = api;
        this.findingsStore = findingsStore;
    }

    /** Returns the shared sessions map for use by AttackHandler. */
    public Map<String, Session> getSessions() {
        return sessions;
    }

    /** Returns session info as list of string arrays for UI display. */
    public List<String[]> getSessionInfoList() {
        List<String[]> list = new ArrayList<>();
        for (Session s : sessions.values()) {
            list.add(new String[]{
                s.name, s.baseUrl,
                String.valueOf(s.cookies.size()),
                String.valueOf(s.variables.size()),
                !s.bearerToken.isEmpty() || !s.authUser.isEmpty() ? "Yes" : "No"
            });
        }
        return list;
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
                } else if (path.startsWith("/api/session/") && path.endsWith("/last-host")) {
                    String name = path.substring("/api/session/".length(), path.length() - "/last-host".length());
                    handleLastHost(exchange, name);
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
                    case "/api/session/probe" -> handleProbe(exchange, body);
                    case "/api/session/batch" -> handleBatch(exchange, body);
                    case "/api/session/discover" -> handleDiscover(exchange, body);
                    case "/api/session/auto-probe" -> handleAutoProbe(exchange, body);
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
            long startNanos = System.nanoTime();
            HttpRequestResponse result = sendSessionRequest(session, body);
            long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;

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
                mergeVariables(session, extracted);
            }

            Map<String, Object> out = buildResponseMap(result);
            out.put("response_time_ms", elapsedMs);
            ConfigTab.log("session_request: " + body.getOrDefault("method", "GET") + " " + body.getOrDefault("path", "/") + " -> " + (result.response() != null ? result.response().statusCode() : 0) + " (" + elapsedMs + "ms)");
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
            mergeVariables(session, extracted);

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

                long stepStart = System.nanoTime();
                HttpRequestResponse result = sendSessionRequest(session, step);
                long stepMs = (System.nanoTime() - stepStart) / 1_000_000;

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
                    mergeVariables(session, extracted);
                }

                Map<String, Object> stepResult = new LinkedHashMap<>();
                stepResult.put("step", stepsExecuted);
                stepResult.put("method", step.getOrDefault("method", "GET"));
                stepResult.put("path", step.getOrDefault("path", "/"));
                HttpResponse resp = result.response();
                stepResult.put("status", resp != null ? resp.statusCode() : 0);
                stepResult.put("response_length", resp != null ? resp.body().length() : 0);
                stepResult.put("response_time_ms", stepMs);
                stepResult.put("extracted", extracted);
                // Include body snippet for flow inspection (500 chars max)
                if (resp != null) {
                    String bodySnippet = resp.bodyToString();
                    if (bodySnippet.length() > 500) bodySnippet = bodySnippet.substring(0, 500);
                    stepResult.put("body_snippet", bodySnippet);
                }
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
            synchronized (s) {
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
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sessions", list);
        out.put("total", list.size());
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── GET /api/session/{name}/last-host ─────────────────────────

    private void handleLastHost(HttpExchange exchange, String name) throws Exception {
        if (name == null || name.isEmpty()) {
            sendError(exchange, 400, "Session name required");
            return;
        }
        Session session = sessions.get(name);
        if (session == null) {
            sendError(exchange, 404, "Session not found: " + name);
            return;
        }
        synchronized (session) {
            if (session.lastResponse == null || session.lastResponse.request() == null) {
                sendError(exchange, 409, "Session has no requests yet: " + name);
                return;
            }
            HttpService svc = session.lastResponse.request().httpService();
            if (svc == null) {
                sendError(exchange, 500, "Session last request has no http service");
                return;
            }
            sendJson(exchange, JsonUtil.object(
                "host", svc.host(),
                "port", svc.port(),
                "https", svc.secure()
            ));
        }
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

    // ── POST /api/session/probe — baseline vs payload comparison ──

    @SuppressWarnings("unchecked")
    private void handleProbe(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) { sendError(exchange, 400, "Missing 'session'"); return; }
        Session session = sessions.get(sessionName);
        if (session == null) { sendError(exchange, 404, "Session not found: " + sessionName); return; }

        String method = (String) body.getOrDefault("method", "GET");
        String path = (String) body.getOrDefault("path", "/");
        String parameter = (String) body.get("parameter");
        String baselineValue = (String) body.getOrDefault("baseline_value", "1");
        String payloadValue = (String) body.getOrDefault("payload_value", "");
        String injectionPoint = (String) body.getOrDefault("injection_point", "query");
        List<String> testPayloads = body.containsKey("test_payloads") ? (List<String>) body.get("test_payloads") : null;

        if (parameter == null) { sendError(exchange, 400, "Missing 'parameter'"); return; }

        synchronized (session) {
            // ── Step 1: Send baseline request ──
            Map<String, Object> baselineParams = new LinkedHashMap<>(body);
            baselineParams.put("path", injectParam(path, parameter, baselineValue, injectionPoint));
            if ("body".equals(injectionPoint)) baselineParams.put("data", parameter + "=" + baselineValue);

            long baseStart = System.nanoTime();
            HttpRequestResponse baselineResult = sendSessionRequest(session, baselineParams);
            long baseMs = (System.nanoTime() - baseStart) / 1_000_000;
            if (baselineResult != null) updateCookiesFromResponse(session, baselineResult);

            int baseStatus = baselineResult != null && baselineResult.response() != null ? baselineResult.response().statusCode() : 0;
            int baseLen = baselineResult != null && baselineResult.response() != null ? baselineResult.response().body().length() : 0;
            String baseBody = baselineResult != null && baselineResult.response() != null ? baselineResult.response().bodyToString() : "";

            // ── Step 2: Auto-detect tech stack from baseline ──
            List<String> detectedTech = detectTechFromResponse(baselineResult);

            // ── Step 3: Select payload adaptively if not provided ──
            if ((payloadValue == null || payloadValue.isEmpty()) && (testPayloads == null || testPayloads.isEmpty())) {
                testPayloads = selectAdaptivePayloads(detectedTech, parameter);
            }

            // If single payload provided, use it; otherwise use first from testPayloads
            if (payloadValue != null && !payloadValue.isEmpty() && (testPayloads == null || testPayloads.isEmpty())) {
                testPayloads = List.of(payloadValue);
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("parameter", parameter);
            out.put("baseline_value", baselineValue);
            out.put("injection_point", injectionPoint);
            out.put("baseline_status", baseStatus);
            out.put("baseline_length", baseLen);
            out.put("baseline_time_ms", baseMs);
            if (!detectedTech.isEmpty()) out.put("detected_tech", detectedTech);

            // ── Step 4: Test each payload ──
            List<Map<String, Object>> payloadResults = new ArrayList<>();
            int maxVulnScore = 0;

            for (String testPayload : testPayloads) {
                Map<String, Object> payParams = new LinkedHashMap<>(body);
                payParams.put("path", injectParam(path, parameter, testPayload, injectionPoint));
                if ("body".equals(injectionPoint)) payParams.put("data", parameter + "=" + testPayload);

                long payStart = System.nanoTime();
                HttpRequestResponse payResult = sendSessionRequest(session, payParams);
                long payMs = (System.nanoTime() - payStart) / 1_000_000;
                if (payResult != null) updateCookiesFromResponse(session, payResult);
                session.lastResponse = payResult;

                int payStatus = payResult != null && payResult.response() != null ? payResult.response().statusCode() : 0;
                int payLen = payResult != null && payResult.response() != null ? payResult.response().body().length() : 0;
                String payBody = payResult != null && payResult.response() != null ? payResult.response().bodyToString() : "";

                // Error patterns
                List<Map<String, Object>> errors = detectErrorPatterns(payBody, payStatus);

                // Reflection (multi-variant)
                Map<String, Object> reflection = detectReflection(testPayload, payBody);

                // Vulnerability scoring
                int vulnScore = 0;
                List<String> findings = new ArrayList<>();

                if (baseStatus != payStatus) {
                    if (payStatus == 500) { findings.add("500 error — likely injectable"); vulnScore += 40; }
                    else if (payStatus == 403 || payStatus == 401) { findings.add("Auth change — possible bypass"); vulnScore += 25; }
                    else { findings.add("Status changed: " + baseStatus + " -> " + payStatus); vulnScore += 15; }
                }
                long timeDiff = payMs - baseMs;
                if (timeDiff > 4000) { findings.add("Timing: +" + timeDiff + "ms — blind injection?"); vulnScore += 35; }
                else if (timeDiff > 1500) { findings.add("Timing: +" + timeDiff + "ms"); vulnScore += 10; }
                if (!errors.isEmpty()) {
                    findings.add(errors.get(0).get("type") + ": " + errors.get(0).get("description"));
                    vulnScore += "high".equals(errors.get(0).get("confidence")) ? 40 : 20;
                }
                if (!reflection.isEmpty()) {
                    findings.add("Reflected (" + reflection.get("type") + ")");
                    vulnScore += "raw".equals(reflection.get("type")) ? 30 : 15;
                }
                if (Math.abs(payLen - baseLen) > 200) vulnScore += 5;

                Map<String, Object> pr = new LinkedHashMap<>();
                vulnScore = Math.min(100, vulnScore);

                pr.put("payload", testPayload);
                pr.put("status", payStatus);
                pr.put("length", payLen);
                pr.put("time_ms", payMs);
                pr.put("score", vulnScore);
                if (!errors.isEmpty()) pr.put("errors", errors);
                if (!reflection.isEmpty()) pr.put("reflection", reflection);
                if (!findings.isEmpty()) pr.put("findings", findings);
                payloadResults.add(pr);

                maxVulnScore = Math.max(maxVulnScore, vulnScore);
            }

            out.put("payloads_tested", payloadResults.size());
            out.put("results", payloadResults);
            out.put("max_vulnerability_score", maxVulnScore);
            out.put("likely_vulnerable", maxVulnScore >= 30);

            ConfigTab.log("probe: " + parameter + " on " + path + " -> score=" + maxVulnScore + " (" + payloadResults.size() + " payloads)");
            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

    private String injectParam(String path, String param, String value, String injectionPoint) {
        if ("query".equals(injectionPoint)) {
            return path.contains("?") ? path + "&" + param + "=" + value : path + "?" + param + "=" + value;
        }
        return path;
    }

    /**
     * Match a parameter name against a knowledge-base param_match list.
     *
     * Exact-lowercase match wins first (fast path). Otherwise tokenize
     * camelCase / snake_case / kebab-case and check each token, plus an
     * entry-is-prefix-of-parameter check so "cat" still matches "category".
     * This lets modern names like "productId", "user_email", "post-id"
     * match the short tokens (id, email) that the knowledge base uses.
     */
    static boolean paramMatcherHits(String parameter, List<String> paramMatch) {
        if (parameter == null || paramMatch == null || paramMatch.isEmpty()) return true;
        String lower = parameter.toLowerCase();
        Set<String> tokens = new HashSet<>();
        tokens.add(lower);
        for (String t : lower.split("[_\\-\\s\\.]+")) {
            if (!t.isEmpty()) tokens.add(t);
        }
        // camelCase boundary split on the original casing
        for (String t : parameter.split("(?<!^)(?=[A-Z])")) {
            if (!t.isEmpty()) tokens.add(t.toLowerCase());
        }
        for (String entry : paramMatch) {
            if (entry == null) continue;
            String e = entry.toLowerCase();
            if (tokens.contains(e)) return true;
            // Prefix-of-parameter check (e.g. entry="cat" matches "category").
            // Require entry length >= 3 to avoid "id" matching "identifier"
            // (which we already catch via the id-token split for snake/camel).
            if (e.length() >= 3 && lower.startsWith(e)) return true;
        }
        return false;
    }

    // ── Adaptive tech detection from response headers/body ──

    private List<String> detectTechFromResponse(HttpRequestResponse result) {
        List<String> techs = new ArrayList<>();
        if (result == null || result.response() == null) return techs;
        HttpResponse resp = result.response();

        for (HttpHeader h : resp.headers()) {
            String n = h.name().toLowerCase(), v = h.value().toLowerCase();
            if ("server".equals(n)) {
                if (v.contains("iis")) techs.add("IIS");
                else if (v.contains("apache")) techs.add("Apache");
                else if (v.contains("nginx")) techs.add("Nginx");
                if (v.contains("tomcat")) techs.add("Tomcat");
            }
            if ("x-powered-by".equals(n)) {
                if (v.contains("asp")) techs.add("ASP.NET");
                else if (v.contains("php")) techs.add("PHP");
                else if (v.contains("express")) techs.add("Express");
                else if (v.contains("jsp")) techs.add("Java");
            }
        }

        String body = resp.bodyToString().toLowerCase();
        if (body.contains("ng-app") || body.contains("ng-controller")) techs.add("AngularJS");
        if (body.contains("__next")) techs.add("Next.js");
        if (body.contains("wp-content")) techs.add("WordPress");
        if (body.contains("laravel")) techs.add("Laravel");
        if (body.contains("django")) techs.add("Django");
        if (body.contains("flask")) techs.add("Flask");
        if (body.contains("spring")) techs.add("Spring");
        if (body.contains("rubyonrails") || body.contains("rails")) techs.add("Rails");

        return techs;
    }

    // ── Adaptive payload selection based on detected tech ──

    private List<String> selectAdaptivePayloads(List<String> techs, String parameter) {
        List<String> payloads = new ArrayList<>();
        boolean isNumeric = parameter.matches("(?i)id|num|page|limit|offset|count|idx|index");

        // SQLi payloads adapted to tech
        if (techs.contains("IIS") || techs.contains("ASP.NET")) {
            payloads.add(isNumeric ? "1'" : "test'");
            payloads.add(isNumeric ? "1; WAITFOR DELAY '0:0:2'--" : "'; WAITFOR DELAY '0:0:2'--");
            payloads.add(isNumeric ? "1 AND 1=CONVERT(int,@@version)--" : "' AND 1=CONVERT(int,@@version)--");
        } else if (techs.contains("PHP") || techs.contains("Apache")) {
            payloads.add(isNumeric ? "1'" : "test'");
            payloads.add(isNumeric ? "1 AND SLEEP(2)-- -" : "' AND SLEEP(2)-- -");
            payloads.add(isNumeric ? "1 UNION SELECT NULL-- -" : "' UNION SELECT NULL-- -");
        } else if (techs.contains("Django") || techs.contains("Flask")) {
            payloads.add(isNumeric ? "1'" : "test'");
            payloads.add("{{7*7}}"); // SSTI
        } else {
            // Generic fallback
            payloads.add(isNumeric ? "1'" : "test'");
            payloads.add(isNumeric ? "1 OR 1=1-- -" : "' OR '1'='1");
        }

        // XSS probe (always include)
        payloads.add("<xss_probe_" + System.currentTimeMillis() % 10000 + ">");

        // Path traversal (if parameter looks like a file/path)
        if (parameter.matches("(?i)file|path|item|page|template|include|url|src|doc|dir")) {
            payloads.add("../../../etc/passwd");
        }

        return payloads;
    }

    // ── Multi-variant reflection detection ──

    private Map<String, Object> detectReflection(String payload, String responseBody) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (payload == null || responseBody == null || payload.isEmpty()) return result;

        // Raw reflection
        if (responseBody.contains(payload)) {
            result.put("type", "raw");
            result.put("context", guessReflectionContext(payload, responseBody));
            return result;
        }
        // URL-encoded
        String urlEnc = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8);
        if (!urlEnc.equals(payload) && responseBody.contains(urlEnc)) {
            result.put("type", "url_encoded");
            return result;
        }
        // HTML entity encoded
        String htmlEnc = payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
        if (!htmlEnc.equals(payload) && responseBody.contains(htmlEnc)) {
            result.put("type", "html_encoded");
            return result;
        }
        // JS escaped
        String jsEnc = payload.replace("\\", "\\\\").replace("'", "\\'").replace("\"", "\\\"");
        if (!jsEnc.equals(payload) && responseBody.contains(jsEnc)) {
            result.put("type", "js_escaped");
            return result;
        }
        return result;
    }

    private String guessReflectionContext(String payload, String body) {
        int idx = body.indexOf(payload);
        if (idx < 0) return "unknown";
        // Look backwards for context clues
        String before = body.substring(Math.max(0, idx - 50), idx).toLowerCase();
        if (before.contains("<script") || before.contains("javascript:")) return "javascript";
        if (before.contains("value=") || before.contains("href=") || before.contains("src=")) return "attribute";
        if (before.contains("<!--")) return "html_comment";
        return "html_body";
    }

    // ── Enhanced error pattern detection ──

    private List<Map<String, Object>> detectErrorPatterns(String body, int status) {
        List<Map<String, Object>> patterns = new ArrayList<>();
        String lower = body.toLowerCase();

        // SQL error patterns (expanded)
        String[][] sqlPatterns = {
            {"mssql", "unclosed quotation mark", "high"}, {"mssql", "incorrect syntax near", "high"},
            {"mssql", "microsoft ole db", "high"}, {"mssql", "microsoft sql server", "medium"},
            {"mssql", "sql server driver", "medium"}, {"mssql", "odbc sql server", "medium"},
            {"mysql", "you have an error in your sql syntax", "high"}, {"mysql", "warning: mysql", "medium"},
            {"mysql", "mysqli_", "medium"}, {"mysql", "mysql_fetch", "medium"},
            {"postgresql", "pg_query", "high"}, {"postgresql", "psql error", "high"},
            {"postgresql", "unterminated quoted string", "high"},
            {"oracle", "ora-", "high"}, {"oracle", "oracleexception", "high"},
            {"sqlite", "sqlite3.", "high"}, {"sqlite", "unrecognized token", "high"},
            {"generic", "sql syntax", "medium"}, {"generic", "database error", "medium"},
            {"generic", "query failed", "medium"}, {"generic", "sql exception", "medium"},
        };
        for (String[] p : sqlPatterns) {
            if (lower.contains(p[1])) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("type", "sqli"); m.put("database", p[0]); m.put("description", p[1]); m.put("confidence", p[2]);
                patterns.add(m); break;
            }
        }

        // Path traversal
        if (lower.contains("root:x:0") || lower.contains("[extensions]") || lower.contains("[boot loader]") ||
            lower.contains("for 16-bit app support") || lower.contains("/etc/shadow") || lower.contains("c:\\windows")) {
            patterns.add(Map.of("type", "path_traversal", "description", "System file contents leaked", "confidence", "high"));
        }

        // SSTI — only flag explicit template engine errors, not generic "49" matches
        if (lower.contains("jinja2") || lower.contains("freemarker") || lower.contains("velocity") ||
            lower.contains("thymeleaf") || lower.contains("twig") || lower.contains("mako") ||
            (lower.contains("template") && (lower.contains("error") || lower.contains("exception")))) {
            patterns.add(Map.of("type", "ssti", "description", "Template engine error detected", "confidence", "high"));
        }

        // RCE
        if (lower.contains("uid=") && lower.contains("gid=") || lower.contains("command not found") ||
            lower.contains("sh:") || lower.contains("bash:")) {
            patterns.add(Map.of("type", "rce", "description", "Command execution evidence", "confidence", "high"));
        }

        // XXE
        if ((lower.contains("<!entity") || lower.contains("<!doctype")) && lower.contains("system")) {
            patterns.add(Map.of("type", "xxe", "description", "XXE processing detected", "confidence", "medium"));
        }

        // SSRF
        if (lower.contains("connection refused") || lower.contains("connection timed out") || lower.contains("unreachable")) {
            patterns.add(Map.of("type", "ssrf", "description", "SSRF connection attempt", "confidence", "medium"));
        }

        // Stack trace / debug
        if (lower.contains("stack trace") || lower.contains("at java.") || lower.contains("at system.") ||
            lower.contains("traceback") || lower.contains("exception in") || lower.contains("at line")) {
            patterns.add(Map.of("type", "info_disclosure", "description", "Stack trace leaked", "confidence", "high"));
        }

        // Generic 500 alone is NOT a vulnerability indicator — don't flag
        // Many apps return 500 for invalid input, rate limiting, or general errors
        // Only specific error patterns above should trigger findings

        return patterns;
    }

    // ── POST /api/session/batch — test multiple endpoints at once ──

    private void handleBatch(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) { sendError(exchange, 400, "Missing 'session'"); return; }
        Session session = sessions.get(sessionName);
        if (session == null) { sendError(exchange, 404, "Session not found: " + sessionName); return; }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> endpoints = (List<Map<String, Object>>) body.get("endpoints");
        if (endpoints == null || endpoints.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'endpoints'"); return;
        }

        synchronized (session) {
            List<Map<String, Object>> results = new ArrayList<>();
            Map<Integer, Integer> statusCounts = new java.util.TreeMap<>();
            long totalStart = System.nanoTime();

            for (int i = 0; i < endpoints.size(); i++) {
                Map<String, Object> ep = endpoints.get(i);
                Map<String, Object> reqParams = new LinkedHashMap<>(ep);
                reqParams.put("session", sessionName);

                long reqStart = System.nanoTime();
                HttpRequestResponse result = sendSessionRequest(session, reqParams);
                long reqMs = (System.nanoTime() - reqStart) / 1_000_000;
                if (result != null) updateCookiesFromResponse(session, result);

                int status = result != null && result.response() != null ? result.response().statusCode() : 0;
                int length = result != null && result.response() != null ? result.response().body().length() : 0;
                statusCounts.merge(status, 1, Integer::sum);

                Map<String, Object> r = new LinkedHashMap<>();
                r.put("index", i);
                r.put("method", ep.getOrDefault("method", "GET"));
                r.put("path", ep.getOrDefault("path", "/"));
                r.put("status", status);
                r.put("length", length);
                r.put("time_ms", reqMs);

                // Body snippet (100 chars for batch — keep compact)
                if (result != null && result.response() != null) {
                    String bodyStr = result.response().bodyToString();
                    r.put("title", extractTitle(bodyStr));
                }
                results.add(r);
            }

            long totalMs = (System.nanoTime() - totalStart) / 1_000_000;

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("total_endpoints", endpoints.size());
            out.put("total_time_ms", totalMs);
            out.put("status_distribution", statusCounts);
            out.put("results", results);
            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

    // ── POST /api/session/discover — BFS crawl from session base URL ──

    private void handleDiscover(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) { sendError(exchange, 400, "Missing 'session'"); return; }
        Session session = sessions.get(sessionName);
        if (session == null) { sendError(exchange, 404, "Session not found"); return; }

        int maxPages = body.containsKey("max_pages") ? ((Number) body.get("max_pages")).intValue() : 20;

        synchronized (session) {
            Set<String> visited = new LinkedHashSet<>();
            Queue<String> queue = new LinkedList<>();
            List<Map<String, Object>> endpoints = new ArrayList<>();
            List<Map<String, Object>> forms = new ArrayList<>();
            List<String> detectedTech = new ArrayList<>();
            int totalParams = 0;
            int highRiskParams = 0;

            queue.add("/");

            while (!queue.isEmpty() && visited.size() < maxPages) {
                String pagePath = queue.poll();
                if (visited.contains(pagePath)) continue;
                visited.add(pagePath);

                // Build and send request using session
                Map<String, Object> reqParams = new LinkedHashMap<>();
                reqParams.put("method", "GET");
                reqParams.put("path", pagePath);

                HttpRequestResponse result = sendSessionRequest(session, reqParams);
                if (result == null || result.response() == null) continue;
                updateCookiesFromResponse(session, result);

                HttpResponse resp = result.response();
                String respBody = resp.bodyToString();
                int status = resp.statusCode();

                // Detect tech from first response
                if (detectedTech.isEmpty()) {
                    detectedTech.addAll(detectTechFromResponse(result));
                }

                // Extract title
                String title = extractTitle(respBody);

                // Extract parameters from URL
                List<Map<String, Object>> pageParams = new ArrayList<>();
                if (pagePath.contains("?")) {
                    String query = pagePath.substring(pagePath.indexOf("?") + 1);
                    for (String pair : query.split("&")) {
                        int eq = pair.indexOf("=");
                        if (eq > 0) {
                            String pName = pair.substring(0, eq);
                            String pValue = pair.substring(eq + 1);
                            String risk = scoreParamRisk(pName);
                            Map<String, Object> paramInfo = new LinkedHashMap<>();
                            paramInfo.put("name", pName);
                            paramInfo.put("location", "query");
                            paramInfo.put("sample_value", pValue);
                            paramInfo.put("risk", risk);
                            pageParams.add(paramInfo);
                            totalParams++;
                            if ("high".equals(risk)) highRiskParams++;
                        }
                    }
                }

                // Record endpoint with risk score
                Map<String, Object> ep = new LinkedHashMap<>();
                ep.put("method", "GET");
                ep.put("path", pagePath);
                ep.put("parameters", pageParams);
                ep.put("title", title != null ? title : "");
                ep.put("status", status);
                ep.put("length", resp.body().length());

                // Composite risk score: path sensitivity + param risk + auth level
                int riskScore = scoreEndpointRisk(pagePath, pageParams, status);
                ep.put("risk_score", riskScore);
                ep.put("priority", riskScore >= 7 ? "critical" : riskScore >= 5 ? "high" : riskScore >= 3 ? "medium" : "low");
                endpoints.add(ep);

                // Extract links from HTML
                java.util.regex.Pattern linkPattern = java.util.regex.Pattern.compile(
                    "(?:href|action)=[\"']([^\"'#]+)[\"']", java.util.regex.Pattern.CASE_INSENSITIVE);
                java.util.regex.Matcher linkMatcher = linkPattern.matcher(respBody);
                while (linkMatcher.find()) {
                    String link = linkMatcher.group(1);
                    // Skip external links, javascript:, mailto:
                    if (link.startsWith("http") || link.startsWith("javascript") ||
                        link.startsWith("mailto") || link.startsWith("#")) continue;
                    // Normalize: make absolute
                    if (!link.startsWith("/")) {
                        String basePath = pagePath.contains("/")
                            ? pagePath.substring(0, pagePath.lastIndexOf("/") + 1) : "/";
                        link = basePath + link;
                    }
                    // Normalize relative references (./ and ../)
                    while (link.contains("/./")) link = link.replace("/./", "/");
                    if (link.startsWith("./")) link = link.substring(2);
                    try { link = new java.net.URI(link).normalize().toString(); } catch (Exception ignored) {}
                    if (!visited.contains(link) && !queue.contains(link)) {
                        queue.add(link);
                    }
                }

                // Extract forms
                java.util.regex.Pattern formPattern = java.util.regex.Pattern.compile(
                    "<form[^>]*(?:action=[\"']([^\"']*)[\"'][^>]*method=[\"']([^\"']*)[\"']|method=[\"']([^\"']*)[\"'][^>]*action=[\"']([^\"']*)[\"'])[^>]*>(.*?)</form>",
                    java.util.regex.Pattern.CASE_INSENSITIVE | java.util.regex.Pattern.DOTALL);
                java.util.regex.Matcher formMatcher = formPattern.matcher(respBody);
                while (formMatcher.find()) {
                    // Handle both action-first and method-first attribute order
                    String action = formMatcher.group(1) != null ? formMatcher.group(1) : formMatcher.group(4);
                    String formMethod = formMatcher.group(2) != null ? formMatcher.group(2).toUpperCase() : (formMatcher.group(3) != null ? formMatcher.group(3).toUpperCase() : "GET");
                    String formBody = formMatcher.group(5);

                    List<String> inputs = new ArrayList<>();
                    java.util.regex.Pattern inputPattern = java.util.regex.Pattern.compile(
                        "name=[\"']([^\"']+)[\"']", java.util.regex.Pattern.CASE_INSENSITIVE);
                    java.util.regex.Matcher inputMatcher = inputPattern.matcher(formBody);
                    while (inputMatcher.find()) {
                        String inputName = inputMatcher.group(1);
                        inputs.add(inputName);
                        totalParams++;
                        if ("high".equals(scoreParamRisk(inputName))) highRiskParams++;
                    }

                    if (!action.isEmpty()) {
                        Map<String, Object> formInfo = new LinkedHashMap<>();
                        formInfo.put("action", action);
                        formInfo.put("method", formMethod);
                        formInfo.put("inputs", inputs);
                        formInfo.put("source_page", pagePath);
                        forms.add(formInfo);
                    }
                }
            }

            // Build pre-formatted targets for auto_probe (saves Claude tokens)
            List<Map<String, Object>> targets = new ArrayList<>();
            // From endpoint query params
            for (Map<String, Object> ep : endpoints) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> epParams = (List<Map<String, Object>>) ep.get("parameters");
                if (epParams != null) {
                    for (Map<String, Object> p : epParams) {
                        String risk = (String) p.getOrDefault("risk", "low");
                        if ("high".equals(risk) || "medium".equals(risk)) {
                            Map<String, Object> t = new LinkedHashMap<>();
                            t.put("method", ep.get("method"));
                            t.put("path", ((String) ep.get("path")).split("\\?")[0]); // base path without query
                            t.put("parameter", p.get("name"));
                            t.put("baseline_value", p.getOrDefault("sample_value", "1"));
                            t.put("location", p.getOrDefault("location", "query"));
                            targets.add(t);
                        }
                    }
                }
            }
            // From form inputs
            for (Map<String, Object> form : forms) {
                String action = (String) form.getOrDefault("action", "");
                String formMethod = (String) form.getOrDefault("method", "POST");
                @SuppressWarnings("unchecked")
                List<String> inputs = (List<String>) form.getOrDefault("inputs", List.of());
                for (String input : inputs) {
                    Map<String, Object> t = new LinkedHashMap<>();
                    t.put("method", formMethod);
                    t.put("path", action);
                    t.put("parameter", input);
                    t.put("baseline_value", "test");
                    t.put("location", "body");
                    targets.add(t);
                }
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("pages_crawled", visited.size());
            out.put("endpoints", endpoints);
            out.put("forms", forms);
            out.put("targets", targets);
            out.put("detected_tech", detectedTech);
            out.put("total_parameters", totalParams);
            out.put("high_risk_parameters", highRiskParams);
            out.put("probeable_targets", targets.size());

            ConfigTab.log("discover: " + visited.size() + " pages, " + totalParams + " params (" + highRiskParams + " high-risk)");
            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

    private String scoreParamRisk(String name) {
        String lower = name.toLowerCase();
        if (lower.matches("(?:id|uid|pid|num|page|idx|index|user_id|account_id|order_id|file|path|item|template|include|url|src|doc|dir|load|read|cmd|exec|command)")) {
            return "high";
        }
        if (lower.matches("(?:search|q|query|name|title|comment|msg|text|input|value|keyword|email)")) {
            return "medium";
        }
        return "low";
    }

    private int scoreEndpointRisk(String path, List<Map<String, Object>> params, int status) {
        int score = 0;
        String lower = path.toLowerCase();

        // Path sensitivity scoring
        if (lower.contains("/admin") || lower.contains("/debug") || lower.contains("/backup")) score += 4;
        else if (lower.contains("/api/") || lower.contains("/user") || lower.contains("/account")) score += 3;
        else if (lower.contains("/upload") || lower.contains("/export") || lower.contains("/download")) score += 3;
        else if (lower.contains("/login") || lower.contains("/register") || lower.contains("/search")) score += 2;
        else score += 1;

        // Parameter risk contribution
        int highRiskParams = 0;
        for (Map<String, Object> p : params) {
            String risk = (String) p.getOrDefault("risk", "low");
            if ("high".equals(risk)) highRiskParams++;
        }
        score += Math.min(highRiskParams * 2, 4); // Max +4 from params

        // Status anomaly bonus
        if (status == 500) score += 2;
        else if (status == 403 || status == 401) score += 1;

        return Math.min(score, 10); // Cap at 10
    }

    // ── POST /api/session/auto-probe — knowledge-driven parameter probing ──

    @SuppressWarnings("unchecked")
    private void handleAutoProbe(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) { sendError(exchange, 400, "Missing 'session'"); return; }
        Session session = sessions.get(sessionName);
        if (session == null) { sendError(exchange, 404, "Session not found"); return; }

        List<Map<String, Object>> targets = (List<Map<String, Object>>) body.get("targets");
        List<Map<String, Object>> knowledgeBase = (List<Map<String, Object>>) body.get("knowledge");
        int maxProbes = body.containsKey("max_probes_per_param")
            ? ((Number) body.get("max_probes_per_param")).intValue() : 5;

        if (targets == null || targets.isEmpty()) { sendError(exchange, 400, "Missing 'targets'"); return; }
        if (knowledgeBase == null || knowledgeBase.isEmpty()) { sendError(exchange, 400, "Missing 'knowledge'"); return; }

        synchronized (session) {
            List<Map<String, Object>> findings = new ArrayList<>();
            Set<String> seenFindingKeys = new HashSet<>();
            int totalProbes = 0;

            for (Map<String, Object> target : targets) {
                String method = (String) target.getOrDefault("method", "GET");
                String path = (String) target.get("path");
                String parameter = (String) target.get("parameter");
                String baselineValue = (String) target.getOrDefault("baseline_value", "1");
                String location = (String) target.getOrDefault("location", "query");

                // Send baseline
                Map<String, Object> baseParams = new LinkedHashMap<>();
                baseParams.put("method", method);
                baseParams.put("path", injectParam(path, parameter, baselineValue, location));
                if ("body".equals(location)) baseParams.put("data", parameter + "=" + baselineValue);

                long baselineStartMs = System.nanoTime();
                HttpRequestResponse baselineResult = sendSessionRequest(session, baseParams);
                long baselineElapsedMs = (System.nanoTime() - baselineStartMs) / 1_000_000;
                if (baselineResult == null || baselineResult.response() == null) continue;
                updateCookiesFromResponse(session, baselineResult);

                // Detect tech
                List<String> detectedTech = detectTechFromResponse(baselineResult);

                // Find matching probes from knowledge base
                int probesRun = 0;
                for (Map<String, Object> kb : knowledgeBase) {
                    if (probesRun >= maxProbes) break;
                    String category = (String) kb.get("category");
                    Map<String, Object> contexts = (Map<String, Object>) kb.get("contexts");
                    if (contexts == null) continue;

                    for (Map.Entry<String, Object> ctxEntry : contexts.entrySet()) {
                        if (probesRun >= maxProbes) break;
                        String contextName = ctxEntry.getKey();
                        Map<String, Object> context = (Map<String, Object>) ctxEntry.getValue();

                        // Check tech_match
                        List<String> techMatch = (List<String>) context.getOrDefault("tech_match", List.of());
                        if (!techMatch.isEmpty() && detectedTech.stream().noneMatch(techMatch::contains)) continue;

                        // Check param_match — exact match OR tokenized match so
                        // modern camelCase/snake_case names match the simple
                        // tokens in the knowledge base (productId→id,
                        // post_id→id, category→cat, user_email→email).
                        List<String> paramMatch = (List<String>) context.getOrDefault("param_match", List.of());
                        if (!paramMatch.isEmpty() && !paramMatcherHits(parameter, paramMatch)) continue;

                        // Run probes
                        List<Map<String, Object>> probes = (List<Map<String, Object>>) context.getOrDefault("probes", List.of());
                        for (Map<String, Object> probe : probes) {
                            if (probesRun >= maxProbes) break;

                            String payloadTemplate = (String) probe.get("payload");
                            Map<String, Object> variables = (Map<String, Object>) probe.getOrDefault("variables", Map.of());

                            // Interpolate variables
                            String payload = payloadTemplate
                                .replace("{{baseline}}", baselineValue)
                                .replace("{{marker}}", "probe_" + System.currentTimeMillis() % 100000)
                                .replace("{{sleep}}", String.valueOf(
                                    variables.getOrDefault("sleep", variables.getOrDefault("sleep_seconds", "5"))));
                            for (Map.Entry<String, Object> v : variables.entrySet()) {
                                payload = payload.replace("{{" + v.getKey() + "}}", String.valueOf(v.getValue()));
                            }

                            // Send probe request
                            Map<String, Object> probeParams = new LinkedHashMap<>();
                            probeParams.put("method", method);
                            probeParams.put("path", injectParam(path, parameter, payload, location));
                            if ("body".equals(location)) probeParams.put("data", parameter + "=" + payload);

                            long startMs = System.nanoTime();
                            HttpRequestResponse probeResult = sendSessionRequest(session, probeParams);
                            long elapsedMs = (System.nanoTime() - startMs) / 1_000_000;
                            totalProbes++;
                            probesRun++;

                            if (probeResult == null || probeResult.response() == null) continue;
                            updateCookiesFromResponse(session, probeResult);

                            // URL of what we just sent — used to annotate the
                            // matching Proxy history entry after matchers run.
                            String probeUrl = probeResult.request() != null ? probeResult.request().url() : "";

                            // Evaluate matchers
                            List<Map<String, Object>> matchers = (List<Map<String, Object>>) probe.get("matchers");
                            Map<String, Object> matchResult = com.swissknife.analysis.MatcherEngine.evaluate(
                                matchers, probeResult.response(), elapsedMs, baselineResult.response(), payload
                            );

                            // Compute anomaly indicators regardless of matcher result
                            int probeStatus = probeResult.response().statusCode();
                            int probeLen = probeResult.response().body().length();
                            int baseStatus = baselineResult.response().statusCode();
                            int baseLen = baselineResult.response().body().length();

                            // Anomaly score: stricter scoring to reduce false positives
                            // Only flag MEANINGFUL deviations, not normal app behavior
                            int anomalyScore = 0;
                            List<String> anomalies = new ArrayList<>();

                            // Status: only flag 2xx→5xx transitions (not 2xx→4xx which is normal validation)
                            if (probeStatus != baseStatus) {
                                int baseClass = baseStatus / 100;
                                int probeClass = probeStatus / 100;
                                if (baseClass == 2 && probeClass == 5) {
                                    anomalyScore += 20;
                                    anomalies.add("status:2xx->5xx");
                                }
                                // 2xx→4xx is normal input validation, not anomaly
                            }

                            // Length: only flag large structural changes (>50% AND >1KB)
                            int lenDiff = Math.abs(probeLen - baseLen);
                            if (baseLen > 0 && lenDiff > baseLen * 0.5 && lenDiff > 1000) {
                                anomalyScore += 15;
                                anomalies.add("length:" + lenDiff + "B diff");
                            }

                            // Timing: differential only (vs measured baseline)
                            long timeDiff = elapsedMs - baselineElapsedMs;
                            if (timeDiff > 4000) {
                                anomalyScore += 20;
                                anomalies.add("timing:+" + timeDiff + "ms vs baseline");
                            }

                            // Compute a single confidence score in [0.0, 1.0]
                            // that drives BOTH the finding record and the
                            // Proxy → HTTP history highlight colour. The
                            // formula combines matcher match quality, matcher
                            // boost from the knowledge base, and the anomaly
                            // signals. Only matcher hits with high boost +
                            // anomaly reach ≥0.9 (RED).
                            boolean matcherHit = Boolean.TRUE.equals(matchResult.get("matched"));
                            int probeBoost = probe.containsKey("confidence_boost")
                                ? ((Number) probe.get("confidence_boost")).intValue() : 0;
                            int matcherBoost = ((Number) matchResult.getOrDefault("confidence_boost", 0)).intValue();
                            int rawScore = Math.min(100, probeBoost + matcherBoost + anomalyScore);

                            double confidence;
                            if (matcherHit) {
                                // Matcher fired. Lift to ≥0.6 floor, add the
                                // raw boost fraction, and require strong
                                // signal (boost ≥ 70 or anomaly backing) for
                                // the ≥0.9 RED threshold.
                                double base = 0.60 + (Math.min(probeBoost + matcherBoost, 100) / 250.0);
                                if (anomalyScore >= 20) base += 0.10;  // anomaly corroborates
                                if ((probeBoost + matcherBoost) >= 70 && anomalyScore >= 20) base = Math.max(base, 0.92);
                                confidence = Math.min(1.0, base);
                            } else if (anomalyScore >= 40 && anomalies.size() >= 2) {
                                // No matcher but multiple anomalies — MEDIUM confidence.
                                confidence = 0.45 + Math.min(anomalyScore, 60) / 200.0;  // 0.45 .. 0.75
                            } else if (anomalyScore > 0) {
                                confidence = 0.30 + anomalyScore / 500.0;  // 0.30 .. 0.50
                            } else {
                                confidence = 0.20;  // routine probe, no signal
                            }

                            if (matcherHit) {
                                // R9: Deduplicate per matcher (matched_matchers signature),
                                // not per (endpoint, param, category). Distinct matcher hits
                                // on the same payload represent independent evidence types
                                // (status diff vs reflection vs header_added vs timing) and
                                // each deserves its own finding entry. Old key collapsed
                                // them into one, hiding evidence the operator needs to
                                // judge confidence.
                                @SuppressWarnings("unchecked")
                                List<String> matched = (List<String>) matchResult.getOrDefault("matched_matchers", List.of());
                                String matcherSig = matched.isEmpty()
                                    ? "<no-matcher-tag>"
                                    : String.join(",", matched);
                                String findingKey = method + "|" + path + "|" + parameter
                                    + "|" + category + "|" + contextName + "|" + matcherSig;
                                if (!seenFindingKeys.add(findingKey)) continue;

                                String severity = (String) probe.getOrDefault("severity", "medium");
                                String description = (String) probe.getOrDefault("description", "");
                                String cwe = CWE_MAP.getOrDefault(category, "");

                                Map<String, Object> finding = new LinkedHashMap<>();
                                finding.put("parameter", parameter);
                                finding.put("endpoint", method + " " + path);
                                finding.put("category", category);
                                finding.put("context", contextName);
                                finding.put("probe", payload);
                                finding.put("status", probeStatus);
                                finding.put("score", rawScore);
                                finding.put("confidence", Math.round(confidence * 100.0) / 100.0);
                                finding.put("anomaly_score", anomalyScore);
                                finding.put("anomalies", anomalies);
                                finding.put("severity", severity);
                                finding.put("cwe", cwe);
                                finding.put("matched_matchers", matchResult.get("matched_matchers"));
                                finding.put("description", description);
                                findings.add(finding);

                                // Persist to FindingsStore with confidence note
                                findingsStore.add(
                                    category + "/" + contextName + ": " + description,
                                    "Parameter: " + parameter + ", Payload: " + payload + ", Matchers: " + matchResult.get("matched_matchers"),
                                    severity,
                                    method + " " + path,
                                    "Status: " + probeStatus + ", Confidence: " + String.format("%.2f", confidence) + ", Score: " + rawScore + (cwe.isEmpty() ? "" : ", " + cwe)
                                );
                            } else if (anomalyScore >= 40 && anomalies.size() >= 2) {
                                // Deduplicate anomaly findings too
                                String findingKey = method + "|" + path + "|" + parameter + "|" + category;
                                if (!seenFindingKeys.add(findingKey)) continue;

                                int normalizedAnomaly = Math.min(100, anomalyScore);
                                String cwe = CWE_MAP.getOrDefault(category, "");

                                Map<String, Object> finding = new LinkedHashMap<>();
                                finding.put("parameter", parameter);
                                finding.put("endpoint", method + " " + path);
                                finding.put("category", category);
                                finding.put("context", contextName);
                                finding.put("probe", payload);
                                finding.put("status", probeStatus);
                                finding.put("score", normalizedAnomaly);
                                finding.put("confidence", Math.round(confidence * 100.0) / 100.0);
                                finding.put("anomaly_score", normalizedAnomaly);
                                finding.put("anomalies", anomalies);
                                finding.put("severity", "info");
                                finding.put("cwe", cwe);
                                finding.put("matched_matchers", List.of());
                                finding.put("description", "Anomalous response (no matcher matched) — review manually");
                                findings.add(finding);

                                findingsStore.add(
                                    category + "/" + contextName + ": Anomalous response",
                                    "Parameter: " + parameter + ", Payload: " + payload + ", Anomalies: " + anomalies,
                                    "info",
                                    method + " " + path,
                                    "Status: " + probeStatus + ", Confidence: " + String.format("%.2f", confidence) + ", Anomaly score: " + normalizedAnomaly
                                );
                            }

                            // Auto-highlight driven by confidence threshold.
                            // RED only at ≥0.9 — matches hunter feedback that
                            // RED should mean high-confidence evidence, not
                            // just "a matcher fired".
                            com.swissknife.http.ProxyHighlight.Level level =
                                com.swissknife.http.ProxyHighlight.levelFromConfidence(confidence);
                            String note = String.format("%s/%s c=%.2f", category, contextName, confidence);
                            if (matcherHit) {
                                note += " match=" + matchResult.get("matched_matchers");
                            } else if (!anomalies.isEmpty()) {
                                note += " anomalies=" + anomalies;
                            } else {
                                note += " probe=" + (payload.length() > 30 ? payload.substring(0, 30) + "…" : payload);
                            }
                            com.swissknife.http.ProxyHighlight.tagLatest(api, probeUrl, level, note);
                        }
                    }
                }

                // Tag the baseline green so the pair is obvious in history.
                if (baselineResult != null && baselineResult.request() != null) {
                    com.swissknife.http.ProxyHighlight.tagLatest(
                        api, baselineResult.request().url(),
                        com.swissknife.http.ProxyHighlight.Level.BASELINE,
                        "baseline for " + parameter);
                }
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("parameters_tested", targets.size());
            out.put("total_probes_sent", totalProbes);
            out.put("findings", findings);
            out.put("auto_saved_findings", findings.size());

            ConfigTab.log("auto-probe: " + targets.size() + " params, " + totalProbes + " probes, " + findings.size() + " findings");
            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

    private String extractTitle(String html) {
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
            // Parse URL safely — handle unencoded special chars (quotes, backslashes, etc.)
            // that are common in pentesting payloads
            URI uri;
            try {
                uri = new URI(fullUrl);
            } catch (java.net.URISyntaxException e) {
                // Fallback: manually parse scheme://host:port and treat the rest as raw path
                uri = buildSafeUri(fullUrl);
            }
            String host = uri.getHost();
            int port = uri.getPort();
            boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());
            if (port == -1) port = isHttps ? 443 : 80;

            // Use raw path to preserve payload chars (don't double-encode)
            String requestPath = uri.getRawPath();
            if (requestPath == null || requestPath.isEmpty()) requestPath = "/";
            String rawQuery = uri.getRawQuery();
            if (rawQuery != null) {
                requestPath += "?" + rawQuery;
            } else {
                // Check if original fullUrl has query string that URI couldn't parse
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

            // Route through Burp proxy listener so the exchange lands in
            // Proxy → HTTP history (not just Logger). Every probe/test tool
            // ultimately funnels through here, so this wins visibility for
            // session_request, auto_probe, probe_endpoint, bulk_test, test_*.
            HttpRequestResponse result = com.swissknife.http.ProxyTunnel.sendOrFallback(api, request);

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

                result = com.swissknife.http.ProxyTunnel.sendOrFallback(api, redirReq);
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

        // Cap cookies at 200 to prevent unbounded growth
        while (session.cookies.size() > 200) {
            String oldest = session.cookies.keySet().iterator().next();
            session.cookies.remove(oldest);
        }
    }

    /**
     * Merge extracted variables into session, capping at 200 entries to prevent unbounded growth.
     */
    private void mergeVariables(Session session, Map<String, String> extracted) {
        session.variables.putAll(extracted);
        while (session.variables.size() > 200) {
            String oldest = session.variables.keySet().iterator().next();
            session.variables.remove(oldest);
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

    /**
     * Build a URI from a URL string that may contain unencoded special chars.
     * Manually parses scheme://host:port and encodes the path/query parts.
     */
    private URI buildSafeUri(String fullUrl) throws java.net.URISyntaxException {
        // Extract scheme
        int schemeEnd = fullUrl.indexOf("://");
        if (schemeEnd < 0) throw new java.net.URISyntaxException(fullUrl, "No scheme");
        String scheme = fullUrl.substring(0, schemeEnd);
        String rest = fullUrl.substring(schemeEnd + 3);

        // Extract host:port
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

        // Split path and query — don't encode, pass raw to Burp
        String path = pathAndQuery;
        String query = null;
        int qIdx = pathAndQuery.indexOf('?');
        if (qIdx >= 0) {
            path = pathAndQuery.substring(0, qIdx);
            query = pathAndQuery.substring(qIdx + 1);
        }

        // Build URI with encoded path but raw query (Burp handles the actual HTTP encoding)
        String encodedPath = java.net.URLEncoder.encode(path, java.nio.charset.StandardCharsets.UTF_8)
                .replace("%2F", "/")  // preserve path separators
                .replace("+", "%20"); // spaces as %20 not +

        return new URI(scheme, null, host, port, encodedPath, query, null);
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
}
