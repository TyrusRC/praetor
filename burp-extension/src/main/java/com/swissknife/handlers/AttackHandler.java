package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/**
 * Attack automation endpoints for authorization testing, race conditions, and HPP.
 *
 * POST /api/attack/auth-matrix  - test endpoints across auth states for IDOR
 * POST /api/attack/race         - race condition testing with concurrent requests
 * POST /api/attack/hpp          - HTTP parameter pollution testing
 */
public class AttackHandler extends BaseHandler {

    private final MontoyaApi api;
    private final Map<String, SessionHandler.Session> sessions;

    public AttackHandler(MontoyaApi api, Map<String, SessionHandler.Session> sessions) {
        this.api = api;
        this.sessions = sessions;
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
            case "/api/attack/auth-matrix" -> handleAuthMatrix(exchange, body);
            case "/api/attack/race" -> handleRaceCondition(exchange, body);
            case "/api/attack/hpp" -> handleHpp(exchange, body);
            default -> sendError(exchange, 404, "Not found");
        }
    }

    // ── POST /api/attack/auth-matrix ─────────────────────────────

    @SuppressWarnings("unchecked")
    private void handleAuthMatrix(HttpExchange exchange, Map<String, Object> body) throws Exception {
        List<Map<String, Object>> endpoints = (List<Map<String, Object>>) body.get("endpoints");
        if (endpoints == null || endpoints.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'endpoints'");
            return;
        }

        Map<String, Object> authStates = (Map<String, Object>) body.get("auth_states");
        if (authStates == null || authStates.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'auth_states'");
            return;
        }

        // Determine base_url
        String baseUrl = (String) body.get("base_url");
        if (baseUrl == null || baseUrl.isBlank()) {
            // Try to get from first auth state's session
            for (var stateEntry : authStates.entrySet()) {
                Map<String, Object> stateConfig = (Map<String, Object>) stateEntry.getValue();
                String sessionName = (String) stateConfig.get("session");
                if (sessionName != null) {
                    SessionHandler.Session session = sessions.get(sessionName);
                    if (session != null && !session.baseUrl.isEmpty()) {
                        baseUrl = session.baseUrl;
                        break;
                    }
                }
            }
        }
        if (baseUrl == null || baseUrl.isBlank()) {
            sendError(exchange, 400, "Cannot determine base_url: provide it or use a session with base_url set");
            return;
        }

        // Collect auth state names in order
        List<String> stateNames = new ArrayList<>(authStates.keySet());

        List<Map<String, Object>> matrix = new ArrayList<>();
        int totalRequests = 0;
        int potentialIssues = 0;

        for (Map<String, Object> endpoint : endpoints) {
            String method = (String) endpoint.getOrDefault("method", "GET");
            String endpointPath = (String) endpoint.getOrDefault("path", "/");
            String endpointBody = (String) endpoint.get("body");
            String url = baseUrl.endsWith("/") && endpointPath.startsWith("/")
                ? baseUrl.substring(0, baseUrl.length() - 1) + endpointPath
                : baseUrl + endpointPath;

            Map<String, Object> endpointResult = new LinkedHashMap<>();
            endpointResult.put("method", method);
            endpointResult.put("path", endpointPath);

            // Send request for each auth state — results keyed by state name
            Map<String, Object> stateResults = new LinkedHashMap<>();
            String firstBody = null;
            int firstStatus = 0;

            for (int i = 0; i < stateNames.size(); i++) {
                String stateName = stateNames.get(i);
                @SuppressWarnings("unchecked")
                Map<String, Object> stateConfig = (Map<String, Object>) authStates.get(stateName);

                HttpRequestResponse result = sendWithAuthState(method, url, endpointBody, stateConfig);
                totalRequests++;

                Map<String, Object> sr = new LinkedHashMap<>();

                if (result != null && result.response() != null) {
                    HttpResponse resp = result.response();
                    int status = resp.statusCode();
                    int length = resp.body().length();
                    String respBody = resp.bodyToString();

                    sr.put("status", status);
                    sr.put("length", length);

                    if (i == 0) {
                        firstStatus = status;
                        firstBody = respBody;
                    } else {
                        double similarity = calculateSimilarity(firstBody, respBody);
                        sr.put("similarity", Math.round(similarity * 100));

                        // Flag IDOR: same 2xx status + >90% body similarity
                        boolean bothSuccess = (firstStatus >= 200 && firstStatus < 300)
                            && (status >= 200 && status < 300);
                        if (bothSuccess && similarity > 0.9) {
                            sr.put("flag", "IDOR");
                            potentialIssues++;
                        }
                    }
                } else {
                    sr.put("status", 0);
                    sr.put("error", "Request failed");
                }

                stateResults.put(stateName, sr);
            }

            endpointResult.put("results", stateResults);
            matrix.add(endpointResult);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("matrix", matrix);
        out.put("endpoints_tested", endpoints.size());
        out.put("auth_states_tested", stateNames.size());
        out.put("total_requests", totalRequests);
        out.put("potential_issues", potentialIssues);
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── POST /api/attack/race ────────────────────────────────────

    @SuppressWarnings("unchecked")
    private void handleRaceCondition(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) {
            sendError(exchange, 400, "Missing 'session'");
            return;
        }

        SessionHandler.Session session = sessions.get(sessionName);
        if (session == null) {
            sendError(exchange, 404, "Session not found: " + sessionName);
            return;
        }

        Map<String, Object> requestSpec = (Map<String, Object>) body.get("request");
        if (requestSpec == null) {
            sendError(exchange, 400, "Missing 'request'");
            return;
        }

        int concurrent = 10;
        Object concObj = body.get("concurrent");
        if (concObj instanceof Number n) {
            concurrent = Math.min(Math.max(n.intValue(), 1), 50);
        }

        boolean expectOnce = true;
        Object expectObj = body.get("expect_once");
        if (expectObj instanceof Boolean b) {
            expectOnce = b;
        }

        // Build the base request
        String method = (String) requestSpec.getOrDefault("method", "POST");
        String reqPath = (String) requestSpec.getOrDefault("path", "/");
        String fullUrl;
        if (!session.baseUrl.isEmpty()) {
            String base = session.baseUrl;
            if (base.endsWith("/") && reqPath.startsWith("/")) {
                base = base.substring(0, base.length() - 1);
            }
            fullUrl = base + reqPath;
        } else {
            fullUrl = reqPath;
        }

        HttpRequest baseRequest;
        try {
            URI uri = new URI(fullUrl);
            baseRequest = buildBaseRequest(uri, method, session);
            baseRequest = resolveRequestBody(baseRequest, requestSpec);
        } catch (Exception e) {
            sendError(exchange, 400, "Failed to build request: " + e.getMessage());
            return;
        }

        // Fire concurrent requests using CountDownLatch
        ExecutorService executor = Executors.newFixedThreadPool(concurrent);
        CountDownLatch readyLatch = new CountDownLatch(concurrent);
        CountDownLatch goLatch = new CountDownLatch(1);

        final HttpRequest finalRequest = baseRequest;
        List<Future<Map<String, Object>>> futures = new ArrayList<>();

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < concurrent; i++) {
            final int index = i;
            futures.add(executor.submit(() -> {
                readyLatch.countDown();
                goLatch.await();

                long reqStart = System.currentTimeMillis();
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("index", index);

                try {
                    HttpRequestResponse response = api.http().sendRequest(finalRequest);
                    long reqEnd = System.currentTimeMillis();
                    result.put("time_ms", reqEnd - reqStart);

                    if (response != null && response.response() != null) {
                        HttpResponse resp = response.response();
                        result.put("status", resp.statusCode());
                        int len = resp.body().length();
                        result.put("length", len);
                        result.put("response_length", len);

                        String bodyStr = resp.bodyToString();
                        if (bodyStr.length() > 500) {
                            bodyStr = bodyStr.substring(0, 500);
                        }
                        result.put("body_preview", bodyStr);
                    } else {
                        result.put("status", 0);
                        result.put("length", 0);
                        result.put("error", "No response");
                    }
                } catch (Exception e) {
                    result.put("status", 0);
                    result.put("error", e.getMessage());
                    result.put("time_ms", System.currentTimeMillis() - reqStart);
                }

                return result;
            }));
        }

        // Wait for all threads to be ready, then release them simultaneously
        readyLatch.await(10, TimeUnit.SECONDS);
        goLatch.countDown();

        // Collect results
        List<Map<String, Object>> results = new ArrayList<>();
        for (Future<Map<String, Object>> f : futures) {
            try {
                results.add(f.get(30, TimeUnit.SECONDS));
            } catch (Exception e) {
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("error", e.getMessage());
                results.add(err);
            }
        }

        long totalTime = System.currentTimeMillis() - startTime;
        executor.shutdown();

        // Analyze results
        Map<Integer, Integer> statusDistribution = new LinkedHashMap<>();
        int successCount = 0;
        for (Map<String, Object> r : results) {
            Object statusObj = r.get("status");
            int status = statusObj instanceof Number n ? n.intValue() : 0;
            statusDistribution.merge(status, 1, Integer::sum);
            if (status >= 200 && status < 300) {
                successCount++;
            }
        }

        boolean vulnerable = expectOnce && successCount > 1;

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("concurrent", concurrent);
        out.put("total_time_ms", totalTime);
        out.put("status_distribution", statusDistribution);
        out.put("success_count", successCount);
        out.put("results", results);
        out.put("vulnerable", vulnerable);
        if (vulnerable) {
            out.put("finding", "Race condition detected: expected single success but got "
                + successCount + " successful responses out of " + concurrent + " concurrent requests");
        }
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── POST /api/attack/hpp ─────────────────────────────────────

    @SuppressWarnings("unchecked")
    private void handleHpp(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) {
            sendError(exchange, 400, "Missing 'session'");
            return;
        }

        SessionHandler.Session session = sessions.get(sessionName);
        if (session == null) {
            sendError(exchange, 404, "Session not found: " + sessionName);
            return;
        }

        String basePath = (String) body.get("base_path");
        if (basePath == null || basePath.isBlank()) {
            sendError(exchange, 400, "Missing 'base_path'");
            return;
        }

        String parameter = (String) body.get("parameter");
        if (parameter == null || parameter.isBlank()) {
            sendError(exchange, 400, "Missing 'parameter'");
            return;
        }

        String originalValue = (String) body.get("original_value");
        if (originalValue == null) {
            sendError(exchange, 400, "Missing 'original_value'");
            return;
        }

        List<String> pollutedValues = (List<String>) body.get("polluted_values");
        if (pollutedValues == null || pollutedValues.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'polluted_values'");
            return;
        }

        List<String> locations = (List<String>) body.get("locations");
        if (locations == null || locations.isEmpty()) {
            locations = List.of("query", "body", "both");
        }

        String baseUrl = session.baseUrl;
        if (baseUrl.isEmpty()) {
            sendError(exchange, 400, "Session has no base_url set");
            return;
        }

        // Send baseline: original value in query
        String baselineUrl = buildUrl(baseUrl, basePath, parameter, originalValue);
        HttpRequest baselineReq;
        try {
            URI uri = new URI(baselineUrl);
            baselineReq = buildBaseRequest(uri, "GET", session);
        } catch (Exception e) {
            sendError(exchange, 400, "Failed to build baseline request: " + e.getMessage());
            return;
        }

        HttpRequestResponse baselineResult = api.http().sendRequest(baselineReq);
        int baselineStatus = 0;
        int baselineLength = 0;
        if (baselineResult != null && baselineResult.response() != null) {
            baselineStatus = baselineResult.response().statusCode();
            baselineLength = baselineResult.response().body().length();
        }

        // Test polluted variants
        List<Map<String, Object>> variantResults = new ArrayList<>();
        int anomaliesFound = 0;

        for (String pollutedValue : pollutedValues) {
            for (String location : locations) {
                Map<String, Object> variant = new LinkedHashMap<>();
                variant.put("polluted_value", pollutedValue);
                variant.put("payload", pollutedValue);
                variant.put("location", location);

                try {
                    HttpRequest variantReq = buildHppRequest(
                        baseUrl, basePath, parameter, originalValue, pollutedValue, location, session);

                    HttpRequestResponse variantResult = api.http().sendRequest(variantReq);

                    if (variantResult != null && variantResult.response() != null) {
                        HttpResponse resp = variantResult.response();
                        int status = resp.statusCode();
                        int length = resp.body().length();

                        variant.put("status", status);
                        variant.put("length", length);
                        variant.put("response_length", length);
                        variant.put("length_diff", Math.abs(length - baselineLength));

                        // Detect anomaly: status differs or length differs >20%
                        boolean statusDiffers = status != baselineStatus;
                        boolean lengthDiffers = baselineLength > 0
                            && Math.abs(length - baselineLength) > (baselineLength * 0.2);

                        if (statusDiffers || lengthDiffers) {
                            variant.put("anomaly", true);
                            if (statusDiffers) variant.put("status_differs", true);
                            if (lengthDiffers) variant.put("length_differs", true);
                            anomaliesFound++;
                        }
                    } else {
                        variant.put("status", 0);
                        variant.put("error", "No response");
                    }
                } catch (Exception e) {
                    variant.put("error", e.getMessage());
                }

                variantResults.add(variant);
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("baseline_status", baselineStatus);
        out.put("baseline_length", baselineLength);
        out.put("variants_tested", variantResults.size());
        out.put("results", variantResults);
        out.put("anomalies_found", anomaliesFound);
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── Helper: send request with auth state config ──────────────

    @SuppressWarnings("unchecked")
    private HttpRequestResponse sendWithAuthState(String method, String url, String body,
                                                   Map<String, Object> stateConfig) {
        try {
            Object removeAuth = stateConfig.get("remove_auth");
            boolean noAuth = removeAuth instanceof Boolean b && b;

            URI uri = new URI(url);
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

            if (!noAuth) {
                // Apply session state if referenced
                String sessionName = (String) stateConfig.get("session");
                if (sessionName != null) {
                    SessionHandler.Session session = sessions.get(sessionName);
                    if (session != null) {
                        // Apply session headers
                        for (var entry : session.headers.entrySet()) {
                            request = request.withHeader(entry.getKey(), entry.getValue());
                        }
                        // Apply session cookies
                        if (!session.cookies.isEmpty()) {
                            request = request.withHeader("Cookie", buildCookieString(session.cookies));
                        }
                        // Apply session bearer
                        if (!session.bearerToken.isEmpty()) {
                            request = request.withHeader("Authorization", "Bearer " + session.bearerToken);
                        }
                    }
                }

                // Override with explicit bearer_token
                String bearerToken = (String) stateConfig.get("bearer_token");
                if (bearerToken != null && !bearerToken.isEmpty()) {
                    request = request.withHeader("Authorization", "Bearer " + bearerToken);
                }

                // Override with explicit cookies
                Map<String, Object> cookies = (Map<String, Object>) stateConfig.get("cookies");
                if (cookies != null && !cookies.isEmpty()) {
                    Map<String, String> cookieMap = new LinkedHashMap<>();
                    cookies.forEach((k, v) -> cookieMap.put(k, String.valueOf(v)));
                    request = request.withHeader("Cookie", buildCookieString(cookieMap));
                }

                // Override with explicit headers
                Map<String, Object> headers = (Map<String, Object>) stateConfig.get("headers");
                if (headers != null) {
                    for (var entry : headers.entrySet()) {
                        request = request.withHeader(entry.getKey(), String.valueOf(entry.getValue()));
                    }
                }
            }

            // Apply body if present
            if (body != null && !body.isEmpty()) {
                request = request.withBody(body);
            }

            return api.http().sendRequest(request);
        } catch (Exception e) {
            return null;
        }
    }

    // ── Helper: build base request from URI + session ────────────

    private HttpRequest buildBaseRequest(URI uri, String method, SessionHandler.Session session) {
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

        // Apply session headers
        for (var entry : session.headers.entrySet()) {
            request = request.withHeader(entry.getKey(), entry.getValue());
        }

        // Apply bearer token
        if (!session.bearerToken.isEmpty()) {
            request = request.withHeader("Authorization", "Bearer " + session.bearerToken);
        }

        // Apply cookies
        if (!session.cookies.isEmpty()) {
            request = request.withHeader("Cookie", buildCookieString(session.cookies));
        }

        return request;
    }

    // ── Helper: resolve request body from spec ───────────────────

    @SuppressWarnings("unchecked")
    private HttpRequest resolveRequestBody(HttpRequest request, Map<String, Object> spec) {
        Map<String, Object> jsonBody = (Map<String, Object>) spec.get("json_body");
        if (jsonBody != null) {
            request = request.withHeader("Content-Type", "application/json");
            return request.withBody(JsonUtil.toJson(jsonBody));
        }

        String data = (String) spec.get("data");
        if (data != null && !data.isEmpty()) {
            request = request.withHeader("Content-Type", "application/x-www-form-urlencoded");
            return request.withBody(data);
        }

        String body = (String) spec.get("body");
        if (body != null && !body.isEmpty()) {
            return request.withBody(body);
        }

        return request;
    }

    // ── Helper: build HPP variant request ────────────────────────

    private HttpRequest buildHppRequest(String baseUrl, String basePath, String parameter,
                                         String originalValue, String pollutedValue,
                                         String location, SessionHandler.Session session) throws Exception {
        String url;
        String body = null;

        switch (location) {
            case "query" -> {
                url = buildUrl(baseUrl, basePath, parameter, pollutedValue);
            }
            case "body" -> {
                url = buildUrl(baseUrl, basePath, null, null);
                body = parameter + "=" + pollutedValue;
            }
            case "both" -> {
                url = buildUrl(baseUrl, basePath, parameter, originalValue);
                body = parameter + "=" + pollutedValue;
            }
            default -> {
                url = buildUrl(baseUrl, basePath, parameter, pollutedValue);
            }
        }

        URI uri = new URI(url);
        HttpRequest request = buildBaseRequest(uri, "GET", session);

        if (body != null) {
            request = request.withMethod("POST")
                .withHeader("Content-Type", "application/x-www-form-urlencoded")
                .withBody(body);
        }

        return request;
    }

    // ── Helper: build URL with query parameter ───────────────────

    private String buildUrl(String baseUrl, String path, String param, String value) {
        String base = baseUrl.endsWith("/") && path.startsWith("/")
            ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String url = base + path;
        if (param != null && value != null) {
            url += "?" + param + "=" + value;
        }
        return url;
    }

    // ── Helper: build cookie header string ───────────────────────

    private String buildCookieString(Map<String, String> cookies) {
        StringBuilder sb = new StringBuilder();
        for (var entry : cookies.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }
        return sb.toString();
    }

    // ── Helper: calculate string similarity ──────────────────────

    /**
     * Calculates similarity between two strings using length ratio and character sampling.
     * Returns a value between 0.0 (completely different) and 1.0 (identical).
     */
    double calculateSimilarity(String a, String b) {
        if (a == null && b == null) return 1.0;
        if (a == null || b == null) return 0.0;
        if (a.equals(b)) return 1.0;
        if (a.isEmpty() && b.isEmpty()) return 1.0;
        if (a.isEmpty() || b.isEmpty()) return 0.0;

        // Length similarity
        double lengthSimilarity = (double) Math.min(a.length(), b.length())
            / Math.max(a.length(), b.length());

        // Character sampling: sample 200 positions, count matches
        int sampleSize = 200;
        int minLen = Math.min(a.length(), b.length());
        int samplesToTake = Math.min(sampleSize, minLen);
        int matches = 0;

        if (samplesToTake > 0) {
            double step = (double) minLen / samplesToTake;
            for (int i = 0; i < samplesToTake; i++) {
                int pos = (int) (i * step);
                if (pos < a.length() && pos < b.length() && a.charAt(pos) == b.charAt(pos)) {
                    matches++;
                }
            }
        }

        double charSimilarity = samplesToTake > 0 ? (double) matches / samplesToTake : 0.0;

        return (lengthSimilarity + charSimilarity) / 2.0;
    }
}
