package com.praetor.attack;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.praetor.handlers.Session;
import com.praetor.http.HttpExchange;
import static com.praetor.http.HttpResponses.sendJson;
import static com.praetor.http.HttpResponses.sendError;
import com.praetor.store.SessionStore;
import com.praetor.util.JsonUtil;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Handles {@code POST /api/attack/race}: fires N concurrent identical
 * requests against a session-bound endpoint, holds them at a barrier,
 * releases them simultaneously, and flags a race condition when the
 * caller-declared "expect once" invariant is broken.
 *
 * Behaviour-preserving lift from AttackHandler.handleRaceCondition.
 */
public final class RaceHandler {

    private final MontoyaApi api;

    public RaceHandler(MontoyaApi api) {
        this.api = api;
    }

    @SuppressWarnings("unchecked")
    public void handle(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) {
            sendError(exchange, 400, "Missing 'session'");
            return;
        }

        Session session = SessionStore.get().getSession(sessionName);
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

        if (!AttackScope.requireInScope(api, exchange, fullUrl)) return;

        HttpRequest baseRequest;
        try {
            URI uri = new URI(fullUrl);
            baseRequest = AttackUtils.buildBaseRequest(uri, method, session);
            baseRequest = resolveRequestBody(baseRequest, requestSpec);
        } catch (Exception e) {
            sendError(exchange, 400, "Failed to build request: " + e.getMessage());
            return;
        }

        // Fire concurrent requests using CountDownLatch
        ExecutorService executor = Executors.newFixedThreadPool(concurrent);
        try {
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
                    HttpRequestResponse response = com.praetor.http.ProxyTunnel.sendOrFallback(api, finalRequest);
                    long reqEnd = System.currentTimeMillis();
                    result.put("time_ms", reqEnd - reqStart);

                    if (response != null && response.response() != null) {
                        HttpResponse resp = response.response();
                        result.put("status", resp.statusCode());
                        int len = resp.body().length();
                        result.put("length", len);
                        result.put("response_length", len);

                        String bodyStr = resp.bodyToString();
                        if (bodyStr.length() > 5000) {
                            bodyStr = bodyStr.substring(0, 5000);
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

        // Wait for all threads to be ready, then release them simultaneously.
        // If the latch times out, some workers never reached the barrier - fire
        // the goLatch anyway, but record that the race was unsynchronised so
        // the caller doesn't trust the "vulnerable" flag.
        boolean raceSynchronised = readyLatch.await(10, TimeUnit.SECONDS);
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

        // Analyze results - only count a 2xx as a "success" if its body
        // doesn't carry application-level error / "already processed" tokens
        // that some apps return alongside 200. Otherwise idempotent endpoints
        // returning 200+"already processed" inflate successCount and false-
        // positively flag IDOR/race vulns.
        Map<Integer, Integer> statusDistribution = new LinkedHashMap<>();
        int successCount = 0;
        for (Map<String, Object> r : results) {
            Object statusObj = r.get("status");
            int status = statusObj instanceof Number n ? n.intValue() : 0;
            statusDistribution.merge(status, 1, Integer::sum);
            if (status >= 200 && status < 300) {
                Object preview = r.get("body_preview");
                String bp = preview instanceof String s ? s.toLowerCase() : "";
                boolean appLevelDuplicate = bp.contains("already processed")
                    || bp.contains("already redeemed")
                    || bp.contains("duplicate request")
                    || bp.contains("duplicate transaction")
                    || bp.contains("already used")
                    || bp.contains("already submitted");
                if (!appLevelDuplicate) successCount++;
            }
        }

        boolean vulnerable = raceSynchronised && expectOnce && successCount > 1;

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("concurrent", concurrent);
        out.put("total_time_ms", totalTime);
        out.put("status_distribution", statusDistribution);
        out.put("success_count", successCount);
        out.put("race_synchronised", raceSynchronised);
        out.put("results", results);
        out.put("vulnerable", vulnerable);
        if (!raceSynchronised) {
            out.put("warning", "Some workers did not reach the barrier within 10s; race is NOT synchronised. " +
                "successCount values cannot be trusted. Re-run with smaller concurrent=N.");
        }
        if (vulnerable) {
            out.put("finding", "Race condition detected: expected single success but got "
                + successCount + " successful responses out of " + concurrent + " concurrent requests");
        }
        sendJson(exchange, JsonUtil.toJson(out));
        } finally {
            executor.shutdown();
        }
    }

    // -- Helper: resolve request body from spec -------------------

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

    // -- Response envelope (duplicated across attack handlers; see A1) ----

}
