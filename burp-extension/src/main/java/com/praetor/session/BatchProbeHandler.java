package com.praetor.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.praetor.handlers.Session;
import com.praetor.http.HttpExchange;
import static com.praetor.http.HttpResponses.sendJson;
import static com.praetor.http.HttpResponses.sendError;
import com.praetor.store.SessionStore;
import com.praetor.ui.ConfigTab;
import com.praetor.util.JsonUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Handles {@code POST /api/session/probe} (baseline vs payload comparison
 * with adaptive payload selection + vulnerability scoring) and
 * {@code POST /api/session/batch} (multi-endpoint hit). Behaviour-preserving
 * lift from SessionHandler.handleProbe + handleBatch.
 */
public final class BatchProbeHandler {

    private final MontoyaApi api;
    private final SessionRequestExecutor executor;

    public BatchProbeHandler(MontoyaApi api, SessionRequestExecutor executor) {
        this.api = api;
        this.executor = executor;
    }

    // ── POST /api/session/probe ──────────────────────────────────────

    @SuppressWarnings("unchecked")
    public void handleProbe(HttpExchange exchange, Map<String, Object> body, SessionStore store) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) { sendError(exchange, 400, "Missing 'session'"); return; }
        Session session = store.getSession(sessionName);
        if (session == null) { sendError(exchange, 404, "Session not found: " + sessionName); return; }

        String method = (String) body.getOrDefault("method", "GET");
        String path = (String) body.getOrDefault("path", "/");
        String parameter = (String) body.get("parameter");
        String baselineValue = (String) body.getOrDefault("baseline_value", "1");
        String payloadValue = (String) body.getOrDefault("payload_value", "");
        String injectionPoint = ((String) body.getOrDefault("injection_point", "query")).toLowerCase();
        List<String> testPayloads = body.containsKey("test_payloads") ? (List<String>) body.get("test_payloads") : null;

        if (parameter == null) { sendError(exchange, 400, "Missing 'parameter'"); return; }
        if (!injectionPoint.equals("query") && !injectionPoint.equals("body")) {
            sendError(exchange, 400, "injection_point must be 'query' or 'body' (got '" + injectionPoint + "')");
            return;
        }

        synchronized (session) {
            Map<String, Object> baselineParams = new LinkedHashMap<>(body);
            baselineParams.put("path", ProbeHelpers.injectParam(path, parameter, baselineValue, injectionPoint));
            if ("body".equals(injectionPoint)) baselineParams.put("data", parameter + "=" + baselineValue);

            long baseStart = System.nanoTime();
            HttpRequestResponse baselineResult = executor.send(session, baselineParams);
            long baseMs = (System.nanoTime() - baseStart) / 1_000_000;
            if (baselineResult != null) executor.updateCookiesFromResponse(session, baselineResult);

            int baseStatus = baselineResult != null && baselineResult.response() != null ? baselineResult.response().statusCode() : 0;
            int baseLen = baselineResult != null && baselineResult.response() != null ? baselineResult.response().body().length() : 0;

            List<String> detectedTech = TechFingerprint.detectFromResponse(baselineResult);

            if ((payloadValue == null || payloadValue.isEmpty()) && (testPayloads == null || testPayloads.isEmpty())) {
                testPayloads = com.praetor.analysis.SessionProbeHelpers.selectAdaptivePayloads(detectedTech, parameter);
            }

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

            List<Map<String, Object>> payloadResults = new ArrayList<>();
            int maxVulnScore = 0;

            for (String testPayload : testPayloads) {
                Map<String, Object> payParams = new LinkedHashMap<>(body);
                payParams.put("path", ProbeHelpers.injectParam(path, parameter, testPayload, injectionPoint));
                if ("body".equals(injectionPoint)) payParams.put("data", parameter + "=" + testPayload);

                long payStart = System.nanoTime();
                HttpRequestResponse payResult = executor.send(session, payParams);
                long payMs = (System.nanoTime() - payStart) / 1_000_000;
                if (payResult != null) executor.updateCookiesFromResponse(session, payResult);
                session.lastResponse = payResult;

                int payStatus = payResult != null && payResult.response() != null ? payResult.response().statusCode() : 0;
                int payLen = payResult != null && payResult.response() != null ? payResult.response().body().length() : 0;
                String payBody = payResult != null && payResult.response() != null ? payResult.response().bodyToString() : "";

                List<Map<String, Object>> errors = com.praetor.analysis.SessionProbeHelpers.detectErrorPatterns(payBody, payStatus);
                Map<String, Object> reflection = com.praetor.analysis.SessionProbeHelpers.detectReflection(testPayload, payBody);

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

    // ── POST /api/session/batch ──────────────────────────────────────

    public void handleBatch(HttpExchange exchange, Map<String, Object> body, SessionStore store) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) { sendError(exchange, 400, "Missing 'session'"); return; }
        Session session = store.getSession(sessionName);
        if (session == null) { sendError(exchange, 404, "Session not found: " + sessionName); return; }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> endpoints = (List<Map<String, Object>>) body.get("endpoints");
        if (endpoints == null || endpoints.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'endpoints'"); return;
        }

        synchronized (session) {
            List<Map<String, Object>> results = new ArrayList<>();
            Map<Integer, Integer> statusCounts = new TreeMap<>();
            long totalStart = System.nanoTime();

            for (int i = 0; i < endpoints.size(); i++) {
                Map<String, Object> ep = endpoints.get(i);
                Map<String, Object> reqParams = new LinkedHashMap<>(ep);
                reqParams.put("session", sessionName);

                long reqStart = System.nanoTime();
                HttpRequestResponse result = executor.send(session, reqParams);
                long reqMs = (System.nanoTime() - reqStart) / 1_000_000;
                if (result != null) executor.updateCookiesFromResponse(session, result);

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

                if (result != null && result.response() != null) {
                    String bodyStr = result.response().bodyToString();
                    r.put("title", SessionRequestExecutor.extractTitle(bodyStr));
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

}
