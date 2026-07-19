package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.praetor.fuzz.FuzzResult;
import com.praetor.fuzz.FuzzVariant;
import com.praetor.fuzz.VariantBuilder;
import com.praetor.fuzz.VariantExecutor;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.util.JsonUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * POST /api/fuzz — execute fuzz attack with Claude-generated payloads.
 * Supports sniper, battering_ram, pitchfork, and cluster_bomb attack types.
 *
 * Thin orchestrator: variant generation lives in {@link VariantBuilder},
 * per-variant send + grep in {@link VariantExecutor}.
 */
public class FuzzHandler extends BaseHandler {

    private static final int MAX_REQUESTS = 500;

    private final MontoyaApi api;
    private final VariantBuilder builder = new VariantBuilder(MAX_REQUESTS);
    private final VariantExecutor executor;

    public FuzzHandler(MontoyaApi api) {
        this.api = api;
        this.executor = new VariantExecutor(api);
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String path = exchange.getRequestURI().getPath();
        if (!"/api/fuzz".equals(path)) {
            sendError(exchange, 404, "Not found");
            return;
        }

        Map<String, Object> body = readJsonBody(exchange);
        handleFuzz(exchange, body);
    }

    private void handleFuzz(HttpExchange exchange, Map<String, Object> body) throws Exception {
        Object idxObj = body.get("index");
        if (!(idxObj instanceof Number)) {
            sendError(exchange, 400, "Missing or invalid 'index'");
            return;
        }
        int index = ((Number) idxObj).intValue();

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index < 0 || index >= history.size()) {
            sendError(exchange, 404, "Index out of range");
            return;
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> parameters = (List<Map<String, Object>>) body.get("parameters");
        if (parameters == null || parameters.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'parameters'");
            return;
        }

        String attackType = (String) body.getOrDefault("attack_type", "sniper");
        @SuppressWarnings("unchecked")
        List<String> grepMatch = body.get("grep_match") != null
                ? toStringList((List<Object>) body.get("grep_match")) : Collections.emptyList();
        String grepExtract = (String) body.get("grep_extract");
        int maxConcurrent = body.get("max_concurrent") instanceof Number n ? n.intValue() : 5;
        // Cap at 2s. The handler thread is one of a fixed 6-thread pool;
        // a 10-second per-iteration delay starves the API.
        int delayMs = Math.max(0, Math.min(body.get("delay_ms") instanceof Number n ? n.intValue() : 0, 2_000));

        HttpRequest baseRequest = history.get(index).finalRequest();
        HttpResponse baseResponse = history.get(index).originalResponse();

        // Scope gate (Rule 1 HARD): the base host is reused for every variant
        // so one upfront check is sufficient — variants only mutate params.
        if (!requireInScope(api, exchange, baseRequest.url())) return;

        int baselineStatus = baseResponse != null ? baseResponse.statusCode() : 0;
        int baselineLength = baseResponse != null ? baseResponse.body().length() : 0;

        List<FuzzVariant> variants = builder.generate(baseRequest, parameters, attackType);

        if (variants.size() > MAX_REQUESTS) {
            sendError(exchange, 400, "Too many requests: " + variants.size() + " (max " + MAX_REQUESTS + ")");
            return;
        }

        // Execute variants. Cap parallelism at 20 to match attack-handler
        // conventions and avoid starving the API thread pool.
        int parallelism = Math.max(1, Math.min(maxConcurrent, 20));
        List<FuzzResult> results = new ArrayList<>(variants.size());
        for (int i = 0; i < variants.size(); i++) results.add(null);

        if (parallelism == 1 || variants.size() <= 1) {
            for (int i = 0; i < variants.size(); i++) {
                if (delayMs > 0 && i > 0) Thread.sleep(delayMs);
                results.set(i, executor.execute(i, variants.get(i), grepMatch, grepExtract));
            }
        } else {
            java.util.concurrent.ExecutorService pool =
                java.util.concurrent.Executors.newFixedThreadPool(parallelism);
            try {
                List<java.util.concurrent.Future<FuzzResult>> futures = new ArrayList<>(variants.size());
                for (int i = 0; i < variants.size(); i++) {
                    final int idx = i;
                    final FuzzVariant variant = variants.get(i);
                    final int localDelay = delayMs;
                    futures.add(pool.submit(() -> {
                        // Stagger inside the worker so delay_ms still throttles
                        // when parallelism > 1; without this max_concurrent
                        // would defeat the point of delay_ms.
                        if (localDelay > 0 && idx > 0) {
                            try { Thread.sleep(localDelay); } catch (InterruptedException ie) {
                                Thread.currentThread().interrupt();
                            }
                        }
                        return executor.execute(idx, variant, grepMatch, grepExtract);
                    }));
                }
                for (int i = 0; i < futures.size(); i++) {
                    try {
                        results.set(i, futures.get(i).get(60, java.util.concurrent.TimeUnit.SECONDS));
                    } catch (Exception e) {
                        FuzzResult err = new FuzzResult();
                        err.payloadIndex = i;
                        err.parameter = variants.get(i).paramName;
                        err.payload = variants.get(i).payload;
                        err.anomalies = new ArrayList<>(List.of("EXEC_ERROR:" + e.getClass().getSimpleName()));
                        results.set(i, err);
                    }
                }
            } finally {
                pool.shutdown();
            }
        }

        // Compute medians for anomaly detection.
        List<Integer> lengths = new ArrayList<>();
        List<Long> times = new ArrayList<>();
        for (FuzzResult r : results) {
            lengths.add(r.responseLength);
            times.add(r.responseTimeMs);
        }
        int medianLength = median(lengths);
        long medianTime = medianLong(times);

        int statusAnomalies = 0;
        int lengthAnomalies = 0;
        int timingAnomalies = 0;
        int totalGrepHits = 0;

        for (FuzzResult r : results) {
            r.anomalies = new ArrayList<>();

            if (r.statusCode != baselineStatus) {
                r.anomalies.add("STATUS_DIFF");
                statusAnomalies++;
            }
            if (medianLength > 0 && Math.abs(r.responseLength - medianLength) > medianLength * 0.2) {
                r.anomalies.add("LENGTH_DIFF");
                lengthAnomalies++;
            }
            if (medianTime > 0 && r.responseTimeMs > medianTime * 3) {
                r.anomalies.add("TIMING_ANOMALY");
                timingAnomalies++;
            }

            if (r.grepMatches != null) {
                for (int count : r.grepMatches.values()) {
                    totalGrepHits += count;
                }
                if (!r.grepMatches.isEmpty()) {
                    r.anomalies.add("GREP_HIT");
                }
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total_requests", results.size());
        out.put("baseline_status", baselineStatus);
        out.put("baseline_length", baselineLength);

        List<Map<String, Object>> resultList = new ArrayList<>();
        for (FuzzResult r : results) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("payload_index", r.payloadIndex);
            entry.put("parameter", r.parameter);
            entry.put("payload", r.payload);
            entry.put("status_code", r.statusCode);
            entry.put("response_length", r.responseLength);
            entry.put("response_time_ms", r.responseTimeMs);
            if (r.grepMatches != null && !r.grepMatches.isEmpty()) {
                Map<String, Object> gm = new LinkedHashMap<>();
                for (var e : r.grepMatches.entrySet()) gm.put(e.getKey(), e.getValue());
                entry.put("grep_matches", gm);
            }
            if (r.grepExtracted != null) {
                entry.put("grep_extracted", r.grepExtracted);
            }
            entry.put("anomalies", r.anomalies);
            if (r.responseSnippet != null) {
                entry.put("response_snippet", r.responseSnippet);
            }
            resultList.add(entry);
        }
        out.put("results", resultList);

        Map<String, Object> anomalySummary = new LinkedHashMap<>();
        anomalySummary.put("status_anomalies", statusAnomalies);
        anomalySummary.put("length_anomalies", lengthAnomalies);
        anomalySummary.put("timing_anomalies", timingAnomalies);
        anomalySummary.put("grep_hits", totalGrepHits);
        out.put("anomaly_summary", anomalySummary);

        sendJson(exchange, JsonUtil.toJson(out));
    }

    private static List<String> toStringList(List<Object> list) {
        if (list == null) return Collections.emptyList();
        List<String> result = new ArrayList<>();
        for (Object o : list) {
            result.add(String.valueOf(o));
        }
        return result;
    }

    private static int median(List<Integer> values) {
        if (values.isEmpty()) return 0;
        List<Integer> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        return sorted.get(sorted.size() / 2);
    }

    private static long medianLong(List<Long> values) {
        if (values.isEmpty()) return 0;
        List<Long> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        return sorted.get(sorted.size() / 2);
    }
}
