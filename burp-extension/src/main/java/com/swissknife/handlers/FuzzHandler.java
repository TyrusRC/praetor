package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * POST /api/fuzz — execute fuzz attack with Claude-generated payloads.
 * Supports sniper, battering_ram, pitchfork, and cluster_bomb attack types.
 */
public class FuzzHandler extends BaseHandler {

    private static final int MAX_REQUESTS = 500;

    private final MontoyaApi api;

    public FuzzHandler(MontoyaApi api) {
        this.api = api;
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
        // Parse index
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

        // Parse parameters
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
        int delayMs = body.get("delay_ms") instanceof Number n ? n.intValue() : 0;

        // Get base request
        HttpRequest baseRequest = history.get(index).finalRequest();
        HttpResponse baseResponse = history.get(index).originalResponse();

        int baselineStatus = baseResponse != null ? baseResponse.statusCode() : 0;
        int baselineLength = baseResponse != null ? baseResponse.body().length() : 0;

        // Generate request variants
        List<FuzzVariant> variants = generateVariants(baseRequest, parameters, attackType);

        if (variants.size() > MAX_REQUESTS) {
            sendError(exchange, 400, "Too many requests: " + variants.size() + " (max " + MAX_REQUESTS + ")");
            return;
        }

        // Execute variants individually (to get per-request timing)
        List<FuzzResult> results = new ArrayList<>();
        for (int i = 0; i < variants.size(); i++) {
            FuzzVariant variant = variants.get(i);

            if (delayMs > 0 && i > 0) {
                Thread.sleep(delayMs);
            }

            long startNanos = System.nanoTime();
            HttpRequestResponse reqResp = com.swissknife.http.ProxyTunnel.sendOrFallback(api, variant.request);
            long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;

            HttpResponse resp = reqResp.response();
            FuzzResult result = new FuzzResult();
            result.payloadIndex = i;
            result.parameter = variant.paramName;
            result.payload = variant.payload;
            result.statusCode = resp != null ? resp.statusCode() : 0;
            result.responseLength = resp != null ? resp.body().length() : 0;
            result.responseTimeMs = elapsedMs;

            String respBody = resp != null ? resp.bodyToString() : "";

            // Grep matches
            if (!grepMatch.isEmpty()) {
                result.grepMatches = countGrepMatches(respBody, grepMatch);
            }

            // Grep extract
            if (grepExtract != null && !grepExtract.isEmpty()) {
                result.grepExtracted = extractPattern(respBody, grepExtract);
            }

            // Response snippet around first grep match
            if (!grepMatch.isEmpty()) {
                result.responseSnippet = extractSnippet(respBody, grepMatch);
            }

            results.add(result);
        }

        // Compute medians for anomaly detection
        List<Integer> lengths = new ArrayList<>();
        List<Long> times = new ArrayList<>();
        for (FuzzResult r : results) {
            lengths.add(r.responseLength);
            times.add(r.responseTimeMs);
        }
        int medianLength = median(lengths);
        long medianTime = medianLong(times);

        // Detect anomalies
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

        // Build response
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

    // ── Variant generation ────────────────────────────────────

    private List<FuzzVariant> generateVariants(HttpRequest baseRequest,
                                               List<Map<String, Object>> parameters,
                                               String attackType) {
        List<FuzzVariant> variants = new ArrayList<>();

        switch (attackType) {
            case "battering_ram" -> generateBatteringRam(baseRequest, parameters, variants);
            case "pitchfork" -> generatePitchfork(baseRequest, parameters, variants);
            case "cluster_bomb" -> generateClusterBomb(baseRequest, parameters, variants);
            default -> generateSniper(baseRequest, parameters, variants);
        }

        return variants;
    }

    /**
     * Sniper: one parameter at a time, each payload.
     */
    private void generateSniper(HttpRequest baseRequest,
                                List<Map<String, Object>> parameters,
                                List<FuzzVariant> variants) {
        for (Map<String, Object> param : parameters) {
            String name = (String) param.get("name");
            String position = (String) param.getOrDefault("position", "query");
            @SuppressWarnings("unchecked")
            List<String> payloads = toStringList((List<Object>) param.get("payloads"));

            for (String payload : payloads) {
                if (variants.size() >= MAX_REQUESTS) return;
                HttpRequest modified = modifyRequest(baseRequest, name, position, payload);
                variants.add(new FuzzVariant(modified, name, payload));
            }
        }
    }

    /**
     * Battering ram: same payload in all parameters simultaneously.
     */
    private void generateBatteringRam(HttpRequest baseRequest,
                                      List<Map<String, Object>> parameters,
                                      List<FuzzVariant> variants) {
        // Collect all unique payloads across all parameters
        Set<String> allPayloads = new LinkedHashSet<>();
        for (Map<String, Object> param : parameters) {
            @SuppressWarnings("unchecked")
            List<String> payloads = toStringList((List<Object>) param.get("payloads"));
            allPayloads.addAll(payloads);
        }

        for (String payload : allPayloads) {
            if (variants.size() >= MAX_REQUESTS) return;
            HttpRequest modified = baseRequest;
            StringBuilder paramNames = new StringBuilder();
            for (Map<String, Object> param : parameters) {
                String name = (String) param.get("name");
                String position = (String) param.getOrDefault("position", "query");
                modified = modifyRequest(modified, name, position, payload);
                if (paramNames.length() > 0) paramNames.append(",");
                paramNames.append(name);
            }
            variants.add(new FuzzVariant(modified, paramNames.toString(), payload));
        }
    }

    /**
     * Pitchfork: parallel payload lists (payload[i] in param[i]).
     */
    private void generatePitchfork(HttpRequest baseRequest,
                                   List<Map<String, Object>> parameters,
                                   List<FuzzVariant> variants) {
        // Find minimum payload list length
        int minLen = Integer.MAX_VALUE;
        List<List<String>> allPayloads = new ArrayList<>();
        for (Map<String, Object> param : parameters) {
            @SuppressWarnings("unchecked")
            List<String> payloads = toStringList((List<Object>) param.get("payloads"));
            allPayloads.add(payloads);
            minLen = Math.min(minLen, payloads.size());
        }
        if (minLen == 0 || minLen == Integer.MAX_VALUE) return;

        for (int i = 0; i < minLen; i++) {
            if (variants.size() >= MAX_REQUESTS) return;
            HttpRequest modified = baseRequest;
            StringBuilder paramNames = new StringBuilder();
            StringBuilder payloadDesc = new StringBuilder();
            for (int p = 0; p < parameters.size(); p++) {
                String name = (String) parameters.get(p).get("name");
                String position = (String) parameters.get(p).getOrDefault("position", "query");
                String payload = allPayloads.get(p).get(i);
                modified = modifyRequest(modified, name, position, payload);
                if (p > 0) { paramNames.append(","); payloadDesc.append(","); }
                paramNames.append(name);
                payloadDesc.append(payload);
            }
            variants.add(new FuzzVariant(modified, paramNames.toString(), payloadDesc.toString()));
        }
    }

    /**
     * Cluster bomb: all combinations of all payloads across all parameters.
     */
    private void generateClusterBomb(HttpRequest baseRequest,
                                     List<Map<String, Object>> parameters,
                                     List<FuzzVariant> variants) {
        List<List<String>> allPayloads = new ArrayList<>();
        for (Map<String, Object> param : parameters) {
            @SuppressWarnings("unchecked")
            List<String> payloads = toStringList((List<Object>) param.get("payloads"));
            allPayloads.add(payloads);
        }

        // Calculate total combinations (use long to avoid overflow, cap at MAX_REQUESTS)
        int[] indices = new int[parameters.size()];
        long totalCombinationsLong = 1;
        for (List<String> payloads : allPayloads) {
            if (payloads.isEmpty()) return;
            totalCombinationsLong *= payloads.size();
            if (totalCombinationsLong > MAX_REQUESTS) { totalCombinationsLong = MAX_REQUESTS; break; }
        }
        int totalCombinations = (int) totalCombinationsLong;

        for (int combo = 0; combo < totalCombinations; combo++) {
            if (variants.size() >= MAX_REQUESTS) return;

            HttpRequest modified = baseRequest;
            StringBuilder paramNames = new StringBuilder();
            StringBuilder payloadDesc = new StringBuilder();

            for (int p = 0; p < parameters.size(); p++) {
                String name = (String) parameters.get(p).get("name");
                String position = (String) parameters.get(p).getOrDefault("position", "query");
                String payload = allPayloads.get(p).get(indices[p]);
                modified = modifyRequest(modified, name, position, payload);
                if (p > 0) { paramNames.append(","); payloadDesc.append(","); }
                paramNames.append(name);
                payloadDesc.append(payload);
            }
            variants.add(new FuzzVariant(modified, paramNames.toString(), payloadDesc.toString()));

            // Increment indices (odometer style)
            for (int p = parameters.size() - 1; p >= 0; p--) {
                indices[p]++;
                if (indices[p] < allPayloads.get(p).size()) break;
                indices[p] = 0;
            }
        }
    }

    // ── Request modification ──────────────────────────────────

    private HttpRequest modifyRequest(HttpRequest request, String paramName, String position, String payload) {
        return switch (position) {
            case "query" -> modifyQueryParam(request, paramName, payload);
            case "body" -> modifyBodyParam(request, paramName, payload);
            case "header" -> request.withHeader(paramName, payload);
            case "path" -> modifyPathParam(request, paramName, payload);
            case "cookie" -> modifyCookie(request, paramName, payload);
            default -> modifyQueryParam(request, paramName, payload);
        };
    }

    private HttpRequest modifyQueryParam(HttpRequest request, String paramName, String payload) {
        String url = request.url();
        String path = request.path();

        // Split path and query
        int qIdx = path.indexOf('?');
        String basePath = qIdx >= 0 ? path.substring(0, qIdx) : path;
        String queryString = qIdx >= 0 ? path.substring(qIdx + 1) : "";

        String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
        String encodedName = URLEncoder.encode(paramName, StandardCharsets.UTF_8);

        if (queryString.isEmpty()) {
            return request.withPath(basePath + "?" + encodedName + "=" + encodedPayload);
        }

        // Try to replace existing parameter
        String[] pairs = queryString.split("&");
        boolean replaced = false;
        StringBuilder newQuery = new StringBuilder();
        for (String pair : pairs) {
            if (newQuery.length() > 0) newQuery.append("&");
            int eq = pair.indexOf('=');
            String key = eq >= 0 ? pair.substring(0, eq) : pair;
            if (key.equals(encodedName) || key.equals(paramName)) {
                newQuery.append(encodedName).append("=").append(encodedPayload);
                replaced = true;
            } else {
                newQuery.append(pair);
            }
        }
        if (!replaced) {
            newQuery.append("&").append(encodedName).append("=").append(encodedPayload);
        }

        return request.withPath(basePath + "?" + newQuery);
    }

    private HttpRequest modifyBodyParam(HttpRequest request, String paramName, String payload) {
        String bodyStr = request.bodyToString();

        // Detect JSON body
        String contentType = "";
        for (HttpHeader h : request.headers()) {
            if ("Content-Type".equalsIgnoreCase(h.name())) {
                contentType = h.value().toLowerCase();
                break;
            }
        }

        if (contentType.contains("application/json")) {
            return modifyJsonBody(request, paramName, payload, bodyStr);
        }

        // Form-encoded body
        String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
        String encodedName = URLEncoder.encode(paramName, StandardCharsets.UTF_8);

        if (bodyStr == null || bodyStr.isEmpty()) {
            return request.withBody(encodedName + "=" + encodedPayload);
        }

        String[] pairs = bodyStr.split("&");
        boolean replaced = false;
        StringBuilder newBody = new StringBuilder();
        for (String pair : pairs) {
            if (newBody.length() > 0) newBody.append("&");
            int eq = pair.indexOf('=');
            String key = eq >= 0 ? pair.substring(0, eq) : pair;
            if (key.equals(encodedName) || key.equals(paramName)) {
                newBody.append(encodedName).append("=").append(encodedPayload);
                replaced = true;
            } else {
                newBody.append(pair);
            }
        }
        if (!replaced) {
            newBody.append("&").append(encodedName).append("=").append(encodedPayload);
        }

        return request.withBody(newBody.toString());
    }

    private HttpRequest modifyJsonBody(HttpRequest request, String paramName, String payload, String bodyStr) {
        // Simple key replacement in JSON: find "paramName": "..." or "paramName": number and replace value
        // Use a simple regex approach for top-level keys
        String escaped = JsonUtil.escape(payload);
        String pattern = "\"" + Pattern.quote(paramName) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
        String replacement = "\"" + paramName + "\": \"" + escaped + "\"";

        String newBody = bodyStr.replaceFirst(pattern, Matcher.quoteReplacement(replacement));
        if (newBody.equals(bodyStr)) {
            // Key not found — try adding before closing brace
            int lastBrace = newBody.lastIndexOf('}');
            if (lastBrace > 0) {
                newBody = newBody.substring(0, lastBrace).stripTrailing();
                if (!newBody.endsWith("{")) newBody += ", ";
                newBody += "\"" + paramName + "\": \"" + escaped + "\"}";
            }
        }
        return request.withBody(newBody);
    }

    private HttpRequest modifyPathParam(HttpRequest request, String paramName, String payload) {
        String path = request.path();
        // Replace {paramName} placeholder or path segment matching the param name
        String modified = path.replace("{" + paramName + "}", URLEncoder.encode(payload, StandardCharsets.UTF_8));
        if (modified.equals(path)) {
            // Try replacing by segment value — replace segment after /paramName/ segment
            modified = path.replaceFirst(
                "(?i)/" + Pattern.quote(paramName) + "/([^/?]+)",
                "/" + paramName + "/" + URLEncoder.encode(payload, StandardCharsets.UTF_8)
            );
        }
        return request.withPath(modified);
    }

    private HttpRequest modifyCookie(HttpRequest request, String paramName, String payload) {
        String cookieHeader = "";
        for (HttpHeader h : request.headers()) {
            if ("Cookie".equalsIgnoreCase(h.name())) {
                cookieHeader = h.value();
                break;
            }
        }

        if (cookieHeader.isEmpty()) {
            return request.withHeader("Cookie", paramName + "=" + payload);
        }

        String[] cookies = cookieHeader.split(";\\s*");
        boolean replaced = false;
        StringBuilder newCookies = new StringBuilder();
        for (String cookie : cookies) {
            if (newCookies.length() > 0) newCookies.append("; ");
            int eq = cookie.indexOf('=');
            String name = eq >= 0 ? cookie.substring(0, eq).trim() : cookie.trim();
            if (name.equals(paramName)) {
                newCookies.append(paramName).append("=").append(payload);
                replaced = true;
            } else {
                newCookies.append(cookie.trim());
            }
        }
        if (!replaced) {
            newCookies.append("; ").append(paramName).append("=").append(payload);
        }

        return request.withHeader("Cookie", newCookies.toString());
    }

    // ── Grep and analysis helpers ─────────────────────────────

    private Map<String, Integer> countGrepMatches(String responseBody, List<String> patterns) {
        Map<String, Integer> matches = new LinkedHashMap<>();
        String bodyLower = responseBody.toLowerCase();

        for (String pattern : patterns) {
            String patternLower = pattern.toLowerCase();
            int count = 0;
            int idx = 0;
            while ((idx = bodyLower.indexOf(patternLower, idx)) != -1) {
                count++;
                idx += patternLower.length();
            }
            if (count > 0) {
                matches.put(pattern, count);
            }
        }
        return matches;
    }

    private String extractPattern(String responseBody, String regex) {
        try {
            Pattern p = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            Matcher m = p.matcher(responseBody);
            if (m.find()) {
                return m.group();
            }
        } catch (Exception ignored) {
            // Invalid regex — skip
        }
        return null;
    }

    private String extractSnippet(String responseBody, List<String> patterns) {
        String bodyLower = responseBody.toLowerCase();
        for (String pattern : patterns) {
            int idx = bodyLower.indexOf(pattern.toLowerCase());
            if (idx >= 0) {
                int start = Math.max(0, idx - 100);
                int end = Math.min(responseBody.length(), idx + pattern.length() + 100);
                String snippet = responseBody.substring(start, end);
                if (start > 0) snippet = "..." + snippet;
                if (end < responseBody.length()) snippet = snippet + "...";
                return snippet;
            }
        }
        return null;
    }

    // ── Utility helpers ───────────────────────────────────────

    private List<String> toStringList(List<Object> list) {
        if (list == null) return Collections.emptyList();
        List<String> result = new ArrayList<>();
        for (Object o : list) {
            result.add(String.valueOf(o));
        }
        return result;
    }

    private int median(List<Integer> values) {
        if (values.isEmpty()) return 0;
        List<Integer> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        return sorted.get(sorted.size() / 2);
    }

    private long medianLong(List<Long> values) {
        if (values.isEmpty()) return 0;
        List<Long> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        return sorted.get(sorted.size() / 2);
    }

    // ── Inner types ───────────────────────────────────────────

    private static class FuzzVariant {
        final HttpRequest request;
        final String paramName;
        final String payload;

        FuzzVariant(HttpRequest request, String paramName, String payload) {
            this.request = request;
            this.paramName = paramName;
            this.payload = payload;
        }
    }

    private static class FuzzResult {
        int payloadIndex;
        String parameter;
        String payload;
        int statusCode;
        int responseLength;
        long responseTimeMs;
        Map<String, Integer> grepMatches;
        String grepExtracted;
        List<String> anomalies;
        String responseSnippet;
    }
}
