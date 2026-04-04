package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * POST /api/search/history          - search proxy history by query, method, status, content
 * POST /api/search/response-diff    - diff two proxy history responses
 * POST /api/search/compare          - compare two responses programmatically (enhanced diff)
 * POST /api/search/send-to-comparer - send two items to Burp's Comparer tab
 */
public class SearchHandler extends BaseHandler {

    private final MontoyaApi api;

    public SearchHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();

        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        switch (path) {
            case "/api/search/history" -> handleSearchHistory(exchange);
            case "/api/search/response-diff" -> handleResponseDiff(exchange);
            case "/api/search/compare" -> handleCompare(exchange);
            case "/api/search/send-to-comparer" -> handleSendToComparer(exchange);
            default -> sendError(exchange, 404, "Not found");
        }
    }

    /**
     * Search proxy history.
     * Body: {"query":"admin","in_url":true,"in_request_body":false,"in_response_body":true,
     *        "method":"GET","status_code":200,"limit":50}
     */
    private void handleSearchHistory(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String query = (String) body.getOrDefault("query", "");
        boolean inUrl = Boolean.TRUE.equals(body.getOrDefault("in_url", true));
        boolean inRequestBody = Boolean.TRUE.equals(body.get("in_request_body"));
        boolean inResponseBody = Boolean.TRUE.equals(body.get("in_response_body"));
        String filterMethod = (String) body.get("method");
        Object statusObj = body.get("status_code");
        int filterStatus = statusObj instanceof Number n ? n.intValue() : 0;
        int limit = body.get("limit") instanceof Number n ? n.intValue() : 50;

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        List<Map<String, Object>> results = new ArrayList<>();
        String queryLower = query.toLowerCase();

        for (int i = history.size() - 1; i >= 0 && results.size() < limit; i--) {
            ProxyHttpRequestResponse item = history.get(i);
            HttpRequest req = item.finalRequest();
            HttpResponse resp = item.originalResponse();

            // Method filter
            if (filterMethod != null && !req.method().equalsIgnoreCase(filterMethod)) continue;
            // Status filter
            if (filterStatus > 0 && (resp == null || resp.statusCode() != filterStatus)) continue;

            // Query search
            if (!query.isEmpty()) {
                boolean found = false;
                if (inUrl && req.url().toLowerCase().contains(queryLower)) found = true;
                if (!found && inRequestBody && req.bodyToString().toLowerCase().contains(queryLower)) found = true;
                if (!found && inResponseBody && resp != null && resp.bodyToString().toLowerCase().contains(queryLower)) found = true;
                if (!found) continue;
            }

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("index", i);
            entry.put("method", req.method());
            entry.put("url", req.url());
            entry.put("status_code", resp != null ? resp.statusCode() : 0);
            entry.put("response_length", resp != null ? resp.body().length() : 0);
            results.add(entry);
        }

        sendJson(exchange, JsonUtil.object("results", results, "total_matches", results.size()));
    }

    /**
     * Diff two proxy history responses.
     * Body: {"index1": 10, "index2": 15}
     */
    private void handleResponseDiff(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        int idx1 = body.get("index1") instanceof Number n ? n.intValue() : -1;
        int idx2 = body.get("index2") instanceof Number n ? n.intValue() : -1;

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (idx1 < 0 || idx1 >= history.size() || idx2 < 0 || idx2 >= history.size()) {
            sendError(exchange, 400, "Invalid index values");
            return;
        }

        HttpResponse resp1 = history.get(idx1).originalResponse();
        HttpResponse resp2 = history.get(idx2).originalResponse();

        String body1 = resp1 != null ? resp1.bodyToString() : "";
        String body2 = resp2 != null ? resp2.bodyToString() : "";

        // Simple line-by-line diff
        String[] lines1 = body1.split("\n");
        String[] lines2 = body2.split("\n");

        List<String> diffs = new ArrayList<>();
        int maxLines = Math.max(lines1.length, lines2.length);
        for (int i = 0; i < maxLines && diffs.size() < 200; i++) {
            String l1 = i < lines1.length ? lines1[i] : "";
            String l2 = i < lines2.length ? lines2[i] : "";
            if (!l1.equals(l2)) {
                diffs.add("Line " + (i + 1) + ":");
                diffs.add("  - " + truncateLine(l1, 200));
                diffs.add("  + " + truncateLine(l2, 200));
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("index1", idx1);
        result.put("index2", idx2);
        result.put("status1", resp1 != null ? resp1.statusCode() : 0);
        result.put("status2", resp2 != null ? resp2.statusCode() : 0);
        result.put("length1", body1.length());
        result.put("length2", body2.length());
        result.put("diff_lines", diffs);
        result.put("total_differences", diffs.size() / 3);

        sendJson(exchange, JsonUtil.toJson(result));
    }

    /**
     * Enhanced comparison of two proxy history responses.
     * Body: {"index1":42, "index2":43, "mode":"full|headers|body"}
     */
    private void handleCompare(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        int idx1 = body.get("index1") instanceof Number n ? n.intValue() : -1;
        int idx2 = body.get("index2") instanceof Number n ? n.intValue() : -1;
        String mode = (String) body.getOrDefault("mode", "full");

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (idx1 < 0 || idx1 >= history.size() || idx2 < 0 || idx2 >= history.size()) {
            sendError(exchange, 400, "Invalid index values");
            return;
        }

        HttpResponse resp1 = history.get(idx1).originalResponse();
        HttpResponse resp2 = history.get(idx2).originalResponse();

        Map<String, Object> result = new LinkedHashMap<>();

        // Status diff
        int status1 = resp1 != null ? resp1.statusCode() : 0;
        int status2 = resp2 != null ? resp2.statusCode() : 0;
        Map<String, Object> statusDiff = new LinkedHashMap<>();
        statusDiff.put("item1", status1);
        statusDiff.put("item2", status2);
        result.put("status_diff", statusDiff);

        String body1 = resp1 != null ? resp1.bodyToString() : "";
        String body2 = resp2 != null ? resp2.bodyToString() : "";

        // Length diff
        Map<String, Object> lengthDiff = new LinkedHashMap<>();
        lengthDiff.put("item1", body1.length());
        lengthDiff.put("item2", body2.length());
        result.put("length_diff", lengthDiff);

        // Header diffs
        if ("full".equals(mode) || "headers".equals(mode)) {
            result.put("header_diffs", computeHeaderDiffs(resp1, resp2));
        }

        // Body diff
        if ("full".equals(mode) || "body".equals(mode)) {
            result.put("body_diff", computeBodyDiff(body1, body2));
        }

        // Word counts
        Map<String, Object> wordCount = new LinkedHashMap<>();
        wordCount.put("item1", countWords(body1));
        wordCount.put("item2", countWords(body2));
        result.put("word_count", wordCount);

        // Unique words per item
        Set<String> words1 = extractWords(body1);
        Set<String> words2 = extractWords(body2);

        Set<String> uniqueTo1 = new LinkedHashSet<>(words1);
        uniqueTo1.removeAll(words2);
        Set<String> uniqueTo2 = new LinkedHashSet<>(words2);
        uniqueTo2.removeAll(words1);

        // Limit unique words to top 50
        result.put("unique_to_item1", limitSet(uniqueTo1, 50));
        result.put("unique_to_item2", limitSet(uniqueTo2, 50));

        sendJson(exchange, JsonUtil.toJson(result));
    }

    /**
     * Send two proxy history items to Burp's Comparer tab.
     * Body: {"index1":42, "index2":43}
     */
    private void handleSendToComparer(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        int idx1 = body.get("index1") instanceof Number n ? n.intValue() : -1;
        int idx2 = body.get("index2") instanceof Number n ? n.intValue() : -1;

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (idx1 < 0 || idx1 >= history.size() || idx2 < 0 || idx2 >= history.size()) {
            sendError(exchange, 400, "Invalid index values");
            return;
        }

        HttpResponse resp1 = history.get(idx1).originalResponse();
        HttpResponse resp2 = history.get(idx2).originalResponse();

        if (resp1 == null || resp2 == null) {
            sendError(exchange, 400, "One or both responses are null");
            return;
        }

        ByteArray data1 = resp1.toByteArray();
        ByteArray data2 = resp2.toByteArray();

        api.comparer().sendToComparer(data1, data2);
        sendOk(exchange, "Sent items " + idx1 + " and " + idx2 + " to Comparer");
    }

    // ── Compare helpers ───────────────────────────────────────

    private List<Map<String, Object>> computeHeaderDiffs(HttpResponse resp1, HttpResponse resp2) {
        List<Map<String, Object>> diffs = new ArrayList<>();

        Map<String, String> headers1 = new LinkedHashMap<>();
        Map<String, String> headers2 = new LinkedHashMap<>();

        if (resp1 != null) {
            for (HttpHeader h : resp1.headers()) {
                headers1.put(h.name().toLowerCase(), h.value());
            }
        }
        if (resp2 != null) {
            for (HttpHeader h : resp2.headers()) {
                headers2.put(h.name().toLowerCase(), h.value());
            }
        }

        // All header names from both
        Set<String> allNames = new LinkedHashSet<>();
        allNames.addAll(headers1.keySet());
        allNames.addAll(headers2.keySet());

        for (String name : allNames) {
            String val1 = headers1.get(name);
            String val2 = headers2.get(name);
            if (!Objects.equals(val1, val2)) {
                Map<String, Object> diff = new LinkedHashMap<>();
                diff.put("name", name);
                diff.put("item1", val1 != null ? val1 : "");
                diff.put("item2", val2 != null ? val2 : "");
                diffs.add(diff);
            }
        }
        return diffs;
    }

    private Map<String, Object> computeBodyDiff(String body1, String body2) {
        Map<String, Object> diff = new LinkedHashMap<>();

        diff.put("identical", body1.equals(body2));

        // Similarity percentage (simple character-level Jaccard-like)
        if (body1.isEmpty() && body2.isEmpty()) {
            diff.put("similarity_pct", 100.0);
        } else {
            diff.put("similarity_pct", computeSimilarity(body1, body2));
        }

        // Line-by-line diff
        String[] lines1 = body1.split("\n", -1);
        String[] lines2 = body2.split("\n", -1);

        List<String> diffLines = new ArrayList<>();
        int added = 0;
        int removed = 0;
        int maxLines = Math.max(lines1.length, lines2.length);

        for (int i = 0; i < maxLines && diffLines.size() < 200; i++) {
            String l1 = i < lines1.length ? lines1[i] : null;
            String l2 = i < lines2.length ? lines2[i] : null;

            if (l1 != null && l2 != null && l1.equals(l2)) continue;

            if (l1 != null && (l2 == null || !l1.equals(l2))) {
                diffLines.add("- " + truncateLine(l1, 200));
                removed++;
            }
            if (l2 != null && (l1 == null || !l1.equals(l2))) {
                diffLines.add("+ " + truncateLine(l2, 200));
                added++;
            }
        }

        diff.put("added_lines", added);
        diff.put("removed_lines", removed);
        diff.put("diff_lines", diffLines);

        return diff;
    }

    private double computeSimilarity(String s1, String s2) {
        // Use line-level similarity for efficiency
        Set<String> set1 = new HashSet<>(Arrays.asList(s1.split("\n")));
        Set<String> set2 = new HashSet<>(Arrays.asList(s2.split("\n")));

        Set<String> intersection = new HashSet<>(set1);
        intersection.retainAll(set2);

        Set<String> union = new HashSet<>(set1);
        union.addAll(set2);

        if (union.isEmpty()) return 100.0;
        double similarity = (double) intersection.size() / union.size() * 100.0;
        return Math.round(similarity * 10.0) / 10.0;
    }

    private int countWords(String text) {
        if (text == null || text.isBlank()) return 0;
        return text.split("\\s+").length;
    }

    private Set<String> extractWords(String text) {
        if (text == null || text.isBlank()) return Collections.emptySet();
        Set<String> words = new LinkedHashSet<>();
        for (String word : text.split("\\s+")) {
            String cleaned = word.toLowerCase().replaceAll("[^a-z0-9]", "");
            if (cleaned.length() >= 3) {
                words.add(cleaned);
            }
        }
        return words;
    }

    private List<String> limitSet(Set<String> set, int max) {
        List<String> list = new ArrayList<>();
        int count = 0;
        for (String s : set) {
            if (count >= max) break;
            list.add(s);
            count++;
        }
        return list;
    }

    private String truncateLine(String line, int max) {
        if (line.length() <= max) return line;
        return line.substring(0, max) + "...";
    }
}
