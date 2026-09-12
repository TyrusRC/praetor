package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.util.JsonUtil;

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
        // since_index lets callers tail without re-scanning the prefix —
        // matches the get_proxy_history shape.
        int sinceIndex = body.get("since_index") instanceof Number n ? n.intValue() : -1;

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        List<Map<String, Object>> results = new ArrayList<>();
        String queryLower = query.toLowerCase();
        // ByteArray search avoids bodyToString() materialization. Montoya's
        // ByteArray.indexOf is in-place over the underlying byte buffer with
        // a case-insensitive flag — dramatically cheaper than allocating a
        // full String per response on a 50K-entry history. Only build the
        // search needle when body search is requested.
        ByteArray needleCi = (!query.isEmpty() && (inRequestBody || inResponseBody))
            ? ByteArray.byteArray(query)
            : null;

        for (int i = history.size() - 1; i >= 0 && results.size() < limit; i--) {
            if (i <= sinceIndex) break;

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
                // URL — already a String, cheap.
                if (inUrl && req.url().toLowerCase().contains(queryLower)) found = true;
                // Body searches — use ByteArray.indexOf for in-place search
                // (case-insensitive) instead of materializing full bodies.
                if (!found && inRequestBody && needleCi != null) {
                    if (req.body().indexOf(needleCi, false, 0, req.body().length()) >= 0) {
                        found = true;
                    }
                }
                if (!found && inResponseBody && resp != null && needleCi != null) {
                    if (resp.body().indexOf(needleCi, false, 0, resp.body().length()) >= 0) {
                        found = true;
                    }
                }
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
        int differenceCount = 0;
        int maxLines = Math.max(lines1.length, lines2.length);
        for (int i = 0; i < maxLines && diffs.size() + 3 <= 200; i++) {
            String l1 = i < lines1.length ? lines1[i] : "";
            String l2 = i < lines2.length ? lines2[i] : "";
            if (!l1.equals(l2)) {
                diffs.add("Line " + (i + 1) + ":");
                diffs.add("  - " + ResponseDiffComputer.truncateLine(l1, 200));
                diffs.add("  + " + ResponseDiffComputer.truncateLine(l2, 200));
                differenceCount++;
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
        result.put("total_differences", differenceCount);

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
            result.put("header_diffs", ResponseDiffComputer.computeHeaderDiffs(resp1, resp2));
        }

        // Body diff
        if ("full".equals(mode) || "body".equals(mode)) {
            result.put("body_diff", ResponseDiffComputer.computeBodyDiff(body1, body2));
        }

        // Word counts
        Map<String, Object> wordCount = new LinkedHashMap<>();
        wordCount.put("item1", ResponseDiffComputer.countWords(body1));
        wordCount.put("item2", ResponseDiffComputer.countWords(body2));
        result.put("word_count", wordCount);

        // Unique words per item
        Set<String> words1 = ResponseDiffComputer.extractWords(body1);
        Set<String> words2 = ResponseDiffComputer.extractWords(body2);

        Set<String> uniqueTo1 = new LinkedHashSet<>(words1);
        uniqueTo1.removeAll(words2);
        Set<String> uniqueTo2 = new LinkedHashSet<>(words2);
        uniqueTo2.removeAll(words1);

        // Limit unique words to top 50
        result.put("unique_to_item1", ResponseDiffComputer.limitSet(uniqueTo1, 50));
        result.put("unique_to_item2", ResponseDiffComputer.limitSet(uniqueTo2, 50));

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

}
