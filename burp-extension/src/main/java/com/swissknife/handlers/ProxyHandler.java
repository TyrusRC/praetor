package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * GET /api/proxy/history?limit=50&offset=0&filter_url=&filter_method=&filter_status=
 * GET /api/proxy/history/{index}
 */
public class ProxyHandler extends BaseHandler {

    private final MontoyaApi api;

    public ProxyHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();

        if (path.matches("/api/proxy/history/\\d+")) {
            handleDetail(exchange, path);
        } else if (path.equals("/api/proxy/history")) {
            handleList(exchange);
        } else if (path.equals("/api/proxy/count")) {
            handleCount(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    /**
     * Sub-millisecond count-only check. Lets callers ask "is there any
     * history yet / how big?" without paying for any iteration or
     * serialization of entries.
     */
    private void handleCount(HttpExchange exchange) throws Exception {
        int size = api.proxy().history().size();
        sendJson(exchange, JsonUtil.object("count", size));
    }

    private void handleList(HttpExchange exchange) throws Exception {
        Map<String, String> params = queryParams(exchange);
        int limit = intParam(params, "limit", 50);
        int offset = intParam(params, "offset", 0);
        // since_index lets callers tail history incrementally without
        // re-fetching the prefix. -1 = no lower bound (default behaviour).
        int sinceIndex = intParam(params, "since_index", -1);
        // host (exact match) is faster than filter_url for the common
        // "filter by domain" query — URL.host() is cached in Montoya, no
        // toLowerCase / contains on the full URL.
        String hostFilter = params.getOrDefault("host", "").toLowerCase();
        String filterUrl = params.getOrDefault("filter_url", "");
        String filterMethod = params.getOrDefault("filter_method", "");
        String filterStatus = params.getOrDefault("filter_status", "");

        // Pre-compute lowercased filterUrl once (was being recomputed every
        // iteration in the original code).
        String filterUrlLower = filterUrl.toLowerCase();

        // Optional: parse filterStatus once.
        int filterStatusInt = -1;
        if (!filterStatus.isEmpty()) {
            try { filterStatusInt = Integer.parseInt(filterStatus); }
            catch (NumberFormatException nfe) { filterStatusInt = -2; }
        }

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        int totalSize = history.size();
        List<Map<String, Object>> items = new ArrayList<>();
        int count = 0;
        int skipped = 0;

        for (int i = totalSize - 1; i >= 0 && count < limit; i--) {
            // since_index lower bound — short-circuits cleanly when caller
            // tails (e.g. since_index=N-1 returns only the newest entry).
            if (i <= sinceIndex) break;

            ProxyHttpRequestResponse item = history.get(i);
            HttpRequest req = item.finalRequest();
            HttpResponse resp = item.originalResponse();

            String url = req.url();
            String method = req.method();
            int statusCode = resp != null ? resp.statusCode() : 0;

            // Apply filters
            if (!hostFilter.isEmpty()) {
                // Montoya's HttpRequest.httpService().host() is the parsed
                // host; cheap exact compare beats substring on full URL.
                String h = "";
                try { h = req.httpService().host().toLowerCase(); }
                catch (Exception ignored) {}
                if (!h.equals(hostFilter)) continue;
            }
            if (!filterUrl.isEmpty() && !url.toLowerCase().contains(filterUrlLower)) continue;
            if (!filterMethod.isEmpty() && !method.equalsIgnoreCase(filterMethod)) continue;
            if (filterStatusInt == -2) continue;  // malformed status filter -> match nothing
            if (filterStatusInt >= 0 && statusCode != filterStatusInt) continue;

            if (skipped < offset) { skipped++; continue; }

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("index", i);
            entry.put("method", method);
            entry.put("url", url);
            entry.put("status_code", statusCode);
            entry.put("response_length", resp != null ? resp.body().length() : 0);
            entry.put("mime_type", resp != null ? resp.statedMimeType().toString() : "");
            items.add(entry);
            count++;
        }

        sendJson(exchange, JsonUtil.object(
            "total", totalSize,
            "offset", offset,
            "limit", limit,
            "since_index", sinceIndex,
            "returned", items.size(),
            "items", items
        ));
    }

    private void handleDetail(HttpExchange exchange, String path) throws Exception {
        int index;
        try {
            index = Integer.parseInt(path.substring(path.lastIndexOf('/') + 1));
        } catch (NumberFormatException nfe) {
            sendError(exchange, 400, "Invalid index: must be integer");
            return;
        }
        List<ProxyHttpRequestResponse> history = api.proxy().history();

        if (index < 0 || index >= history.size()) {
            sendError(exchange, 404, "Index out of range");
            return;
        }

        ProxyHttpRequestResponse item = history.get(index);
        HttpRequest req = item.finalRequest();
        HttpResponse resp = item.originalResponse();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("index", index);
        result.put("method", req.method());
        result.put("url", req.url());
        result.put("request_headers", headersToList(req.headers()));
        result.put("request_body", req.bodyToString());

        if (resp != null) {
            result.put("status_code", resp.statusCode());
            result.put("response_headers", headersToList(resp.headers()));
            String body = resp.bodyToString();
            int fullLength = body.length();
            boolean truncated = fullLength > 50000;
            if (truncated) {
                body = body.substring(0, 25000) + "\n\n[... TRUNCATED " + (fullLength - 50000) + " chars ...]\n\n" + body.substring(fullLength - 25000);
            }
            result.put("response_body", body);
            result.put("response_length", resp.body().length());
            result.put("body_truncated", truncated);
            result.put("body_size_full", fullLength);
            result.put("mime_type", resp.statedMimeType().toString());
        }

        sendJson(exchange, JsonUtil.toJson(result));
    }

    private List<Map<String, Object>> headersToList(List<HttpHeader> headers) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (HttpHeader h : headers) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", h.name());
            m.put("value", h.value());
            list.add(m);
        }
        return list;
    }
}
