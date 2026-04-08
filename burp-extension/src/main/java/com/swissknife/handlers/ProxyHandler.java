package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
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
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    private void handleList(HttpExchange exchange) throws Exception {
        Map<String, String> params = queryParams(exchange);
        int limit = intParam(params, "limit", 50);
        int offset = intParam(params, "offset", 0);
        String filterUrl = params.getOrDefault("filter_url", "");
        String filterMethod = params.getOrDefault("filter_method", "");
        String filterStatus = params.getOrDefault("filter_status", "");

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        List<Map<String, Object>> items = new ArrayList<>();
        int count = 0;
        int skipped = 0;

        for (int i = history.size() - 1; i >= 0 && count < limit; i--) {
            ProxyHttpRequestResponse item = history.get(i);
            HttpRequest req = item.finalRequest();
            HttpResponse resp = item.originalResponse();

            String url = req.url();
            String method = req.method();
            int statusCode = resp != null ? resp.statusCode() : 0;

            // Apply filters
            if (!filterUrl.isEmpty() && !url.toLowerCase().contains(filterUrl.toLowerCase())) continue;
            if (!filterMethod.isEmpty() && !method.equalsIgnoreCase(filterMethod)) continue;
            if (!filterStatus.isEmpty()) {
                try {
                    if (statusCode != Integer.parseInt(filterStatus)) continue;
                } catch (NumberFormatException ignored) { continue; }
            }

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
            "total", history.size(),
            "offset", offset,
            "limit", limit,
            "items", items
        ));
    }

    private void handleDetail(HttpExchange exchange, String path) throws Exception {
        int index = Integer.parseInt(path.substring(path.lastIndexOf('/') + 1));
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
            // Truncate large response bodies
            if (body.length() > 50000) {
                body = body.substring(0, 25000) + "\n\n[... TRUNCATED " + (body.length() - 50000) + " chars ...]\n\n" + body.substring(body.length() - 25000);
            }
            result.put("response_body", body);
            result.put("response_length", resp.body().length());
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
