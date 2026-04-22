package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.sitemap.SiteMapFilter;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * GET /api/sitemap?prefix=https://example.com&limit=200
 */
public class SitemapHandler extends BaseHandler {

    private final MontoyaApi api;

    public SitemapHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        Map<String, String> params = queryParams(exchange);
        String prefix = params.getOrDefault("prefix", "");
        int limit = intParam(params, "limit", 200);

        var siteMapItems = prefix.isEmpty()
            ? api.siteMap().requestResponses()
            : api.siteMap().requestResponses(SiteMapFilter.prefixFilter(prefix));

        List<Map<String, Object>> items = new ArrayList<>();
        int count = 0;

        for (var item : siteMapItems) {
            if (count >= limit) break;

            HttpRequest req = item.request();
            HttpResponse resp = item.response();

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("method", req.method());
            entry.put("url", req.url());
            entry.put("has_response", resp != null);
            if (resp != null) {
                entry.put("status_code", resp.statusCode());
                entry.put("response_length", resp.body().length());
                entry.put("mime_type", resp.statedMimeType().toString());
            }
            items.add(entry);
            count++;
        }

        sendJson(exchange, JsonUtil.object(
            "total_returned", items.size(),
            "prefix", prefix,
            "items", items
        ));
    }
}
