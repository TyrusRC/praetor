package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.Cookie;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * GET /api/cookies?domain=example.com  - get cookies from Burp's cookie jar
 */
public class CookieHandler extends BaseHandler {

    private final MontoyaApi api;

    public CookieHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        Map<String, String> params = queryParams(exchange);
        String filterDomain = params.getOrDefault("domain", "");

        List<Cookie> cookies = api.http().cookieJar().cookies();
        List<Map<String, Object>> items = new ArrayList<>();

        for (Cookie cookie : cookies) {
            String domain = cookie.domain();

            if (!filterDomain.isEmpty() && !domain.toLowerCase().contains(filterDomain.toLowerCase())) {
                continue;
            }

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", cookie.name());
            entry.put("value", cookie.value());
            entry.put("domain", domain);
            entry.put("path", cookie.path());

            var expiration = cookie.expiration();
            entry.put("expiration", expiration != null ? expiration.toString() : null);

            items.add(entry);
        }

        sendJson(exchange, JsonUtil.object(
            "total", items.size(),
            "filter_domain", filterDomain,
            "cookies", items
        ));
    }
}
