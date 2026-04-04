package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * GET /api/websocket/history?limit=50  - get WebSocket message history from proxy
 */
public class WebSocketHandler extends BaseHandler {

    private final MontoyaApi api;

    public WebSocketHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        Map<String, String> params = queryParams(exchange);
        int limit = intParam(params, "limit", 50);

        try {
            List<ProxyWebSocketMessage> messages = api.proxy().webSocketHistory();
            List<Map<String, Object>> items = new ArrayList<>();
            int count = 0;

            // Iterate newest first
            for (int i = messages.size() - 1; i >= 0 && count < limit; i--) {
                ProxyWebSocketMessage msg = messages.get(i);
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("index", i);
                entry.put("direction", msg.direction().toString());

                String payload = msg.payload().toString();
                if (payload.length() > 5000) {
                    payload = payload.substring(0, 5000) + "... (truncated)";
                }
                entry.put("payload", payload);
                entry.put("length", msg.payload().length());
                entry.put("time", msg.time().toString());

                // Include the upgrade request URL for context
                try {
                    entry.put("upgrade_url", msg.upgradeRequest().url());
                } catch (Exception ignored) {}

                items.add(entry);
                count++;
            }

            sendJson(exchange, JsonUtil.object(
                "total", messages.size(),
                "returned", items.size(),
                "messages", items
            ));
        } catch (Exception e) {
            sendError(exchange, 500,
                "WebSocket history not available: " + e.getMessage());
        }
    }
}
