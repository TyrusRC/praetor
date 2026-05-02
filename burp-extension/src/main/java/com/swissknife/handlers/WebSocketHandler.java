package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * GET /api/websocket/history
 *
 * Query params:
 *   limit          - max items to return (default 50)
 *   offset         - skip first N matches (default 0)
 *   direction      - 'client' / 'server' (case-insensitive substring of direction enum)
 *   filter_payload - case-insensitive substring of message payload
 *   filter_url     - case-insensitive substring of upgrade-request URL
 *   since_index    - only include messages with index > this value
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
        int offset = intParam(params, "offset", 0);
        int sinceIndex = intParam(params, "since_index", -1);
        String direction = params.getOrDefault("direction", "").toLowerCase();
        String payloadFilter = params.getOrDefault("filter_payload", "").toLowerCase();
        String urlFilter = params.getOrDefault("filter_url", "").toLowerCase();

        try {
            List<ProxyWebSocketMessage> messages = api.proxy().webSocketHistory();
            List<Map<String, Object>> items = new ArrayList<>();
            int matched = 0;
            int skipped = 0;

            // Iterate newest first
            for (int i = messages.size() - 1; i >= 0 && items.size() < limit; i--) {
                if (i <= sinceIndex) break;

                ProxyWebSocketMessage msg = messages.get(i);
                String dir = msg.direction().toString();
                String payload = msg.payload().toString();
                String url = "";
                try {
                    url = msg.upgradeRequest().url();
                } catch (Exception ignored) {}

                if (!direction.isEmpty() && !dir.toLowerCase().contains(direction)) continue;
                if (!payloadFilter.isEmpty() && !payload.toLowerCase().contains(payloadFilter)) continue;
                if (!urlFilter.isEmpty() && !url.toLowerCase().contains(urlFilter)) continue;

                matched++;
                if (skipped < offset) { skipped++; continue; }

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("index", i);
                entry.put("direction", dir);

                int rawLen = msg.payload().length();
                // Detect non-text payloads (binary/CBOR/MessagePack/Protobuf):
                // if the byte stream contains NUL or a high ratio of non-printable
                // bytes, surface a base64 snippet so Claude can analyze without
                // mojibake.
                byte[] bytes = msg.payload().getBytes();
                boolean isBinary = false;
                int nonPrintable = 0;
                int sample = Math.min(bytes.length, 256);
                for (int b = 0; b < sample; b++) {
                    int v = bytes[b] & 0xFF;
                    if (v == 0) { isBinary = true; break; }
                    if (v < 9 || (v > 13 && v < 32) || v == 127) nonPrintable++;
                }
                if (!isBinary && sample > 0 && nonPrintable * 4 > sample) {
                    isBinary = true;
                }
                if (isBinary) {
                    int snipLen = Math.min(bytes.length, 256);
                    byte[] snip = new byte[snipLen];
                    System.arraycopy(bytes, 0, snip, 0, snipLen);
                    entry.put("binary", true);
                    entry.put("payload_b64", java.util.Base64.getEncoder().encodeToString(snip));
                    entry.put("payload", "[binary, " + rawLen + " bytes — see payload_b64]");
                } else {
                    if (payload.length() > 5000) {
                        payload = payload.substring(0, 5000) + "... (truncated)";
                    }
                    entry.put("payload", payload);
                }
                entry.put("length", rawLen);
                entry.put("time", msg.time().toString());
                if (!url.isEmpty()) entry.put("url", url);

                items.add(entry);
            }

            sendJson(exchange, JsonUtil.object(
                "total", messages.size(),
                "matched", matched,
                "returned", items.size(),
                "messages", items
            ));
        } catch (Exception e) {
            sendError(exchange, 500,
                "WebSocket history not available: " + e.getMessage());
        }
    }
}
