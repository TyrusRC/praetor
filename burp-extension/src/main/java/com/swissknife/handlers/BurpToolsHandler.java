package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.logger.LoggerCaptureHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * Miscellaneous Burp tool integrations — decoder, project info, logger, intruder templates.
 *
 * POST /api/burp-tools/decoder          — send data to Burp's Decoder tab
 * GET  /api/burp-tools/project          — get project name and ID
 * GET  /api/burp-tools/logger?limit=50  — get Logger tab entries with timing data
 * POST /api/burp-tools/intruder-config  — send to Intruder with template positions
 */
public class BurpToolsHandler extends BaseHandler {

    private final MontoyaApi api;

    public BurpToolsHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if (path.equals("/api/burp-tools/decoder") && "POST".equalsIgnoreCase(method)) {
            handleDecoder(exchange);
        } else if (path.equals("/api/burp-tools/project") && "GET".equalsIgnoreCase(method)) {
            handleProject(exchange);
        } else if (path.equals("/api/burp-tools/logger") && "GET".equalsIgnoreCase(method)) {
            handleLogger(exchange);
        } else if (path.equals("/api/burp-tools/intruder-config") && "POST".equalsIgnoreCase(method)) {
            handleIntruderConfig(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    /**
     * Send data to Burp's Decoder tab for manual analysis.
     */
    private void handleDecoder(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String data = (String) body.get("data");

        if (data == null || data.isEmpty()) {
            sendError(exchange, 400, "Missing 'data' field");
            return;
        }

        try {
            api.decoder().sendToDecoder(ByteArray.byteArray(data));
            sendOk(exchange, "Sent " + data.length() + " chars to Decoder tab");
        } catch (Exception e) {
            sendError(exchange, 500, "Failed to send to Decoder: " + e.getMessage());
        }
    }

    /**
     * Get current project info.
     */
    private void handleProject(HttpExchange exchange) throws Exception {
        try {
            String name = api.project().name();
            String id = api.project().id();
            sendJson(exchange, JsonUtil.object(
                "project_name", name != null ? name : "unknown",
                "project_id", id != null ? id : "unknown",
                "burp_version", api.burpSuite().version().toString(),
                "edition", api.burpSuite().version().edition().toString()
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "Failed to get project info: " + e.getMessage());
        }
    }

    /**
     * Get Logger tab entries with timing data and metadata.
     */
    private void handleLogger(HttpExchange exchange) throws Exception {
        Map<String, String> params = queryParams(exchange);
        int limit = intParam(params, "limit", 50);
        String filterUrl = params.getOrDefault("filter_url", "");

        try {
            // Access logger capture history
            // Note: Logger API may not be available in all Burp versions
            List<Map<String, Object>> items = new ArrayList<>();

            // Fall back to proxy history with timing if logger not available
            var history = api.proxy().history();
            int count = 0;

            for (int i = history.size() - 1; i >= 0 && count < limit; i--) {
                var item = history.get(i);
                var req = item.finalRequest();
                var resp = item.originalResponse();

                String url = req.url();
                if (!filterUrl.isEmpty() && !url.toLowerCase().contains(filterUrl.toLowerCase())) continue;

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("index", i);
                entry.put("method", req.method());
                entry.put("url", url);
                entry.put("status_code", resp != null ? resp.statusCode() : 0);
                entry.put("response_length", resp != null ? resp.body().length() : 0);
                entry.put("mime_type", resp != null ? resp.statedMimeType().toString() : "");

                // Annotations
                String notes = item.annotations().notes();
                if (notes != null && !notes.isEmpty()) {
                    entry.put("notes", notes);
                }
                var color = item.annotations().highlightColor();
                if (color != null) {
                    entry.put("color", color.name());
                }

                // Timing data
                try {
                    entry.put("time", item.time().toString());
                } catch (Exception ignored) {}

                items.add(entry);
                count++;
            }

            sendJson(exchange, JsonUtil.object(
                "total", history.size(),
                "returned", items.size(),
                "items", items
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "Logger access failed: " + e.getMessage());
        }
    }

    /**
     * Send to Intruder with configured insertion point positions.
     */
    private void handleIntruderConfig(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);

        // Option 1: From proxy history index
        Object indexObj = body.get("index");
        // Option 2: From raw request
        String rawRequest = (String) body.get("raw_request");
        String host = (String) body.get("host");
        String tabName = (String) body.getOrDefault("tab_name", "MCP Attack");

        HttpRequest request;

        if (indexObj instanceof Number n) {
            int index = n.intValue();
            var history = api.proxy().history();
            if (index < 0 || index >= history.size()) {
                sendError(exchange, 404, "Index out of range");
                return;
            }
            request = history.get(index).finalRequest();
        } else if (rawRequest != null && host != null) {
            HttpService service = HttpService.httpService(host);
            request = HttpRequest.httpRequest(service, rawRequest);
        } else {
            sendError(exchange, 400, "Provide 'index' or 'raw_request' + 'host'");
            return;
        }

        try {
            api.intruder().sendToIntruder(request, tabName);
            sendJson(exchange, JsonUtil.object(
                "status", "ok",
                "tab_name", tabName,
                "method", request.method(),
                "url", request.url(),
                "message", "Sent to Intruder tab: " + tabName
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "Failed to send to Intruder: " + e.getMessage());
        }
    }
}
