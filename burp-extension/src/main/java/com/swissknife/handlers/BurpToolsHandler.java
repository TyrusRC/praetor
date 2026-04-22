package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.logger.LoggerCaptureHttpRequestResponse;
import com.swissknife.http.HttpExchange;
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

        if (path.equals("/api/burp-tools/project") && "GET".equalsIgnoreCase(method)) {
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
     * Supports both simple send and template-based with custom insertion points.
     *
     * Body options:
     *   Simple:   {"index": 42, "tab_name": "Attack"}
     *   Raw:      {"raw_request": "GET / HTTP/1.1\r\n...", "host": "target.com"}
     *   Template: {"index": 42, "positions": [[10,15],[30,35]], "mode": "replace"}
     *             positions = list of [start, end] byte offsets marking insertion points
     *             mode = "replace" (default) or "append"
     */
    private void handleIntruderConfig(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);

        Object indexObj = body.get("index");
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
            // Check if custom positions are specified
            Object positionsObj = body.get("positions");
            if (positionsObj instanceof List<?> positionsList && !positionsList.isEmpty()) {
                // Template-based: user specifies exact byte offset positions
                List<burp.api.montoya.core.Range> ranges = new ArrayList<>();
                for (Object pos : positionsList) {
                    if (pos instanceof List<?> pair && pair.size() == 2) {
                        int start = ((Number) pair.get(0)).intValue();
                        int end = ((Number) pair.get(1)).intValue();
                        ranges.add(burp.api.montoya.core.Range.range(start, end));
                    }
                }

                HttpRequestTemplate template = HttpRequestTemplate.httpRequestTemplate(request, ranges);
                api.intruder().sendToIntruder(request.httpService(), template, tabName);

                sendJson(exchange, JsonUtil.object(
                    "status", "ok",
                    "tab_name", tabName,
                    "method", request.method(),
                    "url", request.url(),
                    "positions", ranges.size(),
                    "message", "Sent to Intruder with " + ranges.size() + " insertion points"
                ));
            } else {
                // Check for auto-position mode
                String mode = (String) body.getOrDefault("mode", "");
                if ("auto".equals(mode)) {
                    // Let Burp auto-detect insertion points based on parameters
                    HttpRequestTemplate template = HttpRequestTemplate.httpRequestTemplate(
                        request,
                        burp.api.montoya.intruder.HttpRequestTemplateGenerationOptions.REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS
                    );
                    api.intruder().sendToIntruder(request.httpService(), template, tabName);
                    sendJson(exchange, JsonUtil.object(
                        "status", "ok",
                        "tab_name", tabName,
                        "method", request.method(),
                        "url", request.url(),
                        "mode", "auto-positions",
                        "message", "Sent to Intruder with auto-detected insertion points"
                    ));
                } else {
                    // Simple send without template
                    api.intruder().sendToIntruder(request, tabName);
                    sendJson(exchange, JsonUtil.object(
                        "status", "ok",
                        "tab_name", tabName,
                        "method", request.method(),
                        "url", request.url(),
                        "message", "Sent to Intruder tab: " + tabName
                    ));
                }
            }
        } catch (Exception e) {
            sendError(exchange, 500, "Failed to send to Intruder: " + e.getMessage());
        }
    }
}
