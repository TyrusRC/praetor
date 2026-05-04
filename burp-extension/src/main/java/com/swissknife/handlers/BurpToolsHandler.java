package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.HttpRequestTemplate;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * Miscellaneous Burp tool integrations — project info, intruder templates.
 *
 * GET  /api/burp-tools/project          — get project name and ID
 * POST /api/burp-tools/intruder-config  — send to Intruder with template positions
 *
 * The legacy /logger endpoint was removed: it was billed as Logger access but
 * actually read api.proxy().history() (no Logger-only timing data), and the
 * corresponding get_logger_entries Python tool was dropped in v0.5.
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

    // /api/burp-tools/logger removed — see class header for rationale.

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
