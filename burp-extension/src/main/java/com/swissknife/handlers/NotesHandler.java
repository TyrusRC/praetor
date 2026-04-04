package com.swissknife.handlers;

import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.store.FindingsStore;
import com.swissknife.util.JsonUtil;

import java.util.Map;

/**
 * POST /api/notes/findings           - save a finding
 * GET  /api/notes/findings?endpoint= - get findings
 * GET  /api/notes/export?format=     - export report (markdown or json)
 */
public class NotesHandler extends BaseHandler {

    private final FindingsStore store;

    public NotesHandler(FindingsStore store) {
        this.store = store;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if (path.equals("/api/notes/findings") && "POST".equalsIgnoreCase(method)) {
            handleSave(exchange);
        } else if (path.equals("/api/notes/findings") && "GET".equalsIgnoreCase(method)) {
            handleGet(exchange);
        } else if (path.equals("/api/notes/export") && "GET".equalsIgnoreCase(method)) {
            handleExport(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    private void handleSave(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String title = (String) body.get("title");
        if (title == null || title.isEmpty()) {
            sendError(exchange, 400, "Missing 'title'");
            return;
        }

        var finding = store.add(
            title,
            (String) body.getOrDefault("description", ""),
            (String) body.get("severity"),
            (String) body.get("endpoint"),
            (String) body.get("evidence")
        );

        sendJson(exchange, JsonUtil.toJson(finding));
    }

    private void handleGet(HttpExchange exchange) throws Exception {
        String endpoint = queryParams(exchange).get("endpoint");
        var findings = store.getAll(endpoint);
        sendJson(exchange, JsonUtil.object("total", findings.size(), "findings", findings));
    }

    private void handleExport(HttpExchange exchange) throws Exception {
        String format = queryParams(exchange).getOrDefault("format", "markdown");
        if ("json".equalsIgnoreCase(format)) {
            sendJson(exchange, store.exportJson());
        } else {
            // Return markdown as JSON-wrapped string
            sendJson(exchange, JsonUtil.object("format", "markdown", "content", store.exportMarkdown()));
        }
    }
}
