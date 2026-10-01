package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.TaskExecutionEngine;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.util.JsonUtil;

import java.util.Map;

/**
 * Burp-level configuration + task-engine control via the Montoya BurpSuite API.
 *
 * Parity with the official PortSwigger MCP server's option/task-engine tools:
 *   GET  /api/burp-control/options?level=project|user   — export options as JSON
 *   POST /api/burp-control/options   {level, json}       — import options from JSON
 *   GET  /api/burp-control/task-engine                   — {state: RUNNING|PAUSED}
 *   POST /api/burp-control/task-engine  {state}          — set RUNNING|PAUSED
 *
 * Distinct context from /api/burp-tools (longest-prefix routing keeps them separate).
 */
public class BurpControlHandler extends BaseHandler {

    private final MontoyaApi api;

    public BurpControlHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if (path.equals("/api/burp-control/options")) {
            if ("GET".equalsIgnoreCase(method)) { getOptions(exchange); return; }
            if ("POST".equalsIgnoreCase(method)) { setOptions(exchange); return; }
        } else if (path.equals("/api/burp-control/task-engine")) {
            if ("GET".equalsIgnoreCase(method)) { getTaskEngine(exchange); return; }
            if ("POST".equalsIgnoreCase(method)) { setTaskEngine(exchange); return; }
        }
        sendError(exchange, 404, "Not found");
    }

    private void getOptions(HttpExchange exchange) throws Exception {
        String level = queryParams(exchange).getOrDefault("level", "project").toLowerCase();
        String json;
        try {
            json = "user".equals(level)
                ? api.burpSuite().exportUserOptionsAsJson()
                : api.burpSuite().exportProjectOptionsAsJson();
        } catch (Exception e) {
            sendError(exchange, 500, "export failed: " + e.getMessage());
            return;
        }
        sendJson(exchange, JsonUtil.object("level", level, "json", json));
    }

    private void setOptions(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String level = String.valueOf(body.getOrDefault("level", "project")).toLowerCase();
        Object jsonObj = body.get("json");
        if (!(jsonObj instanceof String json) || json.isEmpty()) {
            sendError(exchange, 400, "Missing 'json' (a string of Burp options)");
            return;
        }
        try {
            if ("user".equals(level)) {
                api.burpSuite().importUserOptionsFromJson(json);
            } else {
                api.burpSuite().importProjectOptionsFromJson(json);
            }
        } catch (Exception e) {
            sendError(exchange, 500, "import failed: " + e.getMessage());
            return;
        }
        sendOk(exchange, "Imported " + level + "-level options");
    }

    private void getTaskEngine(HttpExchange exchange) throws Exception {
        TaskExecutionEngine.TaskExecutionEngineState s =
            api.burpSuite().taskExecutionEngine().getState();
        sendJson(exchange, JsonUtil.object("state", s.name()));
    }

    private void setTaskEngine(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String want = String.valueOf(body.getOrDefault("state", "")).trim().toUpperCase();
        TaskExecutionEngine.TaskExecutionEngineState target;
        if ("RUNNING".equals(want)) {
            target = TaskExecutionEngine.TaskExecutionEngineState.RUNNING;
        } else if ("PAUSED".equals(want)) {
            target = TaskExecutionEngine.TaskExecutionEngineState.PAUSED;
        } else {
            sendError(exchange, 400, "state must be RUNNING or PAUSED");
            return;
        }
        api.burpSuite().taskExecutionEngine().setState(target);
        sendJson(exchange, JsonUtil.object("state", target.name()));
    }
}
