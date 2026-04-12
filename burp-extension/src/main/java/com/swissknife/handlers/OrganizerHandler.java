package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * Send items to Burp's Organizer tab for categorization.
 *
 * POST /api/organizer/send      — send a proxy history item to Organizer
 * POST /api/organizer/send-bulk — send multiple items to Organizer
 */
public class OrganizerHandler extends BaseHandler {

    private final MontoyaApi api;

    public OrganizerHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if (path.equals("/api/organizer/send") && "POST".equalsIgnoreCase(method)) {
            handleSend(exchange);
        } else if (path.equals("/api/organizer/send-bulk") && "POST".equalsIgnoreCase(method)) {
            handleSendBulk(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    private void handleSend(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        Object indexObj = body.get("index");
        if (!(indexObj instanceof Number)) {
            sendError(exchange, 400, "Missing or invalid 'index'");
            return;
        }
        int index = ((Number) indexObj).intValue();

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index < 0 || index >= history.size()) {
            sendError(exchange, 404, "Index out of range");
            return;
        }

        ProxyHttpRequestResponse item = history.get(index);
        HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(
            item.finalRequest(), item.originalResponse());

        try {
            api.organizer().sendToOrganizer(rr);
            sendOk(exchange, "Sent to Organizer: " + item.finalRequest().method() + " " + item.finalRequest().url());
        } catch (Exception e) {
            sendError(exchange, 500, "Failed to send to Organizer: " + e.getMessage());
        }
    }

    private void handleSendBulk(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        Object indicesObj = body.get("indices");
        if (!(indicesObj instanceof List<?> indicesList)) {
            sendError(exchange, 400, "Missing or invalid 'indices' array");
            return;
        }

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        int sent = 0;
        List<String> errors = new ArrayList<>();

        for (Object obj : indicesList) {
            if (!(obj instanceof Number n)) continue;
            int index = n.intValue();
            if (index < 0 || index >= history.size()) {
                errors.add("Index " + index + " out of range");
                continue;
            }
            try {
                ProxyHttpRequestResponse item = history.get(index);
                HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(
                    item.finalRequest(), item.originalResponse());
                api.organizer().sendToOrganizer(rr);
                sent++;
            } catch (Exception e) {
                errors.add("Index " + index + ": " + e.getMessage());
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "ok");
        result.put("sent", sent);
        if (!errors.isEmpty()) {
            result.put("errors", errors);
        }
        sendJson(exchange, JsonUtil.toJson(result));
    }
}
