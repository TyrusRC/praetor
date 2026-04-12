package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * Proxy history annotation endpoints.
 *
 * POST /api/annotations/set
 * GET  /api/annotations/{index}
 * POST /api/annotations/bulk
 */
public class AnnotationHandler extends BaseHandler {

    private final MontoyaApi api;

    public AnnotationHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if (path.equals("/api/annotations/set") && "POST".equalsIgnoreCase(method)) {
            handleAnnotationSet(exchange);
        } else if (path.matches("/api/annotations/\\d+") && "GET".equalsIgnoreCase(method)) {
            handleAnnotationGet(exchange, path);
        } else if (path.equals("/api/annotations/bulk") && "POST".equalsIgnoreCase(method)) {
            handleAnnotationBulk(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    private void handleAnnotationSet(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        applyAnnotation(body);
        sendOk(exchange, "Annotation set");
    }

    private void handleAnnotationGet(HttpExchange exchange, String path) throws Exception {
        int index;
        try {
            index = Integer.parseInt(path.substring(path.lastIndexOf('/') + 1));
        } catch (NumberFormatException e) {
            sendError(exchange, 400, "Invalid index");
            return;
        }

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index < 0 || index >= history.size()) {
            sendError(exchange, 404, "Index out of range");
            return;
        }

        ProxyHttpRequestResponse item = history.get(index);
        String notes = item.annotations().notes();
        HighlightColor color = item.annotations().highlightColor();

        sendJson(exchange, JsonUtil.object(
            "index", index,
            "color", color != null ? color.name() : "NONE",
            "notes", notes != null ? notes : ""
        ));
    }

    private void handleAnnotationBulk(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        Object itemsObj = body.get("items");
        if (!(itemsObj instanceof List<?> itemsList)) {
            sendError(exchange, 400, "Missing or invalid 'items' array");
            return;
        }

        int applied = 0;
        List<String> errors = new ArrayList<>();

        for (Object item : itemsList) {
            if (!(item instanceof Map<?, ?> itemMap)) continue;
            try {
                applyAnnotation(itemMap);
                applied++;
            } catch (Exception e) {
                errors.add(e.getMessage());
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "ok");
        result.put("applied", applied);
        if (!errors.isEmpty()) {
            result.put("errors", errors);
        }
        sendJson(exchange, JsonUtil.toJson(result));
    }

    private void applyAnnotation(Map<?, ?> data) {
        Object indexObj = data.get("index");
        if (!(indexObj instanceof Number indexNum)) {
            throw new IllegalArgumentException("Missing or invalid 'index'");
        }
        int index = indexNum.intValue();

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index < 0 || index >= history.size()) {
            throw new IllegalArgumentException("Index out of range: " + index);
        }

        ProxyHttpRequestResponse item = history.get(index);

        Object colorObj = data.get("color");
        if (colorObj instanceof String colorStr && !colorStr.isEmpty()) {
            HighlightColor color = parseHighlightColor(colorStr);
            item.annotations().setHighlightColor(color);
        }

        Object commentObj = data.get("comment");
        if (commentObj instanceof String comment && !comment.isEmpty()) {
            item.annotations().setNotes(comment);
        }
    }

    private HighlightColor parseHighlightColor(String name) {
        return switch (name.toUpperCase()) {
            case "RED" -> HighlightColor.RED;
            case "ORANGE" -> HighlightColor.ORANGE;
            case "YELLOW" -> HighlightColor.YELLOW;
            case "GREEN" -> HighlightColor.GREEN;
            case "CYAN" -> HighlightColor.CYAN;
            case "BLUE" -> HighlightColor.BLUE;
            case "PINK" -> HighlightColor.PINK;
            case "MAGENTA" -> HighlightColor.MAGENTA;
            case "GRAY" -> HighlightColor.GRAY;
            default -> HighlightColor.NONE;
        };
    }
}
