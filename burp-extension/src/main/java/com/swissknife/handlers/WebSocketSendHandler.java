package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.websocket.extension.ExtensionWebSocket;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * WebSocket send/receive through Burp's WebSocket API.
 *
 * POST /api/websocket/connect   — open a WebSocket connection through Burp
 * POST /api/websocket/send      — send a text message on an open connection
 * POST /api/websocket/close     — close a WebSocket connection
 * GET  /api/websocket/connections — list open connections
 */
public class WebSocketSendHandler extends BaseHandler {

    private final MontoyaApi api;
    private final Map<String, WsConnection> connections = new ConcurrentHashMap<>();

    public WebSocketSendHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if (path.equals("/api/websocket/connect") && "POST".equalsIgnoreCase(method)) {
            handleConnect(exchange);
        } else if (path.equals("/api/websocket/send") && "POST".equalsIgnoreCase(method)) {
            handleSend(exchange);
        } else if (path.equals("/api/websocket/close") && "POST".equalsIgnoreCase(method)) {
            handleClose(exchange);
        } else if (path.equals("/api/websocket/connections") && "GET".equalsIgnoreCase(method)) {
            handleList(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    private void handleConnect(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String url = (String) body.get("url");
        String name = (String) body.getOrDefault("name", "ws-" + connections.size());

        if (url == null || url.isEmpty()) {
            sendError(exchange, 400, "Missing 'url' field");
            return;
        }

        try {
            // Build upgrade request
            HttpService service = HttpService.httpService(url);
            String wsPath = "/";
            try {
                java.net.URI uri = new java.net.URI(url);
                wsPath = uri.getRawPath();
                if (wsPath == null || wsPath.isEmpty()) wsPath = "/";
                if (uri.getRawQuery() != null) wsPath += "?" + uri.getRawQuery();
            } catch (Exception ignored) {}

            String upgradeUrl = url.replace("wss://", "https://").replace("ws://", "http://");
            HttpRequest request = HttpRequest.httpRequest(service,
                "GET " + wsPath + " HTTP/1.1\r\n" +
                "Host: " + service.host() + "\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");

            ExtensionWebSocketCreation creation = api.websockets().createWebSocket(request);
            ExtensionWebSocket ws = creation.webSocket().orElse(null);

            if (ws == null) {
                sendError(exchange, 502, "WebSocket connection failed");
                return;
            }

            connections.put(name, new WsConnection(name, url, ws, System.currentTimeMillis()));

            sendJson(exchange, JsonUtil.object(
                "status", "ok",
                "name", name,
                "url", url,
                "message", "WebSocket connected"
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "WebSocket connection error: " + e.getMessage());
        }
    }

    private void handleSend(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String name = (String) body.get("name");
        String message = (String) body.get("message");

        if (name == null || name.isEmpty()) {
            sendError(exchange, 400, "Missing 'name' field");
            return;
        }
        if (message == null) {
            sendError(exchange, 400, "Missing 'message' field");
            return;
        }

        WsConnection conn = connections.get(name);
        if (conn == null) {
            sendError(exchange, 404, "No connection named: " + name);
            return;
        }

        try {
            conn.ws.sendTextMessage(message);
            int total = conn.messagesSent.incrementAndGet();
            sendJson(exchange, JsonUtil.object(
                "status", "ok",
                "name", name,
                "message_sent", message.length() > 200 ? message.substring(0, 200) + "..." : message,
                "total_sent", total
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "Send failed: " + e.getMessage());
        }
    }

    private void handleClose(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String name = (String) body.get("name");

        if (name == null || name.isEmpty()) {
            sendError(exchange, 400, "Missing 'name' field");
            return;
        }

        WsConnection conn = connections.remove(name);
        if (conn == null) {
            sendError(exchange, 404, "No connection named: " + name);
            return;
        }

        try {
            conn.ws.close();
        } catch (Exception ignored) {}

        sendOk(exchange, "WebSocket '" + name + "' closed (sent " + conn.messagesSent.get() + " messages)");
    }

    private void handleList(HttpExchange exchange) throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        for (WsConnection conn : connections.values()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", conn.name);
            entry.put("url", conn.url);
            entry.put("messages_sent", conn.messagesSent.get());
            entry.put("connected_at", new Date(conn.connectedAt).toString());
            list.add(entry);
        }
        sendJson(exchange, JsonUtil.object("connections", list, "count", list.size()));
    }

    private static class WsConnection {
        final String name;
        final String url;
        final ExtensionWebSocket ws;
        final long connectedAt;
        final AtomicInteger messagesSent = new AtomicInteger(0);

        WsConnection(String name, String url, ExtensionWebSocket ws, long connectedAt) {
            this.name = name;
            this.url = url;
            this.ws = ws;
            this.connectedAt = connectedAt;
        }
    }
}
