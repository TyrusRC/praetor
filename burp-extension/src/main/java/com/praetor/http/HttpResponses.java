package com.praetor.http;

import com.praetor.util.JsonUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * JSON response helpers for handler-package collaborators that live outside
 * {@code com.praetor.handlers} and therefore cannot call BaseHandler's
 * {@code protected} response methods. Behaviour mirrors BaseHandler verbatim.
 */
public final class HttpResponses {

    private HttpResponses() { }

    public static void sendJson(HttpExchange exchange, String json) throws IOException {
        sendJson(exchange, 200, json);
    }

    public static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    public static void sendError(HttpExchange exchange, int status, String message) throws IOException {
        sendError(exchange, status, message, codeFromStatus(status), "");
    }

    public static void sendError(HttpExchange exchange, int status, String message,
                                 String code, String hint) throws IOException {
        sendJson(exchange, status, JsonUtil.object(
            "error", message,
            "code", code == null ? "" : code,
            "hint", hint == null ? "" : hint
        ));
    }

    private static String codeFromStatus(int status) {
        return switch (status) {
            case 400 -> "validation_failed";
            case 401 -> "unauthorized";
            case 403 -> "forbidden";
            case 404 -> "not_found";
            case 405 -> "method_not_allowed";
            case 409 -> "conflict";
            case 422 -> "unprocessable";
            case 500 -> "server_error";
            case 501 -> "not_implemented";
            case 503 -> "unavailable";
            default -> "error";
        };
    }
}
