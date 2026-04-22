package com.swissknife.http;

import java.io.IOException;

/**
 * Drop-in replacement for com.sun.net.httpserver.HttpHandler.
 *
 * Implementations handle a single HTTP request/response exchange. The server
 * calls handle(exchange) on a worker thread; the handler is responsible for
 * writing the response via exchange.sendResponseHeaders() and
 * exchange.getResponseBody(), then exchange.close() (or letting try-with-resources
 * close it).
 */
@FunctionalInterface
public interface HttpHandler {
    void handle(HttpExchange exchange) throws IOException;
}
