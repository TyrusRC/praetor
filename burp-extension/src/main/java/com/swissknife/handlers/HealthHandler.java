package com.swissknife.handlers;

import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

public class HealthHandler extends BaseHandler {

    private final String version;

    public HealthHandler(String version) {
        this.version = version;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        sendJson(exchange, JsonUtil.object(
            "status", "ok",
            "version", version,
            "extension", "Swiss Knife MCP"
        ));
    }
}
