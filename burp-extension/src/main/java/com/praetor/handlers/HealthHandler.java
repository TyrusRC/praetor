package com.praetor.handlers;

import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.util.JsonUtil;

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
            "extension", "Praetor MCP"
        ));
    }
}
