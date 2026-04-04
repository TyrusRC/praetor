package com.swissknife.handlers;

import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

public class HealthHandler extends BaseHandler {

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        sendJson(exchange, JsonUtil.object(
            "status", "ok",
            "version", "0.1.0",
            "extension", "Swiss Knife MCP"
        ));
    }
}
