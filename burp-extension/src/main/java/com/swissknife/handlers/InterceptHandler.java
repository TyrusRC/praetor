package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

/**
 * Intercept control endpoints.
 *
 * POST /api/intercept/enable
 * POST /api/intercept/disable
 * GET  /api/intercept/status
 */
public class InterceptHandler extends BaseHandler {

    private final MontoyaApi api;
    private volatile boolean interceptEnabled = false;

    public InterceptHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if (path.equals("/api/intercept/enable") && "POST".equalsIgnoreCase(method)) {
            handleInterceptEnable(exchange);
        } else if (path.equals("/api/intercept/disable") && "POST".equalsIgnoreCase(method)) {
            handleInterceptDisable(exchange);
        } else if (path.equals("/api/intercept/status") && "GET".equalsIgnoreCase(method)) {
            handleInterceptStatus(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    private void handleInterceptEnable(HttpExchange exchange) throws Exception {
        api.proxy().enableIntercept();
        interceptEnabled = true;
        sendOk(exchange, "Intercept enabled");
    }

    private void handleInterceptDisable(HttpExchange exchange) throws Exception {
        api.proxy().disableIntercept();
        interceptEnabled = false;
        sendOk(exchange, "Intercept disabled");
    }

    private void handleInterceptStatus(HttpExchange exchange) throws Exception {
        sendJson(exchange, JsonUtil.object(
            "intercept_enabled", interceptEnabled
        ));
    }
}
