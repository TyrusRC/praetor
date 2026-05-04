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
        sendOk(exchange, "Intercept enabled");
    }

    private void handleInterceptDisable(HttpExchange exchange) throws Exception {
        api.proxy().disableIntercept();
        sendOk(exchange, "Intercept disabled");
    }

    private void handleInterceptStatus(HttpExchange exchange) throws Exception {
        // Read live state from Burp via the Montoya API. A locally cached
        // field would drift the moment the operator toggles intercept in the
        // Burp UI directly; the live read keeps /status honest.
        boolean live = readLiveInterceptState();
        sendJson(exchange, JsonUtil.object(
            "intercept_enabled", live
        ));
    }

    /**
     * Probe Burp's intercept state through reflection because the Montoya
     * Proxy interface only exposes enable/disable, not a getter. Falls back
     * to {@code false} if the underlying implementation no longer carries
     * a recognizable "isInterceptEnabled" / "interceptOn" accessor.
     */
    private boolean readLiveInterceptState() {
        try {
            Object proxy = api.proxy();
            for (String name : new String[]{"isInterceptEnabled", "interceptEnabled", "isEnabled", "interceptOn"}) {
                try {
                    var m = proxy.getClass().getMethod(name);
                    Object v = m.invoke(proxy);
                    if (v instanceof Boolean b) return b;
                } catch (NoSuchMethodException ignored) {
                    // try next name
                }
            }
        } catch (Exception ignored) {
            // fall through
        }
        return false;
    }
}
