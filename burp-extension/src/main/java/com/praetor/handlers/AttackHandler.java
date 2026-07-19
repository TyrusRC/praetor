package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import com.praetor.attack.AuthMatrixHandler;
import com.praetor.attack.HppHandler;
import com.praetor.attack.RaceHandler;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;

import java.util.Map;

/**
 * Thin router for {@code POST /api/attack/*}. Each route dispatches to a
 * collaborator in {@link com.praetor.attack}:
 *
 *   /api/attack/auth-matrix -> AuthMatrixHandler
 *   /api/attack/race        -> RaceHandler
 *   /api/attack/hpp         -> HppHandler
 *
 * Session state is read via {@link com.praetor.store.SessionStore} singleton
 * by each collaborator, so this router no longer needs a sessions map.
 */
public class AttackHandler extends BaseHandler {

    private final AuthMatrixHandler authMatrix;
    private final RaceHandler race;
    private final HppHandler hpp;

    public AttackHandler(MontoyaApi api) {
        this.authMatrix = new AuthMatrixHandler(api);
        this.race = new RaceHandler(api);
        this.hpp = new HppHandler(api);
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String path = exchange.getRequestURI().getPath();
        Map<String, Object> body = readJsonBody(exchange);

        switch (path) {
            case "/api/attack/auth-matrix" -> authMatrix.handle(exchange, body);
            case "/api/attack/race" -> race.handle(exchange, body);
            case "/api/attack/hpp" -> hpp.handle(exchange, body);
            default -> sendError(exchange, 404, "Not found");
        }
    }
}
