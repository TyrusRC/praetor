package com.swissknife.session;

import com.swissknife.handlers.Session;
import com.swissknife.http.HttpExchange;
import static com.swissknife.http.HttpResponses.sendJson;
import static com.swissknife.http.HttpResponses.sendError;
import com.swissknife.store.SessionStore;
import com.swissknife.util.JsonUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Handles {@code POST /api/session/extract}. Re-runs extraction rules over
 * the session's last response, merges new variables, surfaces warnings.
 * Behaviour-preserving lift from SessionHandler.handleExtract.
 */
public final class SessionExtractHandler {

    public void handle(HttpExchange exchange, Map<String, Object> body, SessionStore store) throws Exception {
        String name = (String) body.get("session");
        if (name == null) {
            sendError(exchange, 400, "Missing 'session' name");
            return;
        }

        Session session = store.getSession(name);
        if (session == null) {
            sendError(exchange, 404, "Session not found: " + name);
            return;
        }

        synchronized (session) {
            if (session.lastResponse == null) {
                sendError(exchange, 400, "No previous response in session");
                return;
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> rules = (Map<String, Object>) body.get("extract");
            if (rules == null) {
                @SuppressWarnings("unchecked")
                Map<String, Object> alt = (Map<String, Object>) body.get("rules");
                rules = alt;
            }
            if (rules == null) {
                sendError(exchange, 400, "Missing 'extract'");
                return;
            }

            Map<String, String> extracted = VariableExtractor.extractFromResponse(session.lastResponse, rules);
            List<String> extractWarnings = new ArrayList<>(VariableExtractor.LAST_EXTRACT_WARNINGS.get());
            VariableExtractor.LAST_EXTRACT_WARNINGS.remove();
            VariableExtractor.mergeVariables(session, extracted);

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("status", "ok");
            out.put("extracted", extracted);
            if (!extractWarnings.isEmpty()) {
                out.put("extract_warnings", extractWarnings);
            }
            out.put("session_variables", new LinkedHashMap<>(session.variables));
            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

}
