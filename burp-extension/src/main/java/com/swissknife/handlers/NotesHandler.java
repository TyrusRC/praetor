package com.swissknife.handlers;

import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.store.FindingsStore;
import com.swissknife.util.JsonUtil;

import java.util.List;
import java.util.Map;

/**
 * POST /api/notes/findings           - save a finding
 * GET  /api/notes/findings?endpoint= - get findings
 * GET  /api/notes/export?format=     - export report (markdown or json)
 */
public class NotesHandler extends BaseHandler {

    private final FindingsStore store;
    private final burp.api.montoya.MontoyaApi api;

    public NotesHandler(FindingsStore store, burp.api.montoya.MontoyaApi api) {
        this.store = store;
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if (path.equals("/api/notes/findings") && "POST".equalsIgnoreCase(method)) {
            handleSave(exchange);
        } else if (path.equals("/api/notes/findings") && "GET".equalsIgnoreCase(method)) {
            handleGet(exchange);
        } else if (path.equals("/api/notes/export") && "GET".equalsIgnoreCase(method)) {
            handleExport(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    private void handleSave(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        String title = (String) body.get("title");
        String vulnType = (String) body.get("vuln_type");

        if (title == null || title.isEmpty()) {
            sendError(exchange, 400, "Missing 'title'");
            return;
        }

        // ── chain_with override / NEVER SUBMIT blocklist ──
        @SuppressWarnings("unchecked")
        List<Object> chainWithRaw = (List<Object>) body.get("chain_with");
        List<String> chainWith = new java.util.ArrayList<>();
        if (chainWithRaw != null) {
            for (Object o : chainWithRaw) {
                if (o != null) chainWith.add(String.valueOf(o));
            }
        }

        if (com.swissknife.store.FindingsStore.isNeverSubmit(vulnType, title)) {
            if (chainWith.isEmpty()) {
                sendError(exchange, 400,
                    "'" + (vulnType != null ? vulnType : title) +
                    "' is in NEVER SUBMIT list — provide chain_with[] of existing finding IDs to escalate");
                return;
            }
            for (String id : chainWith) {
                if (!store.hasFinding(id)) {
                    sendError(exchange, 400, "chain_with references unknown finding id: " + id);
                    return;
                }
            }
        }

        // ── evidence object: at least one non-null field ──
        @SuppressWarnings("unchecked")
        Map<String, Object> evidence = (Map<String, Object>) body.get("evidence");
        if (evidence == null) {
            sendError(exchange, 400,
                "evidence required: provide {logger_index, proxy_history_index, or collaborator_interaction_id}");
            return;
        }

        Object loggerIdxObj = evidence.get("logger_index");
        Object proxyIdxObj  = evidence.get("proxy_history_index");
        Object collabIdObj  = evidence.get("collaborator_interaction_id");

        boolean hasLogger = loggerIdxObj instanceof Number;
        boolean hasProxy  = proxyIdxObj instanceof Number;
        boolean hasCollab = collabIdObj instanceof String && !((String) collabIdObj).isEmpty();

        if (!hasLogger && !hasProxy && !hasCollab) {
            sendError(exchange, 400,
                "evidence required: provide logger_index, proxy_history_index, or collaborator_interaction_id");
            return;
        }

        // ── verify existence against live Burp data ──
        int proxyHistorySize = api.proxy().history().size();
        if (hasLogger) {
            int idx = ((Number) loggerIdxObj).intValue();
            // Logger entries in this codebase are sourced from proxy history
            // (see BurpToolsHandler.handleLogger) — same bounds.
            if (idx < 0 || idx >= proxyHistorySize) {
                sendError(exchange, 400, "evidence.logger_index not found: " + idx);
                return;
            }
        }
        if (hasProxy) {
            int idx = ((Number) proxyIdxObj).intValue();
            if (idx < 0 || idx >= proxyHistorySize) {
                sendError(exchange, 400, "evidence.proxy_history_index not found: " + idx);
                return;
            }
        }
        if (hasCollab) {
            String id = (String) collabIdObj;
            try {
                burp.api.montoya.collaborator.CollaboratorClient c = api.collaborator().createClient();
                java.util.List<burp.api.montoya.collaborator.Interaction> interactions = c.getAllInteractions();
                boolean match = false;
                for (var it : interactions) {
                    if (id.equals(it.id().toString())) { match = true; break; }
                }
                if (!match) {
                    sendError(exchange, 400, "evidence.collaborator_interaction_id not found: " + id);
                    return;
                }
            } catch (Exception e) {
                // Collaborator may be unavailable (no Pro license / not configured).
                // Fall through — accept the id when we can't verify, log the limitation.
                api.logging().logToOutput("NotesHandler: collaborator unavailable, accepting interaction id without verification: " + e.getMessage());
            }
        }

        // ── reproductions for timing/blind ──
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> reproductions = (List<Map<String, Object>>) body.get("reproductions");
        if (com.swissknife.store.FindingsStore.requiresReproductions(vulnType)) {
            if (reproductions == null || reproductions.size() < 2) {
                sendError(exchange, 400,
                    "'" + vulnType + "' requires reproductions[] with >= 2 verified Logger entries");
                return;
            }
            for (Map<String, Object> rep : reproductions) {
                Object ridx = rep.get("logger_index");
                if (!(ridx instanceof Number)) {
                    sendError(exchange, 400, "reproductions[].logger_index must be a number");
                    return;
                }
                int ri = ((Number) ridx).intValue();
                if (ri < 0 || ri >= proxyHistorySize) {
                    sendError(exchange, 400, "reproductions[].logger_index not found: " + ri);
                    return;
                }
            }
        }

        // ── store ──
        var finding = store.addFull(
            title,
            (String) body.getOrDefault("description", ""),
            (String) body.get("severity"),
            (String) body.get("endpoint"),
            (String) body.get("evidence_text"),  // freeform proof string moves to a separate key
            vulnType,
            evidence,
            reproductions,
            chainWith.isEmpty() ? null : chainWith
        );

        sendJson(exchange, JsonUtil.toJson(finding));
    }

    private void handleGet(HttpExchange exchange) throws Exception {
        String endpoint = queryParams(exchange).get("endpoint");
        var findings = store.getAll(endpoint);
        sendJson(exchange, JsonUtil.object("total", findings.size(), "findings", findings));
    }

    private void handleExport(HttpExchange exchange) throws Exception {
        String format = queryParams(exchange).getOrDefault("format", "markdown");
        if ("json".equalsIgnoreCase(format)) {
            sendJson(exchange, store.exportJson());
        } else {
            // Return markdown as JSON-wrapped string
            sendJson(exchange, JsonUtil.object("format", "markdown", "content", store.exportMarkdown()));
        }
    }
}
