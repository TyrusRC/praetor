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
                    "' is in NEVER SUBMIT list — provide chain_with[] of existing finding IDs to escalate",
                    "never_submit",
                    "Pass chain_with=['fXYZ'] of an existing confirmed finding that this one chains to. "
                    + "If you believe the class itself should be reportable on this engagement, use "
                    + "set_program_policy(never_submit_remove=['" + (vulnType != null ? vulnType : "") + "']).");
                return;
            }
            for (String id : chainWith) {
                if (!store.hasFinding(id)) {
                    sendError(exchange, 400, "chain_with references unknown finding id: " + id,
                        "chain_unknown_id",
                        "Verify the chain anchor is saved and confirmed. List with get_findings()");
                    return;
                }
            }
        }

        // ── evidence object: at least one non-null field ──
        // Legacy callers may send `evidence` as a String (freeform proof text);
        // only treat it as the structured object when it actually IS a Map.
        Object evidenceObj = body.get("evidence");
        Map<String, Object> evidence = (evidenceObj instanceof Map<?, ?> m)
            ? toStringObjectMap(m)
            : null;
        if (evidence == null) {
            sendError(exchange, 400,
                "evidence required: provide {logger_index, proxy_history_index, or collaborator_interaction_id}",
                "evidence_missing",
                "Pass evidence={'logger_index': <N>} where N is the index of the confirming replay in proxy/Logger history.");
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
                "evidence required: provide logger_index, proxy_history_index, or collaborator_interaction_id",
                "evidence_missing",
                "Replay the request via resend_with_modification(index) and pass that index as evidence.logger_index.");
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
            // Burp's CollaboratorClient.getAllInteractions() only returns interactions
            // generated by THIS exact client instance, and the Collaborator client is
            // not shared across handlers in this codebase. Cross-handler ID lookup is
            // not currently feasible — accept any non-empty string. The hasCollab
            // boolean already requires non-empty.
            String id = (String) collabIdObj;
            if (id.length() < 8) {
                sendError(exchange, 400,
                    "evidence.collaborator_interaction_id looks invalid (too short): " + id);
                return;
            }
        }

        // ── reproductions for timing/blind ──
        // Type-guard: callers may send a non-list shape (e.g. null, scalar) — coerce
        // only when the JSON value is actually a List.
        Object reproductionsObj = body.get("reproductions");
        List<Map<String, Object>> reproductions = null;
        if (reproductionsObj instanceof List<?> rawList) {
            reproductions = new java.util.ArrayList<>();
            for (Object item : rawList) {
                if (item instanceof Map<?, ?> rawMap) {
                    reproductions.add(toStringObjectMap(rawMap));
                }
            }
        }
        if (com.swissknife.store.FindingsStore.requiresReproductions(vulnType)) {
            if (reproductions == null || reproductions.size() < 3) {
                sendError(exchange, 400,
                    "'" + vulnType + "' requires reproductions[] with >= 3 verified Logger entries (Rule 10a)",
                    "reproductions_required",
                    "Replay the timing/blind probe 2 more times so the array totals 3 entries; pass reproductions=[{logger_index, elapsed_ms, status_code}, ...].");
                return;
            }
            for (Map<String, Object> rep : reproductions) {
                Object ridx = rep.get("logger_index");
                if (!(ridx instanceof Number)) {
                    sendError(exchange, 400, "reproductions[].logger_index must be a number",
                        "reproductions_invalid",
                        "Each entry in reproductions[] must include logger_index as an integer.");
                    return;
                }
                int ri = ((Number) ridx).intValue();
                if (ri < 0 || ri >= proxyHistorySize) {
                    sendError(exchange, 400, "reproductions[].logger_index not found: " + ri,
                        "reproductions_invalid",
                        "Logger index " + ri + " is out of range (history size = " + proxyHistorySize + ").");
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

    /**
     * Coerce a raw {@code Map<?, ?>} produced by JsonUtil into {@code Map<String, Object>}.
     * JsonUtil only ever emits string keys, so this is purely a type-system
     * adapter — no runtime data conversion needed.
     */
    private static Map<String, Object> toStringObjectMap(Map<?, ?> raw) {
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        for (Map.Entry<?, ?> e : raw.entrySet()) {
            out.put(String.valueOf(e.getKey()), e.getValue());
        }
        return out;
    }
}
