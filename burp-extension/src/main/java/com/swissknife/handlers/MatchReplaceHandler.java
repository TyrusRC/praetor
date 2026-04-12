package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Match-and-replace rule management endpoints.
 *
 * POST   /api/match-replace/add
 * GET    /api/match-replace
 * DELETE /api/match-replace/{id}
 * POST   /api/match-replace/clear
 */
public class MatchReplaceHandler extends BaseHandler {

    private final MontoyaApi api;
    private final AtomicInteger ruleIdCounter = new AtomicInteger(1);
    private final CopyOnWriteArrayList<MatchReplaceRule> matchReplaceRules = new CopyOnWriteArrayList<>();

    // ── Inner type ────────────────────────────────────────────────

    static final class MatchReplaceRule {
        final int id;
        final String type;      // "request" or "response"
        final String match;     // regex pattern
        final String replace;
        final boolean enabled;
        final String scope;     // "all" or "in_scope"

        MatchReplaceRule(int id, String type, String match, String replace, boolean enabled, String scope) {
            this.id = id;
            this.type = type;
            this.match = match;
            this.replace = replace;
            this.enabled = enabled;
            this.scope = scope;
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("type", type);
            m.put("match", match);
            m.put("replace", replace);
            m.put("enabled", enabled);
            m.put("scope", scope);
            return m;
        }
    }

    // ── Constructor ───────────────────────────────────────────────

    public MatchReplaceHandler(MontoyaApi api) {
        this.api = api;
    }

    // ── Route dispatch ────────────────────────────────────────────

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if (path.equals("/api/match-replace/add") && "POST".equalsIgnoreCase(method)) {
            handleMatchReplaceAdd(exchange);
        } else if (path.equals("/api/match-replace") && "GET".equalsIgnoreCase(method)) {
            handleMatchReplaceList(exchange);
        } else if (path.matches("/api/match-replace/\\d+") && "DELETE".equalsIgnoreCase(method)) {
            handleMatchReplaceDelete(exchange, path);
        } else if (path.equals("/api/match-replace/clear") && "POST".equalsIgnoreCase(method)) {
            handleMatchReplaceClear(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    // ── Handlers ──────────────────────────────────────────────────

    private void handleMatchReplaceAdd(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        Object rulesObj = body.get("rules");
        if (!(rulesObj instanceof List<?> rulesList)) {
            sendError(exchange, 400, "Missing or invalid 'rules' array");
            return;
        }

        List<Map<String, Object>> added = new ArrayList<>();
        for (Object item : rulesList) {
            if (!(item instanceof Map<?, ?> ruleMap)) continue;

            String type = stringVal(ruleMap, "type", "request");
            String match = stringVal(ruleMap, "match", "");
            String replace = stringVal(ruleMap, "replace", "");
            boolean enabled = !Boolean.FALSE.equals(ruleMap.get("enabled")); // default true
            String scope = stringVal(ruleMap, "scope", "all");

            if (match.isEmpty()) continue;

            // Validate regex
            try {
                Pattern.compile(match);
            } catch (PatternSyntaxException e) {
                sendError(exchange, 400, "Invalid regex pattern: " + match + " — " + e.getMessage());
                return;
            }

            int id = ruleIdCounter.getAndIncrement();
            MatchReplaceRule rule = new MatchReplaceRule(id, type, match, replace, enabled, scope);
            matchReplaceRules.add(rule);
            added.add(rule.toMap());
        }

        sendJson(exchange, JsonUtil.object("status", "ok", "rules", added));
    }

    private void handleMatchReplaceList(HttpExchange exchange) throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        for (MatchReplaceRule rule : matchReplaceRules) {
            list.add(rule.toMap());
        }
        sendJson(exchange, JsonUtil.object("rules", list));
    }

    private void handleMatchReplaceDelete(HttpExchange exchange, String path) throws Exception {
        int id;
        try {
            id = Integer.parseInt(path.substring(path.lastIndexOf('/') + 1));
        } catch (NumberFormatException e) {
            sendError(exchange, 400, "Invalid rule ID");
            return;
        }

        boolean removed = matchReplaceRules.removeIf(r -> r.id == id);
        if (removed) {
            sendOk(exchange, "Rule " + id + " removed");
        } else {
            sendError(exchange, 404, "Rule not found: " + id);
        }
    }

    private void handleMatchReplaceClear(HttpExchange exchange) throws Exception {
        int count = matchReplaceRules.size();
        matchReplaceRules.clear();
        sendOk(exchange, "Cleared " + count + " rules");
    }

    // ── Helpers ───────────────────────────────────────────────────

    private String stringVal(Map<?, ?> map, String key, String defaultVal) {
        Object val = map.get(key);
        return val instanceof String s ? s : defaultVal;
    }

    /** Provides read access to match-replace rules for proxy request/response handlers. */
    public List<MatchReplaceRule> getMatchReplaceRules() {
        return Collections.unmodifiableList(matchReplaceRules);
    }
}
