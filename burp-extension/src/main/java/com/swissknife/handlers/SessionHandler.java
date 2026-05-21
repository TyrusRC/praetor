package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.session.AttackSurfaceDiscovery;
import com.swissknife.session.AutoProbeOrchestrator;
import com.swissknife.session.BatchProbeHandler;
import com.swissknife.session.FlowRunner;
import com.swissknife.session.SessionExtractHandler;
import com.swissknife.session.SessionRequestExecutor;
import com.swissknife.store.FindingsStore;
import com.swissknife.store.SessionStore;
import com.swissknife.util.JsonUtil;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Thin router for {@code /api/session/*}. Heavy lifting lives in:
 *  - {@link SessionStore} — session table
 *  - {@link SessionRequestExecutor} — HTTP send, cookie jar, response build
 *  - {@link com.swissknife.session.VariableExtractor} — regex / json_path / interpolation
 *  - {@link FlowRunner} — multi-step flows
 *  - {@link AttackSurfaceDiscovery} — BFS crawl + risk scoring
 *  - {@link AutoProbeOrchestrator} — KB-driven probing
 *  - {@link BatchProbeHandler} — baseline-vs-payload + batch endpoint hit
 *  - {@link SessionExtractHandler} — replay extraction on last response
 *
 * Routes (unchanged from pre-split):
 *  POST   /api/session/create     — create session
 *  POST   /api/session/request    — send request with session state
 *  POST   /api/session/extract    — extract values from last response
 *  POST   /api/session/flow       — execute multi-step flow
 *  POST   /api/session/probe      — baseline-vs-payload comparison
 *  POST   /api/session/batch      — multi-endpoint hit
 *  POST   /api/session/discover   — BFS crawl from session base URL
 *  POST   /api/session/auto-probe — knowledge-driven parameter probing
 *  GET    /api/session/list       — list all sessions
 *  GET    /api/session/{name}/last-host — last-used host for the session
 *  DELETE /api/session/{name}     — delete a session
 */
public class SessionHandler extends BaseHandler {

    private final MontoyaApi api;
    private final SessionStore store = SessionStore.get();
    private final SessionRequestExecutor executor;
    private final FlowRunner flowRunner;
    private final AttackSurfaceDiscovery discovery;
    private final AutoProbeOrchestrator autoProbe;
    private final BatchProbeHandler batchProbe;
    private final SessionExtractHandler extractHandler;

    public SessionHandler(MontoyaApi api, FindingsStore findingsStore) {
        this.api = api;
        this.executor = new SessionRequestExecutor(api);
        this.flowRunner = new FlowRunner(executor, store);
        this.discovery = new AttackSurfaceDiscovery(api, executor);
        this.autoProbe = new AutoProbeOrchestrator(api, executor, findingsStore);
        this.batchProbe = new BatchProbeHandler(api, executor);
        this.extractHandler = new SessionExtractHandler();
    }

    /** Live session table. Kept on the public surface for legacy callers
     *  (AttackHandler ctor + ApiServer wiring). New code should pull
     *  {@link SessionStore#get()} directly. */
    public Map<String, Session> getSessions() {
        return store.getSessions();
    }

    /** Session metadata for the Config UI tab. */
    public List<String[]> getSessionInfoList() {
        return store.getSessionInfoList();
    }

    // ── Routing ───────────────────────────────────────────────────

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();

        switch (method.toUpperCase()) {
            case "GET" -> {
                if ("/api/session/list".equals(path)) {
                    handleList(exchange);
                } else if (path.startsWith("/api/session/") && path.endsWith("/last-host")) {
                    String name = path.substring("/api/session/".length(), path.length() - "/last-host".length());
                    handleLastHost(exchange, name);
                } else {
                    sendError(exchange, 404, "Not found");
                }
            }
            case "POST" -> {
                Map<String, Object> body = readJsonBody(exchange);
                switch (path) {
                    case "/api/session/create" -> handleCreate(exchange, body);
                    case "/api/session/request" -> executor.handle(exchange, body, store);
                    case "/api/session/extract" -> extractHandler.handle(exchange, body, store);
                    case "/api/session/flow" -> flowRunner.handle(exchange, body);
                    case "/api/session/probe" -> batchProbe.handleProbe(exchange, body, store);
                    case "/api/session/batch" -> batchProbe.handleBatch(exchange, body, store);
                    case "/api/session/discover" -> discovery.handle(exchange, body, store);
                    case "/api/session/auto-probe" -> autoProbe.handle(exchange, body, store);
                    default -> sendError(exchange, 404, "Not found");
                }
            }
            case "DELETE" -> {
                String name = pathSegment(exchange, 2);
                if (name != null) {
                    handleDelete(exchange, name);
                } else {
                    sendError(exchange, 400, "Missing session name in path");
                }
            }
            default -> sendError(exchange, 405, "Method not allowed");
        }
    }

    // ── POST /api/session/create ──────────────────────────────────

    private void handleCreate(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String name = (String) body.get("name");
        if (name == null || name.isBlank()) {
            sendError(exchange, 400, "Missing 'name'");
            return;
        }

        Session session = new Session();
        session.name = name;
        session.baseUrl = (String) body.getOrDefault("base_url", "");

        @SuppressWarnings("unchecked")
        Map<String, Object> cookies = (Map<String, Object>) body.get("cookies");
        if (cookies != null) {
            cookies.forEach((k, v) -> session.cookies.put(k, String.valueOf(v)));
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> headers = (Map<String, Object>) body.get("headers");
        if (headers != null) {
            headers.forEach((k, v) -> session.headers.put(k, String.valueOf(v)));
        }

        String bearer = (String) body.get("bearer_token");
        if (bearer != null) session.bearerToken = bearer;

        String authUser = (String) body.get("auth_user");
        if (authUser != null) session.authUser = authUser;

        String authPass = (String) body.get("auth_pass");
        if (authPass != null) session.authPass = authPass;

        store.putSession(name, session);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("session", name);
        out.put("base_url", session.baseUrl);
        out.put("cookies", session.cookies.size());
        out.put("headers", session.headers.size());
        out.put("has_auth", !session.bearerToken.isEmpty() || !session.authUser.isEmpty());
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── GET /api/session/list ─────────────────────────────────────

    private void handleList(HttpExchange exchange) throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        for (Session s : store.getSessions().values()) {
            synchronized (s) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("name", s.name);
                info.put("base_url", s.baseUrl);
                info.put("cookies", s.cookies.size());
                info.put("headers", s.headers.size());
                info.put("variables", s.variables.size());
                info.put("has_auth", !s.bearerToken.isEmpty() || !s.authUser.isEmpty());
                info.put("has_last_response", s.lastResponse != null);
                list.add(info);
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sessions", list);
        out.put("total", list.size());
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── GET /api/session/{name}/last-host ─────────────────────────

    private void handleLastHost(HttpExchange exchange, String name) throws Exception {
        if (name == null || name.isEmpty()) {
            sendError(exchange, 400, "Session name required");
            return;
        }
        Session session = store.getSession(name);
        if (session == null) {
            sendError(exchange, 404, "Session not found: " + name);
            return;
        }
        synchronized (session) {
            HttpRequestResponse last = session.lastResponse;
            if (last == null || last.request() == null) {
                sendError(exchange, 409, "Session has no requests yet: " + name);
                return;
            }
            HttpService svc = last.request().httpService();
            if (svc == null) {
                sendError(exchange, 500, "Session last request has no http service");
                return;
            }
            sendJson(exchange, JsonUtil.object(
                "host", svc.host(),
                "port", svc.port(),
                "https", svc.secure()
            ));
        }
    }

    // ── DELETE /api/session/{name} ────────────────────────────────

    private void handleDelete(HttpExchange exchange, String name) throws Exception {
        Session removed = store.removeSession(name);
        if (removed == null) {
            sendError(exchange, 404, "Session not found: " + name);
            return;
        }
        sendOk(exchange, "Session deleted: " + name);
    }
}
