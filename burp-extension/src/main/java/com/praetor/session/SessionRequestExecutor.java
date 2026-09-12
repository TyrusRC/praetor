package com.praetor.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.praetor.handlers.Session;
import com.praetor.http.HttpExchange;
import static com.praetor.http.HttpResponses.sendJson;
import static com.praetor.http.HttpResponses.sendError;
import com.praetor.server.BaseHandler;
import com.praetor.store.SessionStore;
import com.praetor.ui.ConfigTab;
import com.praetor.util.JsonUtil;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Owns the actual HTTP-send work for sessions: cookie jar merge,
 * Authorization injection, body resolution, redirect-following, response-map
 * construction. Extracted verbatim from SessionHandler.
 *
 * Exposes:
 *  - {@link #send(Session, Map)} — pure sender used by every collaborator
 *  - {@link #handle(HttpExchange, Map, SessionStore)} — full route handler
 *    for {@code POST /api/session/request}
 *  - {@link #updateCookiesFromResponse(Session, HttpRequestResponse)} —
 *    cookie-jar update used by every collaborator after each send
 *  - {@link #buildResponseMap(HttpRequestResponse)} — response-shape builder
 *  - {@link #extractTitle(String)} — shared helper for batch/discover
 */
public final class SessionRequestExecutor {

    private static final int MAX_RESPONSE_SIZE = com.praetor.server.ResponseLimits.MAX_RESPONSE_BODY;

    private final MontoyaApi api;

    public SessionRequestExecutor(MontoyaApi api) {
        this.api = api;
    }

    public MontoyaApi api() {
        return api;
    }

    // ── POST /api/session/request route ──────────────────────────────

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
            long startNanos = System.nanoTime();
            HttpRequestResponse result = send(session, body);
            long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;

            if (result == null) {
                sendError(exchange, 500, "Failed to send request");
                return;
            }

            session.lastResponse = result;
            updateCookiesFromResponse(session, result);

            Map<String, String> extracted = new LinkedHashMap<>();
            List<String> extractWarnings = Collections.emptyList();
            @SuppressWarnings("unchecked")
            Map<String, Object> extractRules = (Map<String, Object>) body.get("extract");
            if (extractRules != null) {
                extracted = VariableExtractor.extractFromResponse(result, extractRules);
                extractWarnings = new ArrayList<>(VariableExtractor.LAST_EXTRACT_WARNINGS.get());
                VariableExtractor.LAST_EXTRACT_WARNINGS.remove();
                VariableExtractor.mergeVariables(session, extracted);
            }

            Map<String, Object> out = buildResponseMap(result);
            out.put("response_time_ms", elapsedMs);
            ConfigTab.log("session_request: " + body.getOrDefault("method", "GET") + " " + body.getOrDefault("path", "/") + " -> " + (result.response() != null ? result.response().statusCode() : 0) + " (" + elapsedMs + "ms)");
            out.put("extracted", extracted);
            if (!extractWarnings.isEmpty()) {
                out.put("extract_warnings", extractWarnings);
            }
            out.put("session_cookies", new LinkedHashMap<>(session.cookies));
            out.put("session_variables", new LinkedHashMap<>(session.variables));

            Object analyzeFlag = body.get("analyze");
            if (analyzeFlag instanceof Boolean b && b && result.response() != null) {
                Map<String, Object> analysis = new LinkedHashMap<>();
                HttpRequest req = result.request();
                HttpResponse resp = result.response();
                analysis.put("tech_stack", com.praetor.analysis.TechStackDetector.detect(resp));
                analysis.put("injection_points", com.praetor.analysis.InjectionPointDetector.detect(req, resp));
                analysis.put("parameters", com.praetor.analysis.ParameterExtractor.extract(req));
                String contentType = resp.headerValue("Content-Type") != null ? resp.headerValue("Content-Type") : "";
                if (contentType.contains("html")) {
                    String bodyStr = resp.bodyToString();
                    analysis.put("forms", com.praetor.analysis.FormExtractor.extract(bodyStr));
                    analysis.put("endpoints", com.praetor.analysis.EndpointExtractor.extract(bodyStr, req.url()));
                }
                if (contentType.contains("javascript") || contentType.contains("html")) {
                    analysis.put("secrets", com.praetor.analysis.JsSecretExtractor.extract(resp.bodyToString()));
                }
                out.put("analysis", analysis);
            }

            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

    // ── Core send (used by handleSessionRequest + flow + probes + batch + discover + auto-probe) ──

    public HttpRequestResponse send(Session session, Map<String, Object> params) {
        return new SessionSender(api).send(session, params);
    }

    public void updateCookiesFromResponse(Session session, HttpRequestResponse result) {
        SessionRequestHelpers.updateCookies(session, result);
    }

    // ── Response formatting ──

    public Map<String, Object> buildResponseMap(HttpRequestResponse result) {
        Map<String, Object> out = new LinkedHashMap<>();
        HttpRequest req = result.request();
        if (req != null) {
            out.put("url", req.url());
        }
        HttpResponse resp = result.response();

        out.put("status", resp != null ? resp.statusCode() : 0);
        out.put("response_length", resp != null ? resp.body().length() : 0);

        if (resp != null) {
            List<Map<String, Object>> headers = new ArrayList<>();
            for (HttpHeader h : resp.headers()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", h.name());
                m.put("value", h.value());
                headers.add(m);
            }
            out.put("response_headers", headers);

            String body = resp.bodyToString();
            if (body.length() > MAX_RESPONSE_SIZE) {
                int half = MAX_RESPONSE_SIZE / 2;
                body = body.substring(0, half)
                    + "\n\n[... TRUNCATED " + (body.length() - MAX_RESPONSE_SIZE) + " chars ...]\n\n"
                    + body.substring(body.length() - half);
            }
            out.put("response_body", body);
        }

        return out;
    }

    public static String extractTitle(String html) {
        if (html == null) return null;
        int start = html.indexOf("<title>");
        if (start < 0) start = html.indexOf("<TITLE>");
        if (start < 0) return null;
        start += 7;
        int end = html.indexOf("</title>", start);
        if (end < 0) end = html.indexOf("</TITLE>", start);
        if (end < 0 || end - start > 200) return null;
        return html.substring(start, end).trim();
    }

}
