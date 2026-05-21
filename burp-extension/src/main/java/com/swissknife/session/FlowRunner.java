package com.swissknife.session;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.swissknife.handlers.Session;
import com.swissknife.http.HttpExchange;
import com.swissknife.store.SessionStore;
import com.swissknife.util.JsonUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Executes the multi-step flow route: {@code POST /api/session/flow}.
 * Per-step variable interpolation, optional extraction, cookie jar updates,
 * and early-stop on 4xx/5xx (unless {@code continue_on_error}).
 *
 * Behaviour-preserving lift from SessionHandler.handleFlow.
 */
public final class FlowRunner {

    private final SessionRequestExecutor executor;
    private final SessionStore store;

    public FlowRunner(SessionRequestExecutor executor, SessionStore store) {
        this.executor = executor;
        this.store = store;
    }

    public void handle(HttpExchange exchange, Map<String, Object> body) throws Exception {
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

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> steps = (List<Map<String, Object>>) body.get("steps");
        if (steps == null || steps.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'steps'");
            return;
        }

        synchronized (session) {
            List<Map<String, Object>> results = new ArrayList<>();
            int stepsExecuted = 0;

            for (Map<String, Object> rawStep : steps) {
                stepsExecuted++;

                Map<String, Object> step = VariableExtractor.interpolateStep(rawStep, session.variables);

                long stepStart = System.nanoTime();
                HttpRequestResponse result = executor.send(session, step);
                long stepMs = (System.nanoTime() - stepStart) / 1_000_000;

                if (result == null) {
                    Map<String, Object> stepResult = new LinkedHashMap<>();
                    stepResult.put("step", stepsExecuted);
                    stepResult.put("error", "Failed to send request");
                    results.add(stepResult);
                    break;
                }

                session.lastResponse = result;
                executor.updateCookiesFromResponse(session, result);

                Map<String, String> extracted = new LinkedHashMap<>();
                List<String> stepExtractWarnings = Collections.emptyList();
                @SuppressWarnings("unchecked")
                Map<String, Object> extractRules = (Map<String, Object>) step.get("extract");
                if (extractRules != null) {
                    extracted = VariableExtractor.extractFromResponse(result, extractRules);
                    stepExtractWarnings = new ArrayList<>(VariableExtractor.LAST_EXTRACT_WARNINGS.get());
                    VariableExtractor.LAST_EXTRACT_WARNINGS.remove();
                    VariableExtractor.mergeVariables(session, extracted);
                }

                Map<String, Object> stepResult = new LinkedHashMap<>();
                stepResult.put("step", stepsExecuted);
                stepResult.put("method", step.getOrDefault("method", "GET"));
                stepResult.put("path", step.getOrDefault("path", "/"));
                HttpResponse resp = result.response();
                stepResult.put("status", resp != null ? resp.statusCode() : 0);
                stepResult.put("response_length", resp != null ? resp.body().length() : 0);
                stepResult.put("response_time_ms", stepMs);
                stepResult.put("extracted", extracted);
                if (!stepExtractWarnings.isEmpty()) {
                    stepResult.put("extract_warnings", stepExtractWarnings);
                }
                if (resp != null) {
                    String bodySnippet = resp.bodyToString();
                    if (bodySnippet.length() > 500) bodySnippet = bodySnippet.substring(0, 500);
                    stepResult.put("body_snippet", bodySnippet);
                }
                results.add(stepResult);

                if (resp != null) {
                    int status = resp.statusCode();
                    if (status >= 400) {
                        Object continueFlag = step.get("continue_on_error");
                        boolean shouldContinue = continueFlag instanceof Boolean b && b;
                        if (!shouldContinue) break;
                    }
                }
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("steps_executed", stepsExecuted);
            out.put("total_steps", steps.size());
            out.put("results", results);
            out.put("session_variables", new LinkedHashMap<>(session.variables));
            out.put("session_cookies", new LinkedHashMap<>(session.cookies));
            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

    private void sendJson(HttpExchange exchange, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendError(HttpExchange exchange, int status, String message) throws IOException {
        String code = switch (status) {
            case 400 -> "validation_failed";
            case 404 -> "not_found";
            default -> "error";
        };
        String json = JsonUtil.object("error", message, "code", code, "hint", "");
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
