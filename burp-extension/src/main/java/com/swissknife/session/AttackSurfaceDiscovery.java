package com.swissknife.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.swissknife.handlers.Session;
import com.swissknife.http.HttpExchange;
import com.swissknife.store.SessionStore;
import com.swissknife.ui.ConfigTab;
import com.swissknife.util.JsonUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Handles {@code POST /api/session/discover}: BFS-crawl from the session
 * base URL, harvest endpoints + forms + parameters, risk-score each
 * endpoint, build pre-formatted {@code targets[]} ready for auto-probe.
 * Behaviour-preserving lift from SessionHandler.handleDiscover.
 */
public final class AttackSurfaceDiscovery {

    @SuppressWarnings("unused")
    private final MontoyaApi api;
    private final SessionRequestExecutor executor;

    public AttackSurfaceDiscovery(MontoyaApi api, SessionRequestExecutor executor) {
        this.api = api;
        this.executor = executor;
    }

    public void handle(HttpExchange exchange, Map<String, Object> body, SessionStore store) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) { sendError(exchange, 400, "Missing 'session'"); return; }
        Session session = store.getSession(sessionName);
        if (session == null) { sendError(exchange, 404, "Session not found"); return; }

        int maxPages = body.containsKey("max_pages") ? ((Number) body.get("max_pages")).intValue() : 20;

        synchronized (session) {
            Set<String> visited = new LinkedHashSet<>();
            Queue<String> queue = new LinkedList<>();
            List<Map<String, Object>> endpoints = new ArrayList<>();
            List<Map<String, Object>> forms = new ArrayList<>();
            List<String> detectedTech = new ArrayList<>();
            int totalParams = 0;
            int highRiskParams = 0;

            queue.add("/");

            while (!queue.isEmpty() && visited.size() < maxPages) {
                String pagePath = queue.poll();
                if (visited.contains(pagePath)) continue;
                visited.add(pagePath);

                Map<String, Object> reqParams = new LinkedHashMap<>();
                reqParams.put("method", "GET");
                reqParams.put("path", pagePath);

                HttpRequestResponse result = executor.send(session, reqParams);
                if (result == null || result.response() == null) continue;
                executor.updateCookiesFromResponse(session, result);

                HttpResponse resp = result.response();
                String respBody = resp.bodyToString();
                int status = resp.statusCode();

                if (detectedTech.isEmpty()) {
                    detectedTech.addAll(TechFingerprint.detectFromResponse(result));
                }

                String title = SessionRequestExecutor.extractTitle(respBody);

                List<Map<String, Object>> pageParams = new ArrayList<>();
                if (pagePath.contains("?")) {
                    String query = pagePath.substring(pagePath.indexOf("?") + 1);
                    for (String pair : query.split("&")) {
                        int eq = pair.indexOf("=");
                        if (eq > 0) {
                            String pName = pair.substring(0, eq);
                            String pValue = pair.substring(eq + 1);
                            String risk = scoreParamRisk(pName);
                            Map<String, Object> paramInfo = new LinkedHashMap<>();
                            paramInfo.put("name", pName);
                            paramInfo.put("location", "query");
                            paramInfo.put("sample_value", pValue);
                            paramInfo.put("risk", risk);
                            pageParams.add(paramInfo);
                            totalParams++;
                            if ("high".equals(risk)) highRiskParams++;
                        }
                    }
                }

                Map<String, Object> ep = new LinkedHashMap<>();
                ep.put("method", "GET");
                ep.put("path", pagePath);
                ep.put("parameters", pageParams);
                ep.put("title", title != null ? title : "");
                ep.put("status", status);
                ep.put("length", resp.body().length());

                int riskScore = scoreEndpointRisk(pagePath, pageParams, status);
                ep.put("risk_score", riskScore);
                ep.put("priority", riskScore >= 7 ? "critical" : riskScore >= 5 ? "high" : riskScore >= 3 ? "medium" : "low");
                endpoints.add(ep);

                Pattern linkPattern = Pattern.compile(
                    "(?:href|action)=[\"']([^\"'#]+)[\"']", Pattern.CASE_INSENSITIVE);
                Matcher linkMatcher = linkPattern.matcher(respBody);
                while (linkMatcher.find()) {
                    String link = linkMatcher.group(1);
                    if (link.startsWith("http") || link.startsWith("javascript") ||
                        link.startsWith("mailto") || link.startsWith("#")) continue;
                    if (!link.startsWith("/")) {
                        String basePath = pagePath.contains("/")
                            ? pagePath.substring(0, pagePath.lastIndexOf("/") + 1) : "/";
                        link = basePath + link;
                    }
                    while (link.contains("/./")) link = link.replace("/./", "/");
                    if (link.startsWith("./")) link = link.substring(2);
                    try { link = new java.net.URI(link).normalize().toString(); } catch (Exception ignored) {}
                    if (!visited.contains(link) && !queue.contains(link)) {
                        queue.add(link);
                    }
                }

                Pattern formPattern = Pattern.compile(
                    "<form[^>]*(?:action=[\"']([^\"']*)[\"'][^>]*method=[\"']([^\"']*)[\"']|method=[\"']([^\"']*)[\"'][^>]*action=[\"']([^\"']*)[\"'])[^>]*>(.*?)</form>",
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                Matcher formMatcher = formPattern.matcher(respBody);
                while (formMatcher.find()) {
                    String action = formMatcher.group(1) != null ? formMatcher.group(1) : formMatcher.group(4);
                    String formMethod = formMatcher.group(2) != null ? formMatcher.group(2).toUpperCase() : (formMatcher.group(3) != null ? formMatcher.group(3).toUpperCase() : "GET");
                    String formBody = formMatcher.group(5);

                    List<String> inputs = new ArrayList<>();
                    Pattern inputPattern = Pattern.compile(
                        "name=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
                    Matcher inputMatcher = inputPattern.matcher(formBody);
                    while (inputMatcher.find()) {
                        String inputName = inputMatcher.group(1);
                        inputs.add(inputName);
                        totalParams++;
                        if ("high".equals(scoreParamRisk(inputName))) highRiskParams++;
                    }

                    if (!action.isEmpty()) {
                        Map<String, Object> formInfo = new LinkedHashMap<>();
                        formInfo.put("action", action);
                        formInfo.put("method", formMethod);
                        formInfo.put("inputs", inputs);
                        formInfo.put("source_page", pagePath);
                        forms.add(formInfo);
                    }
                }
            }

            List<Map<String, Object>> targets = new ArrayList<>();
            for (Map<String, Object> ep : endpoints) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> epParams = (List<Map<String, Object>>) ep.get("parameters");
                if (epParams != null) {
                    for (Map<String, Object> p : epParams) {
                        String risk = (String) p.getOrDefault("risk", "low");
                        if ("high".equals(risk) || "medium".equals(risk)) {
                            Map<String, Object> t = new LinkedHashMap<>();
                            t.put("method", ep.get("method"));
                            t.put("path", ((String) ep.get("path")).split("\\?")[0]);
                            t.put("parameter", p.get("name"));
                            t.put("baseline_value", p.getOrDefault("sample_value", "1"));
                            t.put("location", p.getOrDefault("location", "query"));
                            targets.add(t);
                        }
                    }
                }
            }
            for (Map<String, Object> form : forms) {
                String action = (String) form.getOrDefault("action", "");
                String formMethod = (String) form.getOrDefault("method", "POST");
                @SuppressWarnings("unchecked")
                List<String> inputs = (List<String>) form.getOrDefault("inputs", List.of());
                for (String input : inputs) {
                    Map<String, Object> t = new LinkedHashMap<>();
                    t.put("method", formMethod);
                    t.put("path", action);
                    t.put("parameter", input);
                    t.put("baseline_value", "test");
                    t.put("location", "body");
                    targets.add(t);
                }
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("pages_crawled", visited.size());
            out.put("endpoints", endpoints);
            out.put("forms", forms);
            out.put("targets", targets);
            out.put("detected_tech", detectedTech);
            out.put("total_parameters", totalParams);
            out.put("high_risk_parameters", highRiskParams);
            out.put("probeable_targets", targets.size());

            ConfigTab.log("discover: " + visited.size() + " pages, " + totalParams + " params (" + highRiskParams + " high-risk)");
            sendJson(exchange, JsonUtil.toJson(out));
        }
    }

    private String scoreParamRisk(String name) {
        String lower = name.toLowerCase();
        if (lower.matches("(?:id|uid|pid|num|page|idx|index|user_id|account_id|order_id|file|path|item|template|include|url|src|doc|dir|load|read|cmd|exec|command)")) {
            return "high";
        }
        if (lower.matches("(?:search|q|query|name|title|comment|msg|text|input|value|keyword|email)")) {
            return "medium";
        }
        return "low";
    }

    private int scoreEndpointRisk(String path, List<Map<String, Object>> params, int status) {
        int score = 0;
        String lower = path.toLowerCase();

        if (lower.contains("/admin") || lower.contains("/debug") || lower.contains("/backup")) score += 4;
        else if (lower.contains("/api/") || lower.contains("/user") || lower.contains("/account")) score += 3;
        else if (lower.contains("/upload") || lower.contains("/export") || lower.contains("/download")) score += 3;
        else if (lower.contains("/login") || lower.contains("/register") || lower.contains("/search")) score += 2;
        else score += 1;

        int highRiskParams = 0;
        for (Map<String, Object> p : params) {
            String risk = (String) p.getOrDefault("risk", "low");
            if ("high".equals(risk)) highRiskParams++;
        }
        score += Math.min(highRiskParams * 2, 4);

        if (status == 500) score += 2;
        else if (status == 403 || status == 401) score += 1;

        return Math.min(score, 10);
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
