package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.ui.ConfigTab;
import com.swissknife.util.JsonUtil;

import java.net.URI;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Manages reusable request macros — recorded sequences of HTTP requests
 * with variable extraction and interpolation between steps.
 *
 * POST   /api/macro/create   — create a macro
 * POST   /api/macro/run      — execute a macro
 * GET    /api/macro/list     — list all macros
 * GET    /api/macro/{name}   — get macro definition
 * DELETE /api/macro/{name}   — delete a macro
 */
public class MacroHandler extends BaseHandler {

    private final MontoyaApi api;
    private final Map<String, Macro> macros = new ConcurrentHashMap<>();

    public MacroHandler(MontoyaApi api) {
        this.api = api;
    }

    // ── Models ────────────────────────────────────────────────────

    static class ExtractionRule {
        String name;
        String source; // "body" or "header"
        String pattern;
        int group;
    }

    static class MacroStep {
        String method;
        String url;
        Map<String, String> headers = new LinkedHashMap<>();
        String body;
        List<ExtractionRule> extractRules = new ArrayList<>();
    }

    static class Macro {
        String name;
        String description;
        List<MacroStep> steps = new ArrayList<>();
    }

    // ── Routing ───────────────────────────────────────────────────

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();

        switch (method.toUpperCase()) {
            case "POST" -> {
                Map<String, Object> body = readJsonBody(exchange);
                switch (path) {
                    case "/api/macro/create" -> handleCreate(exchange, body);
                    case "/api/macro/run" -> handleRun(exchange, body);
                    default -> {
                        // Check for POST to /api/macro/{name}/pause etc. — not needed, fall through
                        sendError(exchange, 404, "Not found");
                    }
                }
            }
            case "GET" -> {
                if ("/api/macro/list".equals(path)) {
                    handleList(exchange);
                } else {
                    // GET /api/macro/{name}
                    String name = pathSegment(exchange, 2); // api=0, macro=1, {name}=2
                    if (name != null && !name.equals("list")) {
                        handleGet(exchange, name);
                    } else {
                        sendError(exchange, 404, "Not found");
                    }
                }
            }
            case "DELETE" -> {
                // DELETE /api/macro/{name}
                String name = pathSegment(exchange, 2);
                if (name != null) {
                    handleDelete(exchange, name);
                } else {
                    sendError(exchange, 400, "Missing macro name in path");
                }
            }
            default -> sendError(exchange, 405, "Method not allowed");
        }
    }

    // ── POST /api/macro/create ────────────────────────────────────

    private void handleCreate(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String name = (String) body.get("name");
        if (name == null || name.isBlank()) {
            sendError(exchange, 400, "Missing 'name'");
            return;
        }

        String description = (String) body.getOrDefault("description", "");

        @SuppressWarnings("unchecked")
        List<Object> stepsRaw = (List<Object>) body.get("steps");
        if (stepsRaw == null || stepsRaw.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'steps'");
            return;
        }

        Macro macro = new Macro();
        macro.name = name;
        macro.description = description;

        for (Object stepObj : stepsRaw) {
            @SuppressWarnings("unchecked")
            Map<String, Object> stepMap = (Map<String, Object>) stepObj;
            MacroStep step = new MacroStep();
            step.method = (String) stepMap.getOrDefault("method", "GET");
            step.url = (String) stepMap.get("url");

            if (step.url == null || step.url.isBlank()) {
                sendError(exchange, 400, "Each step must have a 'url'");
                return;
            }

            // Parse headers
            @SuppressWarnings("unchecked")
            Map<String, Object> hdrs = (Map<String, Object>) stepMap.get("headers");
            if (hdrs != null) {
                hdrs.forEach((k, v) -> step.headers.put(k, String.valueOf(v)));
            }

            step.body = (String) stepMap.getOrDefault("body", "");

            // Parse extraction rules
            @SuppressWarnings("unchecked")
            List<Object> extractRaw = (List<Object>) stepMap.get("extract");
            if (extractRaw != null) {
                for (Object ruleObj : extractRaw) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> ruleMap = (Map<String, Object>) ruleObj;
                    ExtractionRule rule = new ExtractionRule();
                    rule.name = (String) ruleMap.get("name");
                    rule.source = (String) ruleMap.getOrDefault("source", "body");
                    rule.pattern = (String) ruleMap.get("pattern");
                    Object groupObj = ruleMap.get("group");
                    rule.group = groupObj instanceof Number n ? n.intValue() : 1;

                    if (rule.name == null || rule.pattern == null) {
                        sendError(exchange, 400, "Extraction rules need 'name' and 'pattern'");
                        return;
                    }
                    step.extractRules.add(rule);
                }
            }

            macro.steps.add(step);
        }

        macros.put(name, macro);
        ConfigTab.log("Macro created: " + name + " (" + macro.steps.size() + " steps)");

        sendJson(exchange, JsonUtil.object(
            "status", "ok",
            "name", name,
            "steps", macro.steps.size()
        ));
    }

    // ── POST /api/macro/run ───────────────────────────────────────

    private void handleRun(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String name = (String) body.get("name");
        if (name == null || name.isBlank()) {
            sendError(exchange, 400, "Missing 'name'");
            return;
        }

        Macro macro = macros.get(name);
        if (macro == null) {
            sendError(exchange, 404, "Macro not found: " + name);
            return;
        }

        // Initial variables from caller
        Map<String, String> variables = new LinkedHashMap<>();
        @SuppressWarnings("unchecked")
        Map<String, Object> initVars = (Map<String, Object>) body.get("variables");
        if (initVars != null) {
            initVars.forEach((k, v) -> variables.put(k, String.valueOf(v)));
        }

        List<Map<String, Object>> results = new ArrayList<>();
        int stepNum = 0;

        for (MacroStep step : macro.steps) {
            stepNum++;

            // Interpolate variables into url, headers, body
            String url = interpolate(step.url, variables);
            String reqBody = interpolate(step.body, variables);
            Map<String, String> headers = new LinkedHashMap<>();
            for (var entry : step.headers.entrySet()) {
                headers.put(entry.getKey(), interpolate(entry.getValue(), variables));
            }

            try {
                // Build and send HTTP request
                URI uri;
                try {
                    uri = new URI(url);
                } catch (java.net.URISyntaxException e) {
                    uri = buildSafeUri(url);
                }

                String host = uri.getHost();
                int port = uri.getPort();
                boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());
                if (port == -1) port = isHttps ? 443 : 80;

                String requestPath = uri.getRawPath();
                if (requestPath == null || requestPath.isEmpty()) requestPath = "/";
                String rawQuery = uri.getRawQuery();
                if (rawQuery != null) requestPath += "?" + rawQuery;

                HttpService service = HttpService.httpService(host, port, isHttps);

                HttpRequest request = HttpRequest.httpRequest()
                    .withMethod(step.method.toUpperCase())
                    .withPath(requestPath)
                    .withService(service)
                    .withHeader("Host", host);

                // Apply step headers
                for (var entry : headers.entrySet()) {
                    request = request.withHeader(entry.getKey(), entry.getValue());
                }

                // Apply body
                if (reqBody != null && !reqBody.isEmpty()) {
                    request = request.withBody(reqBody);
                }

                // Send request
                HttpRequestResponse result = com.swissknife.http.ProxyTunnel.sendOrFallback(api, request);
                HttpResponse response = result.response();
                int statusCode = response != null ? response.statusCode() : 0;

                ConfigTab.log("Macro " + name + " step " + stepNum + ": "
                    + step.method + " " + url + " -> " + statusCode);

                // Apply extraction rules
                if (response != null) {
                    for (ExtractionRule rule : step.extractRules) {
                        String extracted = applyExtraction(response, rule);
                        if (extracted != null) {
                            variables.put(rule.name, extracted);
                        }
                    }
                }

                Map<String, Object> stepResult = new LinkedHashMap<>();
                stepResult.put("step", stepNum);
                stepResult.put("status", statusCode);
                stepResult.put("url", url);
                stepResult.put("method", step.method);
                if (response != null) {
                    stepResult.put("response_length", response.bodyToString().length());
                }
                results.add(stepResult);

            } catch (Exception e) {
                Map<String, Object> stepResult = new LinkedHashMap<>();
                stepResult.put("step", stepNum);
                stepResult.put("status", 0);
                stepResult.put("url", url);
                stepResult.put("error", e.getMessage());
                results.add(stepResult);
                ConfigTab.log("Macro " + name + " step " + stepNum + " failed: " + e.getMessage());
                break;
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("name", name);
        out.put("steps_executed", results.size());
        out.put("variables", variables);
        out.put("results", results);
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── GET /api/macro/list ───────────────────────────────────────

    private void handleList(HttpExchange exchange) throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        for (Macro macro : macros.values()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", macro.name);
            item.put("description", macro.description);
            item.put("steps", macro.steps.size());
            list.add(item);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("macros", list);
        out.put("total_count", list.size());
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── GET /api/macro/{name} ─────────────────────────────────────

    private void handleGet(HttpExchange exchange, String name) throws Exception {
        Macro macro = macros.get(name);
        if (macro == null) {
            sendError(exchange, 404, "Macro not found: " + name);
            return;
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", macro.name);
        out.put("description", macro.description);

        List<Map<String, Object>> stepsList = new ArrayList<>();
        for (MacroStep step : macro.steps) {
            Map<String, Object> stepMap = new LinkedHashMap<>();
            stepMap.put("method", step.method);
            stepMap.put("url", step.url);
            if (!step.headers.isEmpty()) {
                stepMap.put("headers", new LinkedHashMap<>(step.headers));
            }
            if (step.body != null && !step.body.isEmpty()) {
                stepMap.put("body", step.body);
            }

            List<Map<String, Object>> extractList = new ArrayList<>();
            for (ExtractionRule rule : step.extractRules) {
                Map<String, Object> ruleMap = new LinkedHashMap<>();
                ruleMap.put("name", rule.name);
                ruleMap.put("source", rule.source);
                ruleMap.put("pattern", rule.pattern);
                ruleMap.put("group", rule.group);
                extractList.add(ruleMap);
            }
            if (!extractList.isEmpty()) {
                stepMap.put("extract", extractList);
            }

            stepsList.add(stepMap);
        }
        out.put("steps", stepsList);
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // ── DELETE /api/macro/{name} ──────────────────────────────────

    private void handleDelete(HttpExchange exchange, String name) throws Exception {
        Macro removed = macros.remove(name);
        if (removed == null) {
            sendError(exchange, 404, "Macro not found: " + name);
            return;
        }
        ConfigTab.log("Macro deleted: " + name);
        sendOk(exchange, "Macro '" + name + "' deleted");
    }

    // ── Helpers ───────────────────────────────────────────────────

    /**
     * Replace {{variable}} placeholders with values from the variables map.
     */
    private String interpolate(String template, Map<String, String> variables) {
        if (template == null || template.isEmpty() || variables.isEmpty()) {
            return template;
        }
        String result = template;
        for (var entry : variables.entrySet()) {
            result = result.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        return result;
    }

    /**
     * Apply an extraction rule to a response. Returns the matched value or null.
     */
    private String applyExtraction(HttpResponse response, ExtractionRule rule) {
        String text;
        if ("header".equalsIgnoreCase(rule.source)) {
            // Concatenate all response headers for matching
            StringBuilder sb = new StringBuilder();
            for (HttpHeader header : response.headers()) {
                sb.append(header.name()).append(": ").append(header.value()).append("\n");
            }
            text = sb.toString();
        } else {
            // Default: body
            text = response.bodyToString();
        }

        try {
            Pattern pattern = Pattern.compile(rule.pattern);
            Matcher matcher = pattern.matcher(text);
            if (matcher.find() && rule.group <= matcher.groupCount()) {
                return matcher.group(rule.group);
            }
        } catch (Exception e) {
            ConfigTab.log("Extraction rule '" + rule.name + "' regex error: " + e.getMessage());
        }
        return null;
    }

    /**
     * Build a URI from a URL string, handling unencoded special characters
     * by manually parsing scheme://host:port and treating the rest as raw path.
     */
    private URI buildSafeUri(String url) throws java.net.URISyntaxException {
        // Find scheme
        int schemeEnd = url.indexOf("://");
        if (schemeEnd < 0) {
            return new URI("http://" + url);
        }
        String scheme = url.substring(0, schemeEnd);
        String rest = url.substring(schemeEnd + 3);

        // Find host:port vs path
        int pathStart = rest.indexOf('/');
        String authority = pathStart >= 0 ? rest.substring(0, pathStart) : rest;
        String pathAndQuery = pathStart >= 0 ? rest.substring(pathStart) : "/";

        // Split query
        int qIdx = pathAndQuery.indexOf('?');
        String path = qIdx >= 0 ? pathAndQuery.substring(0, qIdx) : pathAndQuery;
        String query = qIdx >= 0 ? pathAndQuery.substring(qIdx + 1) : null;

        return new URI(scheme, authority, path, query, null);
    }

    /** Returns the stored macros map (for potential use by other handlers). */
    public Map<String, Macro> getMacros() {
        return macros;
    }
}
