package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.swissknife.http.HttpExchange;
import com.swissknife.analysis.*;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * POST /api/analysis/parameters        - extract params from request at index
 * POST /api/analysis/forms             - extract HTML forms from response at index
 * POST /api/analysis/endpoints         - extract API endpoints from response at index
 * POST /api/analysis/injection-points  - identify potential injection points
 * POST /api/analysis/tech-stack        - detect tech stack from response headers/body
 * POST /api/analysis/js-secrets        - extract secrets/API keys from response body
 * POST /api/analysis/dom              - DOM structure and JS sink/source analysis
 * GET  /api/analysis/unique-endpoints  - deduplicated endpoints from proxy history
 */
public class AnalysisHandler extends BaseHandler {

    private final MontoyaApi api;

    public AnalysisHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();

        if ("GET".equalsIgnoreCase(exchange.getRequestMethod()) && path.equals("/api/analysis/unique-endpoints")) {
            handleUniqueEndpoints(exchange);
            return;
        }

        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        Map<String, Object> body = readJsonBody(exchange);
        int index = body.get("index") instanceof Number n ? n.intValue() : -1;

        if (index < 0) {
            sendError(exchange, 400, "Missing or invalid 'index'");
            return;
        }

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index >= history.size()) {
            sendError(exchange, 404, "Index out of range");
            return;
        }

        ProxyHttpRequestResponse item = history.get(index);
        HttpRequest req = item.finalRequest();
        HttpResponse resp = item.originalResponse();

        switch (path) {
            case "/api/analysis/parameters" -> {
                sendJson(exchange, JsonUtil.toJson(ParameterExtractor.extract(req)));
            }
            case "/api/analysis/forms" -> {
                if (resp == null) { sendError(exchange, 400, "No response available"); return; }
                sendJson(exchange, JsonUtil.toJson(FormExtractor.extract(resp.bodyToString())));
            }
            case "/api/analysis/endpoints" -> {
                if (resp == null) { sendError(exchange, 400, "No response available"); return; }
                sendJson(exchange, JsonUtil.toJson(EndpointExtractor.extract(resp.bodyToString(), req.url())));
            }
            case "/api/analysis/injection-points" -> {
                sendJson(exchange, JsonUtil.toJson(InjectionPointDetector.detect(req, resp)));
            }
            case "/api/analysis/tech-stack" -> {
                if (resp == null) { sendError(exchange, 400, "No response available"); return; }
                sendJson(exchange, JsonUtil.toJson(TechStackDetector.detect(resp)));
            }
            case "/api/analysis/js-secrets" -> {
                if (resp == null) { sendError(exchange, 400, "No response available"); return; }
                sendJson(exchange, JsonUtil.toJson(JsSecretExtractor.extract(resp.bodyToString())));
            }
            case "/api/analysis/dom" -> {
                if (resp == null) { sendError(exchange, 400, "No response available"); return; }
                sendJson(exchange, JsonUtil.toJson(DomAnalyzer.analyze(resp.bodyToString())));
            }
            case "/api/analysis/smart" -> {
                // Combined analysis: tech stack + injection points + forms + endpoints + secrets in one call
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("url", req.url());
                result.put("method", req.method());

                // Tech stack
                if (resp != null) {
                    result.put("tech_stack", TechStackDetector.detect(resp));
                }

                // Injection points
                result.put("injection_points", InjectionPointDetector.detect(req, resp));

                // Parameters
                result.put("parameters", ParameterExtractor.extract(req));

                if (resp != null) {
                    String bodyStr = resp.bodyToString();
                    String contentType = resp.headerValue("Content-Type") != null ? resp.headerValue("Content-Type") : "";

                    // Forms (only for HTML responses)
                    if (contentType.contains("html")) {
                        result.put("forms", FormExtractor.extract(bodyStr));
                        result.put("endpoints", EndpointExtractor.extract(bodyStr, req.url()));
                    }

                    // JS secrets (for JS and HTML responses)
                    if (contentType.contains("javascript") || contentType.contains("html")) {
                        Map<String, Object> secrets = JsSecretExtractor.extract(bodyStr);
                        @SuppressWarnings("unchecked")
                        List<Object> secretsList = (List<Object>) secrets.getOrDefault("secrets", List.of());
                        if (!secretsList.isEmpty()) {
                            result.put("secrets", secrets);
                        }
                    }
                }

                sendJson(exchange, JsonUtil.toJson(result));
            }
            default -> sendError(exchange, 404, "Not found");
        }
    }

    /**
     * Deduplicate endpoints from proxy history.
     * Groups by base path (ignoring query params), shows param names per endpoint.
     */
    private void handleUniqueEndpoints(HttpExchange exchange) throws Exception {
        Map<String, String> params = queryParams(exchange);
        String prefix = params.getOrDefault("prefix", "");
        int limit = intParam(params, "limit", 200);

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        // key: method + path, value: set of parameter names
        Map<String, Set<String>> endpointParams = new LinkedHashMap<>();
        Map<String, Integer> endpointStatus = new LinkedHashMap<>();

        for (ProxyHttpRequestResponse item : history) {
            HttpRequest req = item.finalRequest();
            String url = req.url();

            if (!prefix.isEmpty() && !url.startsWith(prefix)) continue;

            // Extract base path without query string
            String basePath;
            try {
                java.net.URI uri = new java.net.URI(url);
                basePath = uri.getScheme() + "://" + uri.getHost()
                    + (uri.getPort() > 0 && uri.getPort() != 80 && uri.getPort() != 443 ? ":" + uri.getPort() : "")
                    + uri.getPath();
            } catch (Exception e) {
                continue;
            }

            String key = req.method() + " " + basePath;
            endpointParams.computeIfAbsent(key, k -> new LinkedHashSet<>());

            // Collect parameter names
            for (var p : req.parameters()) {
                endpointParams.get(key).add(p.name() + " (" + p.type().toString().toLowerCase() + ")");
            }

            HttpResponse resp = item.originalResponse();
            if (resp != null && !endpointStatus.containsKey(key)) {
                endpointStatus.put(key, (int) resp.statusCode());
            }
        }

        List<Map<String, Object>> items = new ArrayList<>();
        int count = 0;
        for (var entry : endpointParams.entrySet()) {
            if (count >= limit) break;
            Map<String, Object> ep = new LinkedHashMap<>();
            ep.put("endpoint", entry.getKey());
            ep.put("parameters", new ArrayList<>(entry.getValue()));
            ep.put("status_code", endpointStatus.getOrDefault(entry.getKey(), 0));
            items.add(ep);
            count++;
        }

        sendJson(exchange, JsonUtil.object("total", items.size(), "endpoints", items));
    }
}
