package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;

/**
 * POST /api/collaborator/payload       - generate a new Collaborator payload
 * GET  /api/collaborator/interactions   - poll for interactions
 * POST /api/collaborator/auto-test     - inject payload into a parameter and poll
 */
public class CollaboratorHandler extends BaseHandler {

    private final MontoyaApi api;
    private CollaboratorClient client;

    public CollaboratorHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();

        String method = exchange.getRequestMethod();

        if (path.equals("/api/collaborator/payload") && "POST".equalsIgnoreCase(method)) {
            handleGeneratePayload(exchange);
        } else if (path.equals("/api/collaborator/interactions") && "GET".equalsIgnoreCase(method)) {
            handleGetInteractions(exchange);
        } else if (path.equals("/api/collaborator/auto-test") && "POST".equalsIgnoreCase(method)) {
            handleAutoTest(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    private synchronized CollaboratorClient getClient() {
        if (client == null) {
            client = api.collaborator().createClient();
        }
        return client;
    }

    private void handleGeneratePayload(HttpExchange exchange) throws Exception {
        try {
            CollaboratorClient c = getClient();
            CollaboratorPayload payload = c.generatePayload();

            sendJson(exchange, JsonUtil.object(
                "payload", payload.toString(),
                "interaction_id", payload.id().toString(),
                "server", c.server().address()
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "Collaborator not available (requires Burp Professional): " + e.getMessage());
        }
    }

    /**
     * Auto-test: generate payload, inject into a parameter of a proxy history request, send, and poll.
     * Body: {"index": 42, "parameter": "url", "injection_point": "query|body|header", "poll_seconds": 5}
     */
    private void handleAutoTest(HttpExchange exchange) throws Exception {
        try {
            Map<String, Object> body = readJsonBody(exchange);
            Object indexObj = body.get("index");
            String paramName = (String) body.get("parameter");

            if (!(indexObj instanceof Number) || paramName == null || paramName.isEmpty()) {
                sendError(exchange, 400, "Required: 'index' (int) and 'parameter' (string)");
                return;
            }

            int index = ((Number) indexObj).intValue();
            String injectionPoint = (String) body.getOrDefault("injection_point", "query");
            int pollSeconds = body.get("poll_seconds") instanceof Number n ? n.intValue() : 5;
            pollSeconds = Math.min(pollSeconds, 15); // Cap at 15 seconds

            // Get the original request
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            if (index < 0 || index >= history.size()) {
                sendError(exchange, 404, "Index out of range");
                return;
            }

            // Generate collaborator payload
            CollaboratorClient c = getClient();
            CollaboratorPayload payload = c.generatePayload();
            String payloadUrl = payload.toString();

            // Modify the request with the collaborator payload
            HttpRequest original = history.get(index).finalRequest();
            HttpRequest modified = original;

            switch (injectionPoint.toLowerCase()) {
                case "query" -> {
                    // Replace parameter value in URL query string
                    String origUrl = original.url();
                    String newUrl = replaceQueryParam(origUrl, paramName, payloadUrl);
                    String newPath = extractPath(newUrl);
                    modified = modified.withPath(newPath);
                }
                case "body" -> {
                    // Replace parameter value in body
                    String origBody = original.bodyToString();
                    String newBody = replaceBodyParam(origBody, paramName, payloadUrl);
                    modified = modified.withBody(newBody);
                }
                case "header" -> {
                    modified = modified.withHeader(paramName, payloadUrl);
                }
                default -> {
                    sendError(exchange, 400, "injection_point must be 'query', 'body', or 'header'");
                    return;
                }
            }

            // Send the modified request
            HttpRequestResponse result = api.http().sendRequest(modified);
            int responseStatus = result.response() != null ? result.response().statusCode() : 0;

            // Wait and poll for interactions
            Thread.sleep(pollSeconds * 1000L);
            List<Interaction> interactions = c.getAllInteractions();

            List<Map<String, Object>> interactionItems = new ArrayList<>();
            for (Interaction interaction : interactions) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("type", interaction.type().toString());
                entry.put("timestamp", interaction.timeStamp().toString());
                entry.put("client_ip", interaction.clientIp().toString());
                entry.put("payload_id", interaction.id().toString());
                interactionItems.add(entry);
            }

            sendJson(exchange, JsonUtil.object(
                "payload_injected", payloadUrl,
                "parameter", paramName,
                "injection_point", injectionPoint,
                "response_status", responseStatus,
                "poll_seconds", pollSeconds,
                "interactions_found", interactionItems.size(),
                "interactions", interactionItems,
                "vulnerable", !interactionItems.isEmpty()
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "Auto-test failed (requires Burp Professional): " + e.getMessage());
        }
    }

    private String replaceQueryParam(String url, String paramName, String newValue) {
        try {
            java.net.URI uri = new java.net.URI(url);
            String query = uri.getRawQuery();
            if (query == null) {
                // Append parameter
                return url + "?" + paramName + "=" + java.net.URLEncoder.encode(newValue, "UTF-8");
            }
            StringBuilder newQuery = new StringBuilder();
            boolean replaced = false;
            for (String pair : query.split("&")) {
                if (newQuery.length() > 0) newQuery.append("&");
                int eq = pair.indexOf('=');
                String key = eq > 0 ? pair.substring(0, eq) : pair;
                if (key.equals(paramName)) {
                    newQuery.append(key).append("=").append(java.net.URLEncoder.encode(newValue, "UTF-8"));
                    replaced = true;
                } else {
                    newQuery.append(pair);
                }
            }
            if (!replaced) {
                newQuery.append("&").append(paramName).append("=").append(java.net.URLEncoder.encode(newValue, "UTF-8"));
            }
            return url.split("\\?")[0] + "?" + newQuery;
        } catch (Exception e) {
            return url;
        }
    }

    private String replaceBodyParam(String body, String paramName, String newValue) {
        if (body == null || body.isEmpty()) return paramName + "=" + newValue;
        try {
            StringBuilder newBody = new StringBuilder();
            boolean replaced = false;
            for (String pair : body.split("&")) {
                if (newBody.length() > 0) newBody.append("&");
                int eq = pair.indexOf('=');
                String key = eq > 0 ? pair.substring(0, eq) : pair;
                if (key.equals(paramName)) {
                    newBody.append(key).append("=").append(java.net.URLEncoder.encode(newValue, "UTF-8"));
                    replaced = true;
                } else {
                    newBody.append(pair);
                }
            }
            if (!replaced) {
                newBody.append("&").append(paramName).append("=").append(java.net.URLEncoder.encode(newValue, "UTF-8"));
            }
            return newBody.toString();
        } catch (Exception e) {
            return body;
        }
    }

    private String extractPath(String url) {
        try {
            java.net.URI uri = new java.net.URI(url);
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) path = "/";
            if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
            return path;
        } catch (Exception e) {
            return "/";
        }
    }

    private void handleGetInteractions(HttpExchange exchange) throws Exception {
        try {
            CollaboratorClient c = getClient();
            List<Interaction> interactions = c.getAllInteractions();

            List<Map<String, Object>> items = new ArrayList<>();
            for (Interaction interaction : interactions) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("type", interaction.type().toString());
                entry.put("timestamp", interaction.timeStamp().toString());
                entry.put("client_ip", interaction.clientIp().toString());
                entry.put("payload_id", interaction.id().toString());
                items.add(entry);
            }

            sendJson(exchange, JsonUtil.object(
                "total", items.size(),
                "interactions", items
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "Collaborator not available: " + e.getMessage());
        }
    }
}
