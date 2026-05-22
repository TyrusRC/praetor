package com.swissknife.attack;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.swissknife.handlers.Session;
import com.swissknife.http.HttpExchange;
import static com.swissknife.http.HttpResponses.sendJson;
import static com.swissknife.http.HttpResponses.sendError;
import com.swissknife.store.SessionStore;
import com.swissknife.util.JsonUtil;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Handles {@code POST /api/attack/hpp}: HTTP parameter pollution. Sends a
 * baseline, then permutes the target parameter across query / body / both
 * locations with each polluted value, and flags anomalies (status delta or
 * length delta >20% vs baseline).
 *
 * Behaviour-preserving lift from AttackHandler.handleHpp.
 */
public final class HppHandler {

    private final MontoyaApi api;

    public HppHandler(MontoyaApi api) {
        this.api = api;
    }

    @SuppressWarnings("unchecked")
    public void handle(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String sessionName = (String) body.get("session");
        if (sessionName == null) {
            sendError(exchange, 400, "Missing 'session'");
            return;
        }

        Session session = SessionStore.get().getSession(sessionName);
        if (session == null) {
            sendError(exchange, 404, "Session not found: " + sessionName);
            return;
        }

        String basePath = (String) body.get("base_path");
        if (basePath == null || basePath.isBlank()) {
            sendError(exchange, 400, "Missing 'base_path'");
            return;
        }

        String parameter = (String) body.get("parameter");
        if (parameter == null || parameter.isBlank()) {
            sendError(exchange, 400, "Missing 'parameter'");
            return;
        }

        String originalValue = (String) body.get("original_value");
        if (originalValue == null) {
            sendError(exchange, 400, "Missing 'original_value'");
            return;
        }

        List<String> pollutedValues = (List<String>) body.get("polluted_values");
        if (pollutedValues == null || pollutedValues.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'polluted_values'");
            return;
        }

        List<String> locations = (List<String>) body.get("locations");
        if (locations == null || locations.isEmpty()) {
            locations = List.of("query", "body", "both");
        }

        String baseUrl = session.baseUrl;
        if (baseUrl.isEmpty()) {
            sendError(exchange, 400, "Session has no base_url set");
            return;
        }

        // Send baseline: original value in query
        String baselineUrl = buildUrl(baseUrl, basePath, parameter, originalValue);

        if (!AttackScope.requireInScope(api, exchange, baselineUrl)) return;
        HttpRequest baselineReq;
        try {
            URI uri = new URI(baselineUrl);
            baselineReq = AttackUtils.buildBaseRequest(uri, "GET", session);
        } catch (Exception e) {
            sendError(exchange, 400, "Failed to build baseline request: " + e.getMessage());
            return;
        }

        HttpRequestResponse baselineResult = com.swissknife.http.ProxyTunnel.sendOrFallback(api, baselineReq);
        int baselineStatus = 0;
        int baselineLength = 0;
        if (baselineResult != null && baselineResult.response() != null) {
            baselineStatus = baselineResult.response().statusCode();
            baselineLength = baselineResult.response().body().length();
        }

        // Test polluted variants
        List<Map<String, Object>> variantResults = new ArrayList<>();
        int anomaliesFound = 0;

        for (String pollutedValue : pollutedValues) {
            for (String location : locations) {
                Map<String, Object> variant = new LinkedHashMap<>();
                variant.put("polluted_value", pollutedValue);
                variant.put("payload", pollutedValue);
                variant.put("location", location);

                try {
                    HttpRequest variantReq = buildHppRequest(
                        baseUrl, basePath, parameter, originalValue, pollutedValue, location, session);

                    HttpRequestResponse variantResult = com.swissknife.http.ProxyTunnel.sendOrFallback(api, variantReq);

                    if (variantResult != null && variantResult.response() != null) {
                        HttpResponse resp = variantResult.response();
                        int status = resp.statusCode();
                        int length = resp.body().length();

                        variant.put("status", status);
                        variant.put("length", length);
                        variant.put("response_length", length);
                        variant.put("length_diff", Math.abs(length - baselineLength));

                        // Detect anomaly: status differs or length differs >20%
                        boolean statusDiffers = status != baselineStatus;
                        boolean lengthDiffers = baselineLength > 0
                            && Math.abs(length - baselineLength) > (baselineLength * 0.2);

                        if (statusDiffers || lengthDiffers) {
                            variant.put("anomaly", true);
                            if (statusDiffers) variant.put("status_differs", true);
                            if (lengthDiffers) variant.put("length_differs", true);
                            anomaliesFound++;
                        }
                    } else {
                        variant.put("status", 0);
                        variant.put("error", "No response");
                    }
                } catch (Exception e) {
                    variant.put("error", e.getMessage());
                }

                variantResults.add(variant);
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("baseline_status", baselineStatus);
        out.put("baseline_length", baselineLength);
        out.put("variants_tested", variantResults.size());
        out.put("results", variantResults);
        out.put("anomalies_found", anomaliesFound);
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // -- Helper: build HPP variant request ------------------------

    private HttpRequest buildHppRequest(String baseUrl, String basePath, String parameter,
                                         String originalValue, String pollutedValue,
                                         String location, Session session) throws Exception {
        String url;
        String body = null;

        switch (location) {
            case "query" -> {
                url = buildUrl(baseUrl, basePath, parameter, pollutedValue);
            }
            case "body" -> {
                url = buildUrl(baseUrl, basePath, null, null);
                body = java.net.URLEncoder.encode(parameter, StandardCharsets.UTF_8)
                    + "=" + java.net.URLEncoder.encode(pollutedValue, StandardCharsets.UTF_8);
            }
            case "both" -> {
                url = buildUrl(baseUrl, basePath, parameter, originalValue);
                body = java.net.URLEncoder.encode(parameter, StandardCharsets.UTF_8)
                    + "=" + java.net.URLEncoder.encode(pollutedValue, StandardCharsets.UTF_8);
            }
            default -> {
                url = buildUrl(baseUrl, basePath, parameter, pollutedValue);
            }
        }

        URI uri = new URI(url);
        HttpRequest request = AttackUtils.buildBaseRequest(uri, "GET", session);

        if (body != null) {
            request = request.withMethod("POST")
                .withHeader("Content-Type", "application/x-www-form-urlencoded")
                .withBody(body);
        }

        return request;
    }

    // -- Helper: build URL with query parameter -------------------
    // Package-private so unit tests can exercise URL composition.

    static String buildUrl(String baseUrl, String path, String param, String value) {
        String base = baseUrl.endsWith("/") && path.startsWith("/")
            ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String url = base + path;
        if (param != null && value != null) {
            url += "?" + java.net.URLEncoder.encode(param, StandardCharsets.UTF_8)
                + "=" + java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
        }
        return url;
    }

    // -- Response envelope (duplicated across attack handlers; see A1) ----

}
