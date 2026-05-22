package com.swissknife.fuzz;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.swissknife.util.JsonUtil;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generates the request variants that drive a fuzz run.
 *
 * Four Intruder-style attack types:
 * <ul>
 *   <li>sniper — one param at a time, each payload</li>
 *   <li>battering_ram — same payload in every param at once</li>
 *   <li>pitchfork — payload[i] in param[i] (lockstep)</li>
 *   <li>cluster_bomb — cartesian product of payloads</li>
 * </ul>
 *
 * Mutates the base request via {@link #modifyRequest(HttpRequest, String, String, String)}
 * which dispatches by position (query / body / header / path / cookie).
 */
public final class VariantBuilder {

    private final int maxRequests;

    public VariantBuilder(int maxRequests) {
        this.maxRequests = maxRequests;
    }

    public List<FuzzVariant> generate(HttpRequest baseRequest,
                                      List<Map<String, Object>> parameters,
                                      String attackType) {
        List<FuzzVariant> variants = new ArrayList<>();
        switch (attackType) {
            case "battering_ram" -> generateBatteringRam(baseRequest, parameters, variants);
            case "pitchfork" -> generatePitchfork(baseRequest, parameters, variants);
            case "cluster_bomb" -> generateClusterBomb(baseRequest, parameters, variants);
            default -> generateSniper(baseRequest, parameters, variants);
        }
        return variants;
    }

    /** Sniper: one parameter at a time, each payload. */
    private void generateSniper(HttpRequest baseRequest,
                                List<Map<String, Object>> parameters,
                                List<FuzzVariant> variants) {
        for (Map<String, Object> param : parameters) {
            String name = (String) param.get("name");
            String position = (String) param.getOrDefault("position", "query");
            @SuppressWarnings("unchecked")
            List<String> payloads = toStringList((List<Object>) param.get("payloads"));

            for (String payload : payloads) {
                if (variants.size() >= maxRequests) return;
                HttpRequest modified = modifyRequest(baseRequest, name, position, payload);
                variants.add(new FuzzVariant(modified, name, payload));
            }
        }
    }

    /** Battering ram: same payload in all parameters simultaneously. */
    private void generateBatteringRam(HttpRequest baseRequest,
                                      List<Map<String, Object>> parameters,
                                      List<FuzzVariant> variants) {
        Set<String> allPayloads = new LinkedHashSet<>();
        for (Map<String, Object> param : parameters) {
            @SuppressWarnings("unchecked")
            List<String> payloads = toStringList((List<Object>) param.get("payloads"));
            allPayloads.addAll(payloads);
        }

        for (String payload : allPayloads) {
            if (variants.size() >= maxRequests) return;
            HttpRequest modified = baseRequest;
            StringBuilder paramNames = new StringBuilder();
            for (Map<String, Object> param : parameters) {
                String name = (String) param.get("name");
                String position = (String) param.getOrDefault("position", "query");
                modified = modifyRequest(modified, name, position, payload);
                if (paramNames.length() > 0) paramNames.append(",");
                paramNames.append(name);
            }
            variants.add(new FuzzVariant(modified, paramNames.toString(), payload));
        }
    }

    /** Pitchfork: parallel payload lists (payload[i] in param[i]). */
    private void generatePitchfork(HttpRequest baseRequest,
                                   List<Map<String, Object>> parameters,
                                   List<FuzzVariant> variants) {
        int minLen = Integer.MAX_VALUE;
        List<List<String>> allPayloads = new ArrayList<>();
        for (Map<String, Object> param : parameters) {
            @SuppressWarnings("unchecked")
            List<String> payloads = toStringList((List<Object>) param.get("payloads"));
            allPayloads.add(payloads);
            minLen = Math.min(minLen, payloads.size());
        }
        if (minLen == 0 || minLen == Integer.MAX_VALUE) return;

        for (int i = 0; i < minLen; i++) {
            if (variants.size() >= maxRequests) return;
            HttpRequest modified = baseRequest;
            StringBuilder paramNames = new StringBuilder();
            StringBuilder payloadDesc = new StringBuilder();
            for (int p = 0; p < parameters.size(); p++) {
                String name = (String) parameters.get(p).get("name");
                String position = (String) parameters.get(p).getOrDefault("position", "query");
                String payload = allPayloads.get(p).get(i);
                modified = modifyRequest(modified, name, position, payload);
                if (p > 0) { paramNames.append(","); payloadDesc.append(","); }
                paramNames.append(name);
                payloadDesc.append(payload);
            }
            variants.add(new FuzzVariant(modified, paramNames.toString(), payloadDesc.toString()));
        }
    }

    /** Cluster bomb: all combinations of all payloads across all parameters. */
    private void generateClusterBomb(HttpRequest baseRequest,
                                     List<Map<String, Object>> parameters,
                                     List<FuzzVariant> variants) {
        List<List<String>> allPayloads = new ArrayList<>();
        for (Map<String, Object> param : parameters) {
            @SuppressWarnings("unchecked")
            List<String> payloads = toStringList((List<Object>) param.get("payloads"));
            allPayloads.add(payloads);
        }

        int[] indices = new int[parameters.size()];
        long totalCombinationsLong = 1;
        for (List<String> payloads : allPayloads) {
            if (payloads.isEmpty()) return;
            totalCombinationsLong *= payloads.size();
            if (totalCombinationsLong > maxRequests) { totalCombinationsLong = maxRequests; break; }
        }
        int totalCombinations = (int) totalCombinationsLong;

        for (int combo = 0; combo < totalCombinations; combo++) {
            if (variants.size() >= maxRequests) return;

            HttpRequest modified = baseRequest;
            StringBuilder paramNames = new StringBuilder();
            StringBuilder payloadDesc = new StringBuilder();

            for (int p = 0; p < parameters.size(); p++) {
                String name = (String) parameters.get(p).get("name");
                String position = (String) parameters.get(p).getOrDefault("position", "query");
                String payload = allPayloads.get(p).get(indices[p]);
                modified = modifyRequest(modified, name, position, payload);
                if (p > 0) { paramNames.append(","); payloadDesc.append(","); }
                paramNames.append(name);
                payloadDesc.append(payload);
            }
            variants.add(new FuzzVariant(modified, paramNames.toString(), payloadDesc.toString()));

            // Odometer increment.
            for (int p = parameters.size() - 1; p >= 0; p--) {
                indices[p]++;
                if (indices[p] < allPayloads.get(p).size()) break;
                indices[p] = 0;
            }
        }
    }

    // ── Request modification ──────────────────────────────────

    private HttpRequest modifyRequest(HttpRequest request, String paramName, String position, String payload) {
        return switch (position) {
            case "query" -> modifyQueryParam(request, paramName, payload);
            case "body" -> modifyBodyParam(request, paramName, payload);
            case "header" -> request.withHeader(paramName, payload);
            case "path" -> modifyPathParam(request, paramName, payload);
            case "cookie" -> modifyCookie(request, paramName, payload);
            default -> modifyQueryParam(request, paramName, payload);
        };
    }

    private HttpRequest modifyQueryParam(HttpRequest request, String paramName, String payload) {
        String path = request.path();
        int qIdx = path.indexOf('?');
        String basePath = qIdx >= 0 ? path.substring(0, qIdx) : path;
        String queryString = qIdx >= 0 ? path.substring(qIdx + 1) : "";

        String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
        String encodedName = URLEncoder.encode(paramName, StandardCharsets.UTF_8);

        if (queryString.isEmpty()) {
            return request.withPath(basePath + "?" + encodedName + "=" + encodedPayload);
        }

        String[] pairs = queryString.split("&");
        boolean replaced = false;
        StringBuilder newQuery = new StringBuilder();
        for (String pair : pairs) {
            if (newQuery.length() > 0) newQuery.append("&");
            int eq = pair.indexOf('=');
            String key = eq >= 0 ? pair.substring(0, eq) : pair;
            if (key.equals(encodedName) || key.equals(paramName)) {
                newQuery.append(encodedName).append("=").append(encodedPayload);
                replaced = true;
            } else {
                newQuery.append(pair);
            }
        }
        if (!replaced) {
            newQuery.append("&").append(encodedName).append("=").append(encodedPayload);
        }

        return request.withPath(basePath + "?" + newQuery);
    }

    private HttpRequest modifyBodyParam(HttpRequest request, String paramName, String payload) {
        String bodyStr = request.bodyToString();

        String contentType = "";
        for (HttpHeader h : request.headers()) {
            if ("Content-Type".equalsIgnoreCase(h.name())) {
                contentType = h.value().toLowerCase();
                break;
            }
        }

        if (contentType.contains("application/json")) {
            return modifyJsonBody(request, paramName, payload, bodyStr);
        }

        String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
        String encodedName = URLEncoder.encode(paramName, StandardCharsets.UTF_8);

        if (bodyStr == null || bodyStr.isEmpty()) {
            return request.withBody(encodedName + "=" + encodedPayload);
        }

        String[] pairs = bodyStr.split("&");
        boolean replaced = false;
        StringBuilder newBody = new StringBuilder();
        for (String pair : pairs) {
            if (newBody.length() > 0) newBody.append("&");
            int eq = pair.indexOf('=');
            String key = eq >= 0 ? pair.substring(0, eq) : pair;
            if (key.equals(encodedName) || key.equals(paramName)) {
                newBody.append(encodedName).append("=").append(encodedPayload);
                replaced = true;
            } else {
                newBody.append(pair);
            }
        }
        if (!replaced) {
            newBody.append("&").append(encodedName).append("=").append(encodedPayload);
        }

        return request.withBody(newBody.toString());
    }

    private HttpRequest modifyJsonBody(HttpRequest request, String paramName, String payload, String bodyStr) {
        String escaped = JsonUtil.escape(payload);
        String pattern = "\"" + Pattern.quote(paramName) + "\"\\s*:\\s*(?:\"[^\"]*\"|\\d+(?:\\.\\d+)?|true|false|null)";
        String replacement = "\"" + paramName + "\": \"" + escaped + "\"";

        String newBody = bodyStr.replaceFirst(pattern, Matcher.quoteReplacement(replacement));
        if (newBody.equals(bodyStr)) {
            int lastBrace = newBody.lastIndexOf('}');
            if (lastBrace > 0) {
                newBody = newBody.substring(0, lastBrace).stripTrailing();
                if (!newBody.endsWith("{")) newBody += ", ";
                newBody += "\"" + paramName + "\": \"" + escaped + "\"}";
            }
        }
        return request.withBody(newBody);
    }

    private HttpRequest modifyPathParam(HttpRequest request, String paramName, String payload) {
        String path = request.path();
        String modified = path.replace("{" + paramName + "}", URLEncoder.encode(payload, StandardCharsets.UTF_8));
        if (modified.equals(path)) {
            modified = path.replaceFirst(
                "(?i)/" + Pattern.quote(paramName) + "/([^/?]+)",
                "/" + paramName + "/" + URLEncoder.encode(payload, StandardCharsets.UTF_8)
            );
        }
        return request.withPath(modified);
    }

    private HttpRequest modifyCookie(HttpRequest request, String paramName, String payload) {
        String cookieHeader = "";
        for (HttpHeader h : request.headers()) {
            if ("Cookie".equalsIgnoreCase(h.name())) {
                cookieHeader = h.value();
                break;
            }
        }

        if (cookieHeader.isEmpty()) {
            return request.withHeader("Cookie", paramName + "=" + payload);
        }

        String[] cookies = cookieHeader.split(";\\s*");
        boolean replaced = false;
        StringBuilder newCookies = new StringBuilder();
        for (String cookie : cookies) {
            if (newCookies.length() > 0) newCookies.append("; ");
            int eq = cookie.indexOf('=');
            String name = eq >= 0 ? cookie.substring(0, eq).trim() : cookie.trim();
            if (name.equals(paramName)) {
                newCookies.append(paramName).append("=").append(payload);
                replaced = true;
            } else {
                newCookies.append(cookie.trim());
            }
        }
        if (!replaced) {
            newCookies.append("; ").append(paramName).append("=").append(payload);
        }

        return request.withHeader("Cookie", newCookies.toString());
    }

    static List<String> toStringList(List<Object> list) {
        if (list == null) return Collections.emptyList();
        List<String> result = new ArrayList<>();
        for (Object o : list) {
            result.add(String.valueOf(o));
        }
        return result;
    }
}
