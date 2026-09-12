package com.praetor.fuzz;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.praetor.util.JsonUtil;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Request-mutation helpers (query/body/json/path/cookie) split from VariantBuilder — pure, no builder state. */
final class RequestMutator {

    private RequestMutator() {}

    static HttpRequest modifyRequest(HttpRequest request, String paramName, String position, String payload) {
        return switch (position) {
            case "query" -> modifyQueryParam(request, paramName, payload);
            case "body" -> modifyBodyParam(request, paramName, payload);
            case "header" -> request.withHeader(paramName, payload);
            case "path" -> modifyPathParam(request, paramName, payload);
            case "cookie" -> modifyCookie(request, paramName, payload);
            default -> modifyQueryParam(request, paramName, payload);
        };
    }

    static HttpRequest modifyQueryParam(HttpRequest request, String paramName, String payload) {
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

    static HttpRequest modifyBodyParam(HttpRequest request, String paramName, String payload) {
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

    static HttpRequest modifyJsonBody(HttpRequest request, String paramName, String payload, String bodyStr) {
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

    static HttpRequest modifyPathParam(HttpRequest request, String paramName, String payload) {
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

    static HttpRequest modifyCookie(HttpRequest request, String paramName, String payload) {
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
