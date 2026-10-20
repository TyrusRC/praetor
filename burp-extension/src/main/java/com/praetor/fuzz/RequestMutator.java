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
        if (contentType.contains("multipart/form-data")) {
            return modifyMultipartBody(request, paramName, payload, bodyStr, contentType);
        }
        if (contentType.contains("xml")) {
            return modifyXmlBody(request, paramName, payload, bodyStr);
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

    /** Replace a named part's value in a multipart/form-data body, or append a new part. */
    static HttpRequest modifyMultipartBody(HttpRequest request, String paramName, String payload,
                                           String bodyStr, String contentType) {
        int bIdx = contentType.indexOf("boundary=");
        if (bIdx < 0) return request.withBody(bodyStr);
        String boundary = contentType.substring(bIdx + 9).trim();
        if (boundary.startsWith("\"") && boundary.endsWith("\"")) {
            boundary = boundary.substring(1, boundary.length() - 1);
        }
        int semi = boundary.indexOf(';');
        if (semi >= 0) boundary = boundary.substring(0, semi).trim();

        String delim = "--" + boundary;
        String closing = delim + "--";
        String namePattern = "name=\"" + Pattern.quote(paramName) + "\"";

        String[] parts = bodyStr.split(Pattern.quote(delim));
        boolean replaced = false;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            if (i == 0 && part.trim().isEmpty()) {
                out.append(delim);
                continue;
            }
            if (part.startsWith("--")) {
                out.append(delim).append("--");
                continue;
            }
            if (!replaced && part.matches("(?s).*" + namePattern + ".*")) {
                int blank = part.indexOf("\r\n\r\n");
                if (blank < 0) blank = part.indexOf("\n\n");
                if (blank >= 0) {
                    String sep = part.charAt(blank) == '\r' ? "\r\n\r\n" : "\n\n";
                    String headers = part.substring(0, blank);
                    out.append(delim).append(headers).append(sep).append(payload).append("\r\n");
                    replaced = true;
                    continue;
                }
            }
            out.append(delim).append(part);
        }

        if (!replaced) {
            String body = out.toString();
            int ci = body.lastIndexOf(closing);
            if (ci >= 0) {
                String newPart = delim + "\r\nContent-Disposition: form-data; name=\"" + paramName + "\"\r\n\r\n"
                        + payload + "\r\n";
                body = body.substring(0, ci) + newPart + closing;
                return request.withBody(body);
            }
        }
        return request.withBody(out.toString());
    }

    /** Replace a named element's text or attribute value in an XML body. */
    static HttpRequest modifyXmlBody(HttpRequest request, String paramName, String payload, String bodyStr) {
        String escapedPayload = payload.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");

        String elemPattern = "(<" + Pattern.quote(paramName) + "(?:\\s[^>]*)?>)([^<]*?)(</"
                + Pattern.quote(paramName) + "\\s*>)";
        Matcher elemMatcher = Pattern.compile(elemPattern).matcher(bodyStr);
        if (elemMatcher.find()) {
            String newBody = bodyStr.substring(0, elemMatcher.start(2))
                    + escapedPayload
                    + bodyStr.substring(elemMatcher.end(2));
            return request.withBody(newBody);
        }

        String attrPattern = "(" + Pattern.quote(paramName) + "\\s*=\\s*\")([^\"]*?)(\")";
        Matcher attrMatcher = Pattern.compile(attrPattern).matcher(bodyStr);
        if (attrMatcher.find()) {
            String newBody = bodyStr.substring(0, attrMatcher.start(2))
                    + escapedPayload
                    + bodyStr.substring(attrMatcher.end(2));
            return request.withBody(newBody);
        }

        int lastClose = bodyStr.lastIndexOf("</");
        if (lastClose > 0) {
            String newBody = bodyStr.substring(0, lastClose)
                    + "<" + paramName + ">" + escapedPayload + "</" + paramName + ">\n"
                    + bodyStr.substring(lastClose);
            return request.withBody(newBody);
        }
        return request.withBody(bodyStr);
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
