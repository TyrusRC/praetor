package com.swissknife.analysis;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;

/**
 * Extract all parameters from a request, grouped by location.
 */
public final class ParameterExtractor {

    private ParameterExtractor() {}

    public static Map<String, Object> extract(HttpRequest request) {
        Map<String, Object> result = new LinkedHashMap<>();

        List<Map<String, Object>> queryParams = new ArrayList<>();
        List<Map<String, Object>> bodyParams = new ArrayList<>();
        List<Map<String, Object>> cookieParams = new ArrayList<>();

        for (HttpParameter param : request.parameters()) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("name", param.name());
            p.put("value", param.value());
            p.put("type", param.type().toString());

            switch (param.type()) {
                case URL -> queryParams.add(p);
                case BODY -> bodyParams.add(p);
                case COOKIE -> cookieParams.add(p);
                default -> {} // ignore others
            }
        }

        result.put("url", request.url());
        result.put("method", request.method());
        result.put("query_parameters", queryParams);
        result.put("body_parameters", bodyParams);
        result.put("cookie_parameters", cookieParams);
        result.put("content_type", request.contentType() != null ? request.contentType().toString() : "none");
        result.put("total_parameters", queryParams.size() + bodyParams.size() + cookieParams.size());

        // Check for JSON body
        String body = request.bodyToString();
        if (body != null && !body.isEmpty()) {
            String ct = request.headerValue("Content-Type");
            if (ct != null && ct.contains("json")) {
                result.put("json_body", body.length() > 5000 ? body.substring(0, 5000) + "..." : body);
            }
        }

        return result;
    }
}
