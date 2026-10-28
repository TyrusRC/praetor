package com.praetor.util;

import burp.api.montoya.http.message.HttpHeader;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Shared HTTP helpers — extracted from duplicated methods across handlers. */
public final class HttpHelpers {

    private HttpHelpers() {}

    /** Extract path + query from a URL string. Returns "/" on parse failure. */
    public static String extractPath(String url) {
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

    /** Convert Montoya HttpHeader list to JSON-friendly list of {name, value} maps. */
    public static List<Map<String, Object>> headersToList(List<HttpHeader> headers) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (HttpHeader h : headers) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", h.name());
            m.put("value", h.value());
            list.add(m);
        }
        return list;
    }
}
