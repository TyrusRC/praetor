package com.praetor.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.praetor.handlers.Session;
import com.praetor.http.HttpExchange;
import static com.praetor.http.HttpResponses.sendJson;
import static com.praetor.http.HttpResponses.sendError;
import com.praetor.server.BaseHandler;
import com.praetor.store.SessionStore;
import com.praetor.ui.ConfigTab;
import com.praetor.util.JsonUtil;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Pure request/response helpers for SessionSender (cookie jar, body resolution, safe URI). */
final class SessionRequestHelpers {

    private SessionRequestHelpers() {}

    static void updateCookies(Session session, HttpRequestResponse result) {
        HttpResponse resp = result.response();
        if (resp == null) return;

        for (HttpHeader header : resp.headers()) {
            if ("Set-Cookie".equalsIgnoreCase(header.name())) {
                String value = header.value();
                if (value == null || value.isEmpty()) continue;

                int semi = value.indexOf(';');
                String nameValue = semi > 0 ? value.substring(0, semi).trim() : value.trim();
                int eq = nameValue.indexOf('=');
                if (eq > 0) {
                    String cookieName = nameValue.substring(0, eq).trim();
                    String cookieVal = nameValue.substring(eq + 1).trim();
                    session.cookies.put(cookieName, cookieVal);
                }
            }
        }

        while (session.cookies.size() > 200) {
            String oldest = session.cookies.keySet().iterator().next();
            session.cookies.remove(oldest);
        }
    }

    // ── Body resolution ──

    static HttpRequest resolveBody(HttpRequest request, Map<String, Object> params, Map<String, String> variables) {
        @SuppressWarnings("unchecked")
        Map<String, Object> jsonBody = (Map<String, Object>) params.get("json_body");
        if (jsonBody != null) {
            request = request.withHeader("Content-Type", "application/json");
            return request.withBody(JsonUtil.toJson(jsonBody));
        }

        String data = (String) params.get("data");
        if (data != null && !data.isEmpty()) {
            request = request.withHeader("Content-Type", "application/x-www-form-urlencoded");
            return request.withBody(VariableExtractor.interpolateString(data, variables));
        }

        String body = (String) params.get("body");
        if (body != null && !body.isEmpty()) {
            return request.withBody(VariableExtractor.interpolateString(body, variables));
        }

        return request;
    }

    /**
     * Build a URI from a URL string that may contain unencoded special chars.
     */
    static URI buildSafeUri(String fullUrl) throws java.net.URISyntaxException {
        int schemeEnd = fullUrl.indexOf("://");
        if (schemeEnd < 0) throw new java.net.URISyntaxException(fullUrl, "No scheme");
        String scheme = fullUrl.substring(0, schemeEnd);
        String rest = fullUrl.substring(schemeEnd + 3);

        int pathStart = rest.indexOf('/');
        String hostPort = pathStart >= 0 ? rest.substring(0, pathStart) : rest;
        String pathAndQuery = pathStart >= 0 ? rest.substring(pathStart) : "/";

        String host;
        int port = -1;
        int colonIdx = hostPort.lastIndexOf(':');
        if (colonIdx > 0) {
            host = hostPort.substring(0, colonIdx);
            try { port = Integer.parseInt(hostPort.substring(colonIdx + 1)); }
            catch (NumberFormatException e) { host = hostPort; }
        } else {
            host = hostPort;
        }

        String path = pathAndQuery;
        String query = null;
        int qIdx = pathAndQuery.indexOf('?');
        if (qIdx >= 0) {
            path = pathAndQuery.substring(0, qIdx);
            query = pathAndQuery.substring(qIdx + 1);
        }

        String encodedPath = java.net.URLEncoder.encode(path, java.nio.charset.StandardCharsets.UTF_8)
                .replace("%2F", "/")
                .replace("+", "%20");

        return new URI(scheme, null, host, port, encodedPath, query, null);
    }
}
