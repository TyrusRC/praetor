package com.praetor.attack;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.praetor.handlers.Session;
import com.praetor.store.SessionStore;
import com.praetor.util.JsonUtil;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Sends a request under a given auth-state config, split out of AuthMatrixHandler. */
final class AuthStateSender {

    private AuthStateSender() {}

    @SuppressWarnings("unchecked")
    static HttpRequestResponse send(MontoyaApi api, String method, String url, String body,
                                    Map<String, Object> stateConfig) {
        try {
            Object removeAuth = stateConfig.get("remove_auth");
            boolean noAuth = removeAuth instanceof Boolean b && b;

            URI uri = new URI(url);
            String host = uri.getHost();
            int port = uri.getPort();
            boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());
            if (port == -1) port = isHttps ? 443 : 80;

            String requestPath = uri.getRawPath();
            if (requestPath == null || requestPath.isEmpty()) requestPath = "/";
            if (uri.getRawQuery() != null) requestPath += "?" + uri.getRawQuery();

            HttpService service = HttpService.httpService(host, port, isHttps);

            HttpRequest request = HttpRequest.httpRequest()
                .withMethod(method.toUpperCase())
                .withPath(requestPath)
                .withService(service)
                .withHeader("Host", host);

            if (!noAuth) {
                // Apply session state if referenced
                String sessionName = (String) stateConfig.get("session");
                if (sessionName != null) {
                    Session session = SessionStore.get().getSession(sessionName);
                    if (session != null) {
                        // Snapshot session state under synchronization
                        String sessBearerToken;
                        Map<String, String> sessHeaders;
                        Map<String, String> sessCookies;
                        synchronized (session) {
                            sessBearerToken = session.bearerToken;
                            sessHeaders = new LinkedHashMap<>(session.headers);
                            sessCookies = new LinkedHashMap<>(session.cookies);
                        }
                        // Apply session headers
                        for (var entry : sessHeaders.entrySet()) {
                            request = request.withHeader(entry.getKey(), entry.getValue());
                        }
                        // Apply session cookies
                        if (!sessCookies.isEmpty()) {
                            request = request.withHeader("Cookie", AttackUtils.buildCookieString(sessCookies));
                        }
                        // Apply session bearer
                        if (!sessBearerToken.isEmpty()) {
                            request = request.withHeader("Authorization", "Bearer " + sessBearerToken);
                        }
                    }
                }

                // Override with explicit bearer_token
                String bearerToken = (String) stateConfig.get("bearer_token");
                if (bearerToken != null && !bearerToken.isEmpty()) {
                    request = request.withHeader("Authorization", "Bearer " + bearerToken);
                }

                // Override with explicit cookies
                Map<String, Object> cookies = (Map<String, Object>) stateConfig.get("cookies");
                if (cookies != null && !cookies.isEmpty()) {
                    Map<String, String> cookieMap = new LinkedHashMap<>();
                    cookies.forEach((k, v) -> cookieMap.put(k, String.valueOf(v)));
                    request = request.withHeader("Cookie", AttackUtils.buildCookieString(cookieMap));
                }

                // Override with explicit headers
                Map<String, Object> headers = (Map<String, Object>) stateConfig.get("headers");
                if (headers != null) {
                    for (var entry : headers.entrySet()) {
                        request = request.withHeader(entry.getKey(), String.valueOf(entry.getValue()));
                    }
                }
            }

            // Apply body if present
            if (body != null && !body.isEmpty()) {
                request = request.withBody(body);
            }

            return com.praetor.http.ProxyTunnel.sendOrFallback(api, request);
        } catch (Exception e) {
            return null;
        }
    }

    // -- Helper: calculate string similarity ----------------------
}
