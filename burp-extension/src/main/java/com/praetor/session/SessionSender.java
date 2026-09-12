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

/** Executes a session request (build -> send via Burp -> follow redirects -> cookie jar),
 *  split out of SessionRequestExecutor so the handler stays under the line ceiling. */
final class SessionSender {

    private final MontoyaApi api;

    SessionSender(MontoyaApi api) {
        this.api = api;
    }

    HttpRequestResponse send(Session session, Map<String, Object> params) {
        Object methodObj = params.get("method");
        String method = (methodObj instanceof String s && !s.isBlank()) ? s : "GET";
        Object pathObj = params.get("path");
        String path = (pathObj instanceof String p && !p.isBlank()) ? p : "/";
        String url = (String) params.get("url");

        String fullUrl;
        if (url != null && !url.isBlank()) {
            fullUrl = url;
        } else if (!session.baseUrl.isEmpty()) {
            String base = session.baseUrl;
            if (base.endsWith("/") && path.startsWith("/")) {
                base = base.substring(0, base.length() - 1);
            }
            fullUrl = base + path;
        } else {
            fullUrl = path;
        }

        // Scope gate (Rule 1 HARD): all session-driven outbound goes through this.
        if (!ScopeGate.isInScopeQuiet(api, fullUrl)) {
            ConfigTab.log("session_request: dropped out-of-scope URL " + fullUrl);
            return null;
        }

        try {
            URI uri;
            try {
                uri = new URI(fullUrl);
            } catch (java.net.URISyntaxException e) {
                uri = SessionRequestHelpers.buildSafeUri(fullUrl);
            }
            String host = uri.getHost();
            int port = uri.getPort();
            boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());
            if (port == -1) port = isHttps ? 443 : 80;

            String requestPath = uri.getRawPath();
            if (requestPath == null || requestPath.isEmpty()) requestPath = "/";
            String rawQuery = uri.getRawQuery();
            if (rawQuery != null) {
                requestPath += "?" + rawQuery;
            } else {
                int qIdx = fullUrl.indexOf('?');
                if (qIdx > 0) {
                    String queryPart = fullUrl.substring(qIdx + 1);
                    if (!queryPart.isEmpty()) requestPath += "?" + queryPart;
                }
            }

            HttpService service = HttpService.httpService(host, port, isHttps);

            HttpRequest request = HttpRequest.httpRequest()
                .withMethod(method.toUpperCase())
                .withPath(requestPath)
                .withService(service)
                .withHeader("Host", host);

            for (var entry : session.headers.entrySet()) {
                request = request.withHeader(entry.getKey(), entry.getValue());
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> reqHeaders = (Map<String, Object>) params.get("headers");
            if (reqHeaders != null) {
                for (var entry : reqHeaders.entrySet()) {
                    request = request.withHeader(entry.getKey(), String.valueOf(entry.getValue()));
                }
            }

            if (!session.bearerToken.isEmpty()) {
                request = request.withHeader("Authorization", "Bearer " + session.bearerToken);
            } else if (!session.authUser.isEmpty()) {
                String creds = Base64.getEncoder().encodeToString(
                    (session.authUser + ":" + session.authPass).getBytes(StandardCharsets.UTF_8));
                request = request.withHeader("Authorization", "Basic " + creds);
            }

            Map<String, String> mergedCookies = new LinkedHashMap<>(session.cookies);
            @SuppressWarnings("unchecked")
            Map<String, Object> reqCookies = (Map<String, Object>) params.get("cookies");
            if (reqCookies != null) {
                reqCookies.forEach((k, v) -> mergedCookies.put(k, String.valueOf(v)));
            }
            if (!mergedCookies.isEmpty()) {
                StringBuilder cookieHeader = new StringBuilder();
                for (var entry : mergedCookies.entrySet()) {
                    if (cookieHeader.length() > 0) cookieHeader.append("; ");
                    cookieHeader.append(entry.getKey()).append("=").append(entry.getValue());
                }
                request = request.withHeader("Cookie", cookieHeader.toString());
            }

            request = SessionRequestHelpers.resolveBody(request, params, session.variables);

            HttpRequestResponse result = com.praetor.http.ProxyTunnel.sendOrFallback(api, request);

            Object followFlag = params.get("follow_redirects");
            boolean followRedirects = followFlag instanceof Boolean b && b;
            int maxRedirects = 10;
            int redirectCount = 0;

            while (followRedirects && result != null && result.response() != null && redirectCount < maxRedirects) {
                int statusCode = result.response().statusCode();
                if (statusCode < 300 || statusCode >= 400) break;

                String location = null;
                for (HttpHeader h : result.response().headers()) {
                    if ("Location".equalsIgnoreCase(h.name())) {
                        location = h.value();
                        break;
                    }
                }
                if (location == null || location.isEmpty()) break;

                if (location.startsWith("/")) {
                    location = (redirectCount == 0 ? uri.getScheme() : (isHttps ? "https" : "http"))
                        + "://" + host + (port != 80 && port != 443 ? ":" + port : "") + location;
                } else if (!location.startsWith("http")) {
                    String basePath = requestPath.contains("/") ? requestPath.substring(0, requestPath.lastIndexOf('/') + 1) : "/";
                    location = uri.getScheme() + "://" + host + (port != 80 && port != 443 ? ":" + port : "") + basePath + location;
                }

                SessionRequestHelpers.updateCookies(session, result);

                URI redirectUri = new URI(location);
                String redirPath = redirectUri.getRawPath();
                if (redirPath == null || redirPath.isEmpty()) redirPath = "/";
                if (redirectUri.getRawQuery() != null) redirPath += "?" + redirectUri.getRawQuery();

                String redirHost = redirectUri.getHost() != null ? redirectUri.getHost() : host;
                int redirPort = redirectUri.getPort() > 0 ? redirectUri.getPort() : port;
                boolean redirHttps = "https".equalsIgnoreCase(redirectUri.getScheme());

                String origMethod = result.request() != null ? result.request().method() : method;
                String redirMethod;
                boolean preserveBody;
                if (statusCode == 307 || statusCode == 308) {
                    redirMethod = origMethod;
                    preserveBody = true;
                } else if (statusCode == 303) {
                    redirMethod = "GET";
                    preserveBody = false;
                } else {
                    redirMethod = ("GET".equalsIgnoreCase(origMethod) || "HEAD".equalsIgnoreCase(origMethod)) ? origMethod : "GET";
                    preserveBody = !"GET".equalsIgnoreCase(redirMethod);
                }

                boolean sameOrigin = redirHost.equalsIgnoreCase(host)
                    && redirPort == port
                    && redirHttps == isHttps;

                HttpRequest redirReq = HttpRequest.httpRequest()
                    .withMethod(redirMethod)
                    .withPath(redirPath)
                    .withService(HttpService.httpService(redirHost, redirPort, redirHttps))
                    .withHeader("Host", redirHost);

                if (result.request() != null) {
                    for (HttpHeader h : result.request().headers()) {
                        String name = h.name();
                        if ("Host".equalsIgnoreCase(name) || "Content-Length".equalsIgnoreCase(name)) continue;
                        if (!sameOrigin && (
                                "Authorization".equalsIgnoreCase(name)
                                || "Cookie".equalsIgnoreCase(name)
                                || "Cookie2".equalsIgnoreCase(name)
                                || "Proxy-Authorization".equalsIgnoreCase(name)
                                || name.toLowerCase().startsWith("x-auth")
                                || name.toLowerCase().startsWith("x-api")
                                || name.toLowerCase().startsWith("x-csrf"))) {
                            continue;
                        }
                        redirReq = redirReq.withHeader(name, h.value());
                    }
                    if (preserveBody && result.request().body() != null && result.request().body().length() > 0) {
                        redirReq = redirReq.withBody(result.request().body());
                    }
                }

                if (sameOrigin && !session.cookies.isEmpty()) {
                    StringBuilder cb = new StringBuilder();
                    for (var e2 : session.cookies.entrySet()) {
                        if (cb.length() > 0) cb.append("; ");
                        cb.append(e2.getKey()).append("=").append(e2.getValue());
                    }
                    redirReq = redirReq.withHeader("Cookie", cb.toString());
                }

                result = com.praetor.http.ProxyTunnel.sendOrFallback(api, redirReq);
                host = redirHost;
                port = redirPort;
                isHttps = redirHttps;
                redirectCount++;
            }

            return result;
        } catch (Exception e) {
            return null;
        }
    }
}
