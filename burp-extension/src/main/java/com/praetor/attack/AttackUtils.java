package com.praetor.attack;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.praetor.handlers.Session;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helpers shared across attack collaborator handlers. Lifted verbatim from
 * the pre-split AttackHandler. Promoted to {@code attack/} package because
 * {@link #buildBaseRequest} is used by both {@link RaceHandler} and
 * {@link HppHandler}, and {@link #buildCookieString} is used by all three
 * attack handlers (auth-matrix, race, hpp).
 *
 * Session-state reads are guarded under {@code synchronized(session)} so
 * the snapshot stays consistent — unchanged from the pre-split behaviour.
 */
public final class AttackUtils {

    private AttackUtils() { }

    /**
     * Builds an HttpRequest from a URI + method + session, copying session
     * headers, cookies, and bearer token onto the request. Behaviour-preserving
     * lift from AttackHandler.buildBaseRequest.
     */
    public static HttpRequest buildBaseRequest(URI uri, String method, Session session) {
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

        // Snapshot session state under synchronization
        String sessBearerToken;
        Map<String, String> sessHeaders;
        Map<String, String> sessCookies;
        synchronized (session) {
            sessBearerToken = session.bearerToken;
            sessHeaders = new LinkedHashMap<>(session.headers);
            sessCookies = new LinkedHashMap<>(session.cookies);
        }

        for (var entry : sessHeaders.entrySet()) {
            request = request.withHeader(entry.getKey(), entry.getValue());
        }

        if (!sessBearerToken.isEmpty()) {
            request = request.withHeader("Authorization", "Bearer " + sessBearerToken);
        }

        if (!sessCookies.isEmpty()) {
            request = request.withHeader("Cookie", buildCookieString(sessCookies));
        }

        return request;
    }

    /** Builds a {@code k1=v1; k2=v2} cookie header value from the supplied map. */
    public static String buildCookieString(Map<String, String> cookies) {
        StringBuilder sb = new StringBuilder();
        for (var entry : cookies.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }
        return sb.toString();
    }
}
