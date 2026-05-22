package com.swissknife.attack;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Handles {@code POST /api/attack/auth-matrix}: tests endpoints across
 * named auth states (different sessions/tokens/cookies/headers) and flags
 * IDOR when a non-reference state's response closely matches the
 * reference (owner) state.
 *
 * Behaviour-preserving lift from AttackHandler.handleAuthMatrix.
 */
public final class AuthMatrixHandler {

    private final MontoyaApi api;

    public AuthMatrixHandler(MontoyaApi api) {
        this.api = api;
    }

    @SuppressWarnings("unchecked")
    public void handle(HttpExchange exchange, Map<String, Object> body) throws Exception {
        List<Map<String, Object>> endpoints = (List<Map<String, Object>>) body.get("endpoints");
        if (endpoints == null || endpoints.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'endpoints'");
            return;
        }

        Object authStatesObj = body.get("auth_states");
        if (!(authStatesObj instanceof Map<?, ?> authStatesRaw) || authStatesRaw.isEmpty()) {
            sendError(exchange, 400, "Missing or empty 'auth_states' (expected JSON object {state_name: {...}})");
            return;
        }
        Map<String, Object> authStates = (Map<String, Object>) authStatesRaw;

        // Determine base_url
        String baseUrl = (String) body.get("base_url");
        if (baseUrl == null || baseUrl.isBlank()) {
            // Try to get from first auth state's session
            for (var stateEntry : authStates.entrySet()) {
                Map<String, Object> stateConfig = (Map<String, Object>) stateEntry.getValue();
                String sessionName = (String) stateConfig.get("session");
                if (sessionName != null) {
                    Session session = SessionStore.get().getSession(sessionName);
                    if (session != null && !session.baseUrl.isEmpty()) {
                        baseUrl = session.baseUrl;
                        break;
                    }
                }
            }
        }
        if (baseUrl == null || baseUrl.isBlank()) {
            sendError(exchange, 400, "Cannot determine base_url: provide it or use a session with base_url set");
            return;
        }

        if (!AttackScope.requireInScope(api, exchange, baseUrl)) return;

        // Reference state: caller can specify which state's response is the
        // "owner" (the legitimate access). Defaults to first listed state for
        // backwards compat, but if the operator put the unauthenticated/anon
        // state first, every authenticated state would falsely flag IDOR. The
        // proper IDOR test is "user B sees user A's data" - `reference_state`
        // names user A explicitly.
        List<String> stateNames = new ArrayList<>(authStates.keySet());
        String referenceState = (String) body.get("reference_state");
        if (referenceState != null && !stateNames.contains(referenceState)) {
            sendError(exchange, 400, "reference_state '" + referenceState + "' not in auth_states");
            return;
        }
        if (referenceState != null) {
            stateNames.remove(referenceState);
            stateNames.add(0, referenceState);
        }
        // Warn (not block) if the first state's name suggests anonymity
        String firstStateName = stateNames.get(0);
        if (firstStateName.toLowerCase().matches(".*(anon|guest|public|unauth|noauth|no_auth).*")
            && referenceState == null) {
            // The handler still runs, but the result envelope carries a warning
            // so callers know the IDOR flag may be a false positive.
            api.logging().logToOutput(
                "AttackHandler.handleAuthMatrix: first auth state '" + firstStateName +
                "' looks unauthenticated; IDOR detection compares OTHER states against it. " +
                "Pass reference_state='<authenticated_state>' to fix.");
        }

        List<Map<String, Object>> matrix = new ArrayList<>();
        int totalRequests = 0;
        List<Map<String, Object>> potentialIssues = new ArrayList<>();

        for (Map<String, Object> endpoint : endpoints) {
            String method = (String) endpoint.getOrDefault("method", "GET");
            String endpointPath = (String) endpoint.getOrDefault("path", "/");
            String endpointBody = (String) endpoint.get("body");
            String url = baseUrl.endsWith("/") && endpointPath.startsWith("/")
                ? baseUrl.substring(0, baseUrl.length() - 1) + endpointPath
                : baseUrl + endpointPath;

            Map<String, Object> endpointResult = new LinkedHashMap<>();
            endpointResult.put("method", method);
            endpointResult.put("path", endpointPath);

            // Send request for each auth state - results keyed by state name
            Map<String, Object> stateResults = new LinkedHashMap<>();
            String firstBody = null;
            int firstStatus = 0;

            for (int i = 0; i < stateNames.size(); i++) {
                String stateName = stateNames.get(i);
                Map<String, Object> stateConfig = (Map<String, Object>) authStates.get(stateName);

                HttpRequestResponse result = sendWithAuthState(method, url, endpointBody, stateConfig);
                totalRequests++;

                Map<String, Object> sr = new LinkedHashMap<>();

                if (result != null && result.response() != null) {
                    HttpResponse resp = result.response();
                    int status = resp.statusCode();
                    int length = resp.body().length();
                    String respBody = resp.bodyToString();

                    sr.put("status", status);
                    sr.put("length", length);

                    if (i == 0) {
                        firstStatus = status;
                        firstBody = respBody;
                    } else if (firstBody == null) {
                        sr.put("note", "Baseline auth state failed; comparison skipped");
                    } else {
                        double similarity = calculateSimilarity(firstBody, respBody);
                        sr.put("similarity", Math.round(similarity * 100));

                        // Flag IDOR: same 2xx status + >90% body similarity
                        boolean bothSuccess = (firstStatus >= 200 && firstStatus < 300)
                            && (status >= 200 && status < 300);
                        if (bothSuccess && similarity > 0.9) {
                            sr.put("flag", "IDOR");
                            Map<String, Object> issue = new LinkedHashMap<>();
                            issue.put("type", "IDOR");
                            issue.put("endpoint", method + " " + endpointPath);
                            issue.put("auth_state", stateName);
                            issue.put("reference_state", stateNames.get(0));
                            issue.put("similarity", Math.round(similarity * 100));
                            potentialIssues.add(issue);
                        }
                    }
                } else {
                    sr.put("status", 0);
                    sr.put("error", "Request failed");
                }

                stateResults.put(stateName, sr);
            }

            endpointResult.put("results", stateResults);
            matrix.add(endpointResult);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("matrix", matrix);
        out.put("endpoints_tested", endpoints.size());
        out.put("auth_states_tested", stateNames.size());
        out.put("total_requests", totalRequests);
        out.put("potential_issues", potentialIssues);
        sendJson(exchange, JsonUtil.toJson(out));
    }

    // -- Helper: send request with auth state config --------------

    @SuppressWarnings("unchecked")
    private HttpRequestResponse sendWithAuthState(String method, String url, String body,
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

            return com.swissknife.http.ProxyTunnel.sendOrFallback(api, request);
        } catch (Exception e) {
            return null;
        }
    }

    // -- Helper: calculate string similarity ----------------------

    /**
     * Calculates similarity between two strings using length ratio and character sampling.
     * Returns a value between 0.0 (completely different) and 1.0 (identical).
     * Package-private so unit tests can exercise it without spinning up Burp.
     */
    double calculateSimilarity(String a, String b) {
        if (a == null && b == null) return 1.0;
        if (a == null || b == null) return 0.0;
        if (a.equals(b)) return 1.0;
        if (a.isEmpty() && b.isEmpty()) return 1.0;
        if (a.isEmpty() || b.isEmpty()) return 0.0;

        // Length similarity
        double lengthSimilarity = (double) Math.min(a.length(), b.length())
            / Math.max(a.length(), b.length());

        // Character sampling: sample 200 positions, count matches
        int sampleSize = 200;
        int minLen = Math.min(a.length(), b.length());
        int samplesToTake = Math.min(sampleSize, minLen);
        int matches = 0;

        if (samplesToTake > 0) {
            double step = (double) minLen / samplesToTake;
            for (int i = 0; i < samplesToTake; i++) {
                int pos = (int) (i * step);
                if (pos < a.length() && pos < b.length() && a.charAt(pos) == b.charAt(pos)) {
                    matches++;
                }
            }
        }

        double charSimilarity = samplesToTake > 0 ? (double) matches / samplesToTake : 0.0;

        double combined = (lengthSimilarity + charSimilarity) / 2.0;

        // Length-based penalty: if lengths differ by >20%, cap similarity at 0.7
        // to catch structural changes that sampling might miss
        if (lengthSimilarity < 0.8) {
            combined = Math.min(combined, 0.7);
        }

        return combined;
    }

    // -- Response envelope (duplicated across attack handlers; see A1) ----

}
