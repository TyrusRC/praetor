package com.praetor.handlers.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.praetor.attack.AttackScope;
import com.praetor.http.HttpExchange;
import static com.praetor.http.HttpResponses.sendError;
import static com.praetor.http.HttpResponses.sendJson;
import com.praetor.util.JsonUtil;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Curl-like request executor. Handles redirect following with RFC 7231/7538
 * method/body preservation, Basic auth, Bearer tokens, cookies, and content-type
 * shortcuts (json / data / body). Routed through Burp's proxy so traffic is
 * captured.
 *
 * Extracted from HttpSendHandler.handleCurl (was ~234 lines of one method).
 */
public final class CurlSender {

    private final MontoyaApi api;

    public CurlSender(MontoyaApi api) {
        this.api = api;
    }

    @SuppressWarnings("unchecked")
    public void handle(HttpExchange exchange, Map<String, Object> body) throws Exception {
        String method = (String) body.getOrDefault("method", "GET");
        String url = (String) body.get("url");

        if (url == null || url.isEmpty()) {
            sendError(exchange, 400, "Missing 'url'");
            return;
        }

        if (!AttackScope.requireInScope(api, exchange, url)) return;

        boolean followRedirects = body.get("follow_redirects") instanceof Boolean b ? b : true;
        int maxRedirects = body.get("max_redirects") instanceof Number n ? n.intValue() : 10;

        HttpRequest request = HttpRequest.httpRequest()
            .withMethod(method.toUpperCase())
            .withPath(extractPath(url));

        HttpService service = HttpService.httpService(url);
        request = request.withService(service);
        request = request.withHeader("Host", service.host());

        Map<String, Object> headers = (Map<String, Object>) body.get("headers");
        if (headers != null) {
            for (var entry : headers.entrySet()) {
                request = request.withHeader(entry.getKey(), String.valueOf(entry.getValue()));
            }
        }

        String authUser = (String) body.get("auth_user");
        String authPass = (String) body.get("auth_pass");
        if (authUser != null && authPass != null) {
            String credentials = Base64.getEncoder().encodeToString(
                (authUser + ":" + authPass).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            request = request.withHeader("Authorization", "Basic " + credentials);
        }

        String bearerToken = (String) body.get("bearer_token");
        if (bearerToken != null) {
            request = request.withHeader("Authorization", "Bearer " + bearerToken);
        }

        // Cookie jar carried across redirects: seeded from the caller's
        // cookies, then merged with each hop's Set-Cookie so an auth cookie a
        // 302 sets reaches the followed request. A verbatim Cookie-header copy
        // (the old behavior) dropped it — a login POST that 302s to
        // /my-account then bounced back to /login.
        Map<String, String> cookieJar = new LinkedHashMap<>();
        Map<String, Object> cookies = (Map<String, Object>) body.get("cookies");
        if (cookies != null && !cookies.isEmpty()) {
            for (var entry : cookies.entrySet()) {
                cookieJar.put(entry.getKey(), String.valueOf(entry.getValue()));
            }
            request = request.withHeader("Cookie", renderCookieHeader(cookieJar));
        }

        Map<String, Object> jsonBody = (Map<String, Object>) body.get("json");
        if (jsonBody != null) {
            request = request.withHeader("Content-Type", "application/json");
            request = request.withBody(JsonUtil.toJson(jsonBody));
        } else {
            String data = (String) body.get("data");
            if (data != null && !data.isEmpty()) {
                if (!hasHeader(headers, "Content-Type")) {
                    request = request.withHeader("Content-Type", "application/x-www-form-urlencoded");
                }
                request = request.withBody(data);
            } else {
                String reqBody = (String) body.get("body");
                if (reqBody != null && !reqBody.isEmpty()) {
                    request = request.withBody(reqBody);
                }
            }
        }

        List<Map<String, Object>> redirectChain = new ArrayList<>();
        int preSize = api.proxy().history().size();
        HttpRequestResponse result = com.praetor.http.ProxyTunnel.sendOrFallback(api, request);
        if (result == null) {
            // Both proxy tunnel and direct fallback returned nothing — surface
            // the real cause (UnknownHost / ConnectException / Read timed out)
            // captured by ProxyTunnel.LAST_SEND_ERROR instead of an opaque
            // "No response from target".
            String why = com.praetor.http.ProxyTunnel.lastSendError();
            String hint = why.contains("UnknownHost") || why.contains("UnresolvedAddress")
                ? "Verify the hostname is reachable and DNS resolves from Burp's host."
                : why.contains("ConnectException") || why.contains("refused")
                ? "Target refused the connection — check the port and that the service is up."
                : why.contains("Read timed out") || why.contains("Socket")
                ? "Target accepted the connection but stopped responding — check Burp logs."
                : "Check the Burp proxy listener at 127.0.0.1:8080 and the target URL.";
            sendError(exchange, 502,
                "No response from target" + (why.isEmpty() ? "" : " — " + why),
                "send_failed", hint);
            return;
        }
        // The PoC is the ORIGINAL request; the redirect loop below reassigns
        // `result` to the final hop, so keep a handle on the first exchange for
        // the send_ref evidence store (which cites the payload-carrying request).
        HttpRequestResponse originalResult = result;
        int redirectCount = 0;

        while (followRedirects && redirectCount < maxRedirects && result.response() != null) {
            int status = result.response().statusCode();
            if (status < 300 || status >= 400) break;

            String location = null;
            for (HttpHeader h : result.response().headers()) {
                if ("Location".equalsIgnoreCase(h.name())) {
                    location = h.value();
                    break;
                }
            }
            if (location == null) break;

            Map<String, Object> hop = new LinkedHashMap<>();
            hop.put("status", status);
            hop.put("location", location);
            redirectChain.add(hop);

            if (!location.startsWith("http")) {
                String base = service.secure() ? "https" : "http";
                String baseUri = base + "://" + service.host()
                    + (service.port() != 80 && service.port() != 443 ? ":" + service.port() : "")
                    + extractPath(result.request() != null ? result.request().url() : "/");
                try {
                    location = new java.net.URI(baseUri).resolve(location).toString();
                } catch (Exception e) {
                    location = base + "://" + service.host()
                        + (service.port() != 80 && service.port() != 443 ? ":" + service.port() : "")
                        + location;
                }
            }

            // RFC 7231/7538: 301/302/303 may downgrade to GET;
            //                307/308 MUST preserve the original method and body.
            HttpService nextService = HttpService.httpService(location);
            String nextMethod;
            boolean preserveBody;
            if (status == 307 || status == 308) {
                nextMethod = result.request() != null ? result.request().method() : "GET";
                preserveBody = true;
            } else if (status == 303) {
                nextMethod = "GET";
                preserveBody = false;
            } else {
                String origMethod = result.request() != null ? result.request().method() : "GET";
                nextMethod = ("GET".equalsIgnoreCase(origMethod) || "HEAD".equalsIgnoreCase(origMethod)) ? origMethod : "GET";
                preserveBody = !"GET".equalsIgnoreCase(nextMethod);
            }

            HttpRequest nextRequest = HttpRequest.httpRequest()
                .withMethod(nextMethod)
                .withPath(extractPath(location))
                .withService(nextService)
                .withHeader("Host", nextService.host());

            // Cross-origin redirect strips Authorization (and Cookie); same-origin keeps them.
            boolean sameOrigin = result.request() != null
                && result.request().httpService() != null
                && nextService.host().equalsIgnoreCase(result.request().httpService().host())
                && nextService.port() == result.request().httpService().port()
                && nextService.secure() == result.request().httpService().secure();

            // Merge this hop's Set-Cookie into the jar before carrying cookies
            // forward — the auth cookie a 302 sets must reach the next request.
            List<String> setCookies = new ArrayList<>();
            if (result.response() != null) {
                for (HttpHeader h : result.response().headers()) {
                    if ("Set-Cookie".equalsIgnoreCase(h.name())) setCookies.add(h.value());
                }
            }
            mergeSetCookieHeaders(cookieJar, setCookies);

            if (result.request() != null) {
                for (HttpHeader h : result.request().headers()) {
                    String name = h.name();
                    if ("Host".equalsIgnoreCase(name)) continue;
                    if ("Content-Length".equalsIgnoreCase(name)) continue;
                    if ("Cookie".equalsIgnoreCase(name)) continue; // rebuilt from the jar below
                    if (!sameOrigin && "Authorization".equalsIgnoreCase(name)) continue;
                    nextRequest = nextRequest.withHeader(name, h.value());
                }
                if (preserveBody && result.request().body() != null && result.request().body().length() > 0) {
                    nextRequest = nextRequest.withBody(result.request().body());
                }
            }
            // Same-origin keeps cookies (from the jar, so 302-set cookies win);
            // cross-origin drops them, matching the Authorization strip above.
            if (sameOrigin && !cookieJar.isEmpty()) {
                nextRequest = nextRequest.withHeader("Cookie", renderCookieHeader(cookieJar));
            }

            result = com.praetor.http.ProxyTunnel.sendOrFallback(api, nextRequest);
            service = nextService;
            redirectCount++;
        }

        Map<String, Object> out = new LinkedHashMap<>();
        HttpResponse resp = result.response();
        out.put("status_code", resp != null ? resp.statusCode() : 0);

        // Match the ORIGINAL request (the payload-carrying PoC) against the
        // entries added since preSize — not history.size()-1, which under
        // redirect following points at the final hop and under concurrent
        // traffic at another tool's request. `request` is never reassigned in
        // the redirect loop above, so it still holds the request we sent.
        int idx = com.praetor.util.ProxyHistoryLocator.locate(api, request, preSize);
        if (idx >= 0) {
            out.put("history_index", idx);
        } else {
            // Direct send (proxy-listener fallback): never entered proxy history,
            // so there is no proxy_history_index to cite. Store the ORIGINAL
            // exchange under a send_ref handle so the finding can still cite it as
            // evidence={'send_ref': '...'} (same path as HttpSendHandler).
            String sendRef = com.praetor.store.SendStore.get().store(originalResult);
            out.put("history_index", -1);
            out.put("send_ref", sendRef);
            out.put("history_note", "Request did not appear in proxy history (sent via HTTP client, "
                + "visible in Logger). Cite it as evidence={'send_ref': '" + sendRef + "'}; "
                + "fetch it back with GET /api/http/stored/" + sendRef + ".");
        }

        out.put("redirects_followed", redirectCount);
        if (!redirectChain.isEmpty()) {
            out.put("redirect_chain", redirectChain);
        }

        if (resp != null) {
            List<Map<String, Object>> respHeaders = new ArrayList<>();
            for (HttpHeader h : resp.headers()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", h.name());
                m.put("value", h.value());
                respHeaders.add(m);
            }
            out.put("response_headers", respHeaders);

            String respBody = resp.bodyToString();
            int cap = com.praetor.server.ResponseLimits.MAX_RESPONSE_BODY;
            if (respBody.length() > cap) {
                int half = cap / 2;
                respBody = respBody.substring(0, half)
                    + "\n\n[... TRUNCATED " + (respBody.length() - cap) + " chars ...]\n\n"
                    + respBody.substring(respBody.length() - half);
            }
            out.put("response_body", respBody);
            out.put("response_length", resp.body().length());
        }

        sendJson(exchange, JsonUtil.toJson(out));
    }

    /**
     * Merge Set-Cookie header values into a name-&gt;value jar. Only the
     * {@code name=value} pair before the first {@code ';'} is honored;
     * attributes (Path/Secure/HttpOnly/...) are ignored, and a later hop's
     * cookie overwrites a same-named earlier one.
     * NOTE: does not honor cookie deletion (Max-Age=0 / past Expires),
     * Domain/Path scoping, or the Secure flag — enough to carry an auth cookie
     * across a redirect. A full RFC 6265 jar is the upgrade path if a target
     * ever needs deletion or per-path cookies during a redirect chain.
     */
    static void mergeSetCookieHeaders(Map<String, String> jar, List<String> setCookieValues) {
        if (setCookieValues == null) return;
        for (String sc : setCookieValues) {
            if (sc == null) continue;
            int semi = sc.indexOf(';');
            String pair = semi >= 0 ? sc.substring(0, semi) : sc;
            int eq = pair.indexOf('=');
            if (eq <= 0) continue; // no name, or leading '=' -> malformed, skip
            String name = pair.substring(0, eq).trim();
            String value = pair.substring(eq + 1).trim();
            if (!name.isEmpty()) jar.put(name, value);
        }
    }

    /** Render a name-&gt;value jar into a {@code "a=b; c=d"} Cookie header value. */
    static String renderCookieHeader(Map<String, String> jar) {
        StringBuilder sb = new StringBuilder();
        for (var e : jar.entrySet()) {
            if (sb.length() > 0) sb.append("; ");
            sb.append(e.getKey()).append("=").append(e.getValue());
        }
        return sb.toString();
    }

    private static boolean hasHeader(Map<String, Object> headers, String name) {
        if (headers == null) return false;
        for (String key : headers.keySet()) {
            if (key.equalsIgnoreCase(name)) return true;
        }
        return false;
    }

    private static String extractPath(String url) {
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
}
