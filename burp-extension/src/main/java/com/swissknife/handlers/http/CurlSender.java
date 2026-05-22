package com.swissknife.handlers.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.swissknife.attack.AttackScope;
import com.swissknife.http.HttpExchange;
import static com.swissknife.http.HttpResponses.sendError;
import static com.swissknife.http.HttpResponses.sendJson;
import com.swissknife.util.JsonUtil;

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

        Map<String, Object> cookies = (Map<String, Object>) body.get("cookies");
        if (cookies != null && !cookies.isEmpty()) {
            StringBuilder cookieHeader = new StringBuilder();
            for (var entry : cookies.entrySet()) {
                if (cookieHeader.length() > 0) cookieHeader.append("; ");
                cookieHeader.append(entry.getKey()).append("=").append(entry.getValue());
            }
            request = request.withHeader("Cookie", cookieHeader.toString());
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
        HttpRequestResponse result = com.swissknife.http.ProxyTunnel.sendOrFallback(api, request);
        if (result == null) {
            // Both proxy tunnel and direct fallback returned nothing — surface
            // the real cause (UnknownHost / ConnectException / Read timed out)
            // captured by ProxyTunnel.LAST_SEND_ERROR instead of an opaque
            // "No response from target".
            String why = com.swissknife.http.ProxyTunnel.lastSendError();
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

            if (result.request() != null) {
                for (HttpHeader h : result.request().headers()) {
                    String name = h.name();
                    if ("Host".equalsIgnoreCase(name)) continue;
                    if ("Content-Length".equalsIgnoreCase(name)) continue;
                    if (!sameOrigin && ("Authorization".equalsIgnoreCase(name) || "Cookie".equalsIgnoreCase(name))) continue;
                    nextRequest = nextRequest.withHeader(name, h.value());
                }
                if (preserveBody && result.request().body() != null && result.request().body().length() > 0) {
                    nextRequest = nextRequest.withBody(result.request().body());
                }
            }

            result = com.swissknife.http.ProxyTunnel.sendOrFallback(api, nextRequest);
            service = nextService;
            redirectCount++;
        }

        Map<String, Object> out = new LinkedHashMap<>();
        HttpResponse resp = result.response();
        out.put("status_code", resp != null ? resp.statusCode() : 0);

        int postSize = api.proxy().history().size();
        if (postSize > preSize) {
            out.put("history_index", postSize - 1);
        } else {
            out.put("history_index", -1);
            out.put("history_note", "Request did not appear in proxy history (sent via HTTP client, visible in Logger)");
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
            int cap = com.swissknife.server.ResponseLimits.MAX_RESPONSE_BODY;
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
