package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.util.JsonUtil;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * POST /api/collaborator/payload       - generate a new Collaborator payload
 * GET  /api/collaborator/interactions   - poll for interactions
 * POST /api/collaborator/auto-test     - inject payload into a parameter and poll
 */
public class CollaboratorHandler extends BaseHandler {

    private final MontoyaApi api;

    // Burp's getAllInteractions() drains its buffer — each interaction is
    // returned exactly once, so a second poll loses the first poll's results.
    // Accumulate every drained interaction here so /interactions returns the
    // full history and repeated polling can't drop OOB evidence. Session-
    // scoped; ?clear=true resets it, ?new_only=true returns just this drain.
    private static final List<Map<String, Object>> SEEN =
        new java.util.concurrent.CopyOnWriteArrayList<>();

    public CollaboratorHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();

        String method = exchange.getRequestMethod();

        if (path.equals("/api/collaborator/payload") && "POST".equalsIgnoreCase(method)) {
            handleGeneratePayload(exchange);
        } else if (path.equals("/api/collaborator/interactions") && "GET".equalsIgnoreCase(method)) {
            handleGetInteractions(exchange);
        } else if (path.equals("/api/collaborator/auto-test") && "POST".equalsIgnoreCase(method)) {
            handleAutoTest(exchange);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    private CollaboratorClient getClient() {
        // Share the singleton with auto-probe / OOB matchers so a payload
        // generated here is observable everywhere via the same payload id.
        return com.praetor.collaborator.CollaboratorPool.getOrCreate(api);
    }

    private void handleGeneratePayload(HttpExchange exchange) throws Exception {
        try {
            CollaboratorClient c = getClient();
            CollaboratorPayload payload = c.generatePayload();

            sendJson(exchange, JsonUtil.object(
                "payload", payload.toString(),
                "interaction_id", payload.id().toString(),
                "server", c.server().address()
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "Collaborator not available (requires Burp Professional): " + e.getMessage());
        }
    }

    /**
     * Auto-test: generate payload, inject into a parameter of a proxy history request, send, and poll.
     * Body: {"index": 42, "parameter": "url", "injection_point": "query|body|header", "poll_seconds": 5}
     */
    private void handleAutoTest(HttpExchange exchange) throws Exception {
        try {
            Map<String, Object> body = readJsonBody(exchange);
            Object indexObj = body.get("index");
            String paramName = (String) body.get("parameter");

            if (!(indexObj instanceof Number) || paramName == null || paramName.isEmpty()) {
                sendError(exchange, 400, "Required: 'index' (int) and 'parameter' (string)");
                return;
            }

            int index = ((Number) indexObj).intValue();
            String injectionPoint = (String) body.getOrDefault("injection_point", "query");
            int pollSeconds = body.get("poll_seconds") instanceof Number n ? n.intValue() : 5;
            // Cap at 8 seconds. The handler thread is a worker out of a fixed
            // 6-thread pool; longer blocking poll windows starve the API.
            pollSeconds = Math.max(0, Math.min(pollSeconds, 8));

            // Get the original request
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            if (index < 0 || index >= history.size()) {
                sendError(exchange, 404, "Index out of range");
                return;
            }

            // Modify the request with the collaborator payload
            HttpRequest original = history.get(index).finalRequest();

            // Rule 1 (HARD) — auto_collaborator_test was previously firing
            // requests at whatever URL the captured proxy entry pointed at,
            // skipping the scope gate that every other outbound path now uses.
            if (!requireInScope(api, exchange, original.url())) return;

            // Generate collaborator payload
            CollaboratorClient c = getClient();
            CollaboratorPayload payload = c.generatePayload();
            String payloadUrl = payload.toString();

            HttpRequest modified = original;

            switch (injectionPoint.toLowerCase()) {
                case "query" -> {
                    // Replace parameter value in URL query string
                    String origUrl = original.url();
                    String newUrl = replaceQueryParam(origUrl, paramName, payloadUrl);
                    String newPath = extractPath(newUrl);
                    modified = modified.withPath(newPath);
                }
                case "body" -> {
                    // Replace parameter value in body
                    String origBody = original.bodyToString();
                    String newBody = replaceBodyParam(origBody, paramName, payloadUrl);
                    modified = modified.withBody(newBody);
                }
                case "header" -> {
                    modified = modified.withHeader(paramName, payloadUrl);
                }
                default -> {
                    sendError(exchange, 400, "injection_point must be 'query', 'body', or 'header'");
                    return;
                }
            }

            // Send the modified request
            HttpRequestResponse result = com.praetor.http.ProxyTunnel.sendOrFallback(api, modified);
            // Null-guard: ProxyTunnel can return null on tunnel + fallback
            // failure (e.g. DNS dropout). Don't NPE on .response().
            int responseStatus = (result != null && result.response() != null) ? result.response().statusCode() : 0;

            // Wait and poll for interactions
            Thread.sleep(pollSeconds * 1000L);
            List<Interaction> interactions = c.getAllInteractions();

            List<Map<String, Object>> interactionItems = new ArrayList<>();
            for (Interaction interaction : interactions) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("type", interaction.type().toString());
                entry.put("timestamp", interaction.timeStamp().toString());
                entry.put("client_ip", interaction.clientIp().toString());
                entry.put("payload_id", interaction.id().toString());
                interactionItems.add(entry);
            }

            sendJson(exchange, JsonUtil.object(
                "payload_injected", payloadUrl,
                "parameter", paramName,
                "injection_point", injectionPoint,
                "response_status", responseStatus,
                "poll_seconds", pollSeconds,
                "interactions_found", interactionItems.size(),
                "interactions", interactionItems,
                "vulnerable", !interactionItems.isEmpty()
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "Auto-test failed (requires Burp Professional): " + e.getMessage());
        }
    }

    private String replaceQueryParam(String url, String paramName, String newValue) {
        try {
            java.net.URI uri = new java.net.URI(url);
            String query = uri.getRawQuery();
            if (query == null) {
                // Append parameter
                return url + "?" + paramName + "=" + URLEncoder.encode(newValue, StandardCharsets.UTF_8);
            }
            StringBuilder newQuery = new StringBuilder();
            boolean replaced = false;
            for (String pair : query.split("&")) {
                if (newQuery.length() > 0) newQuery.append("&");
                int eq = pair.indexOf('=');
                String key = eq > 0 ? pair.substring(0, eq) : pair;
                if (key.equals(paramName)) {
                    newQuery.append(key).append("=").append(URLEncoder.encode(newValue, StandardCharsets.UTF_8));
                    replaced = true;
                } else {
                    newQuery.append(pair);
                }
            }
            if (!replaced) {
                newQuery.append("&").append(paramName).append("=").append(URLEncoder.encode(newValue, StandardCharsets.UTF_8));
            }
            return url.split("\\?")[0] + "?" + newQuery;
        } catch (Exception e) {
            return url;
        }
    }

    private String replaceBodyParam(String body, String paramName, String newValue) {
        if (body == null || body.isEmpty()) return paramName + "=" + newValue;
        try {
            StringBuilder newBody = new StringBuilder();
            boolean replaced = false;
            for (String pair : body.split("&")) {
                if (newBody.length() > 0) newBody.append("&");
                int eq = pair.indexOf('=');
                String key = eq > 0 ? pair.substring(0, eq) : pair;
                if (key.equals(paramName)) {
                    newBody.append(key).append("=").append(URLEncoder.encode(newValue, StandardCharsets.UTF_8));
                    replaced = true;
                } else {
                    newBody.append(pair);
                }
            }
            if (!replaced) {
                newBody.append("&").append(paramName).append("=").append(URLEncoder.encode(newValue, StandardCharsets.UTF_8));
            }
            return newBody.toString();
        } catch (Exception e) {
            return body;
        }
    }

    private String extractPath(String url) {
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

    private void handleGetInteractions(HttpExchange exchange) throws Exception {
        try {
            Map<String, String> params = parseQuery(exchange.getRequestURI().getRawQuery());
            if ("true".equalsIgnoreCase(params.get("clear"))) {
                SEEN.clear();
                sendJson(exchange, JsonUtil.object("total", 0, "interactions", new ArrayList<>(), "cleared", true));
                return;
            }
            boolean newOnly = "true".equalsIgnoreCase(params.get("new_only"));

            CollaboratorClient c = getClient();
            List<Interaction> interactions = c.getAllInteractions();

            // Convert this drain's interactions and retain them. getAllInteractions
            // returns each interaction once, so appending never duplicates.
            List<Map<String, Object>> fresh = new ArrayList<>();
            for (Interaction interaction : interactions) {
                fresh.add(toEntry(interaction));
            }
            SEEN.addAll(fresh);

            List<Map<String, Object>> items = newOnly ? fresh : new ArrayList<>(SEEN);
            sendJson(exchange, JsonUtil.object(
                "total", items.size(),
                "new_in_poll", fresh.size(),
                "interactions", items
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "Collaborator not available: " + e.getMessage());
        }
    }

    /**
     * Decode the QNAME (queried domain) from a raw DNS query message. The
     * name follows the 12-byte header as length-prefixed labels terminated by
     * a zero byte; a compression pointer (top two bits set) ends parsing.
     * Returns "" if the bytes are too short or malformed.
     */
    /** Convert one Collaborator interaction to the JSON entry map. */
    private static Map<String, Object> toEntry(Interaction interaction) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("type", interaction.type().toString());
        entry.put("timestamp", interaction.timeStamp().toString());
        entry.put("client_ip", interaction.clientIp().toString());
        entry.put("payload_id", interaction.id().toString());

        // HTTP details (blind SSRF/XXE evidence). Host header carries OOB-exfil
        // data placed in the subdomain (<data>.<id>.oastify.com).
        try {
            if (interaction.httpDetails().isPresent()) {
                var http = interaction.httpDetails().get();
                Map<String, Object> httpData = new LinkedHashMap<>();
                if (http.requestResponse() != null) {
                    var req = http.requestResponse().request();
                    if (req != null) {
                        httpData.put("method", req.method());
                        httpData.put("path", req.path());
                        String hostHdr = req.headerValue("Host");
                        if (hostHdr != null) httpData.put("host", hostHdr);
                        try { httpData.put("url", req.url()); } catch (Exception ignored2) {}
                        String reqBody = req.bodyToString();
                        if (reqBody.length() > 1000) reqBody = reqBody.substring(0, 1000) + "...";
                        httpData.put("request_body", reqBody);
                    }
                }
                entry.put("http_details", httpData);
            }
        } catch (Exception ignored) {}

        // DNS details (DNS exfiltration evidence). The QNAME carries the leaked
        // value in the subdomain — parse it so it is actually readable.
        try {
            if (interaction.dnsDetails().isPresent()) {
                var dns = interaction.dnsDetails().get();
                Map<String, Object> dnsData = new LinkedHashMap<>();
                dnsData.put("query_type", dns.queryType().toString());
                dnsData.put("description", dns.queryType().name() + " lookup");
                try {
                    String qname = extractDnsQname(dns.query());
                    if (!qname.isEmpty()) dnsData.put("query_name", qname);
                } catch (Exception ignored3) {}
                entry.put("dns_details", dnsData);
            }
        } catch (Exception ignored) {}

        return entry;
    }

    /** Parse a raw query string into a name→value map (last value wins). */
    private static Map<String, String> parseQuery(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) return out;
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) out.put(pair.substring(0, eq), pair.substring(eq + 1));
            else if (eq < 0 && !pair.isEmpty()) out.put(pair, "");
        }
        return out;
    }

    static String extractDnsQname(ByteArray q) {
        return q == null ? "" : extractDnsQname(q.getBytes());
    }

    /** Pure byte[] core (Montoya-free, unit-tested). */
    static String extractDnsQname(byte[] b) {
        if (b == null) return "";
        int len = b.length;
        int i = 12; // skip the fixed DNS header
        StringBuilder sb = new StringBuilder();
        while (i < len) {
            int l = b[i] & 0xFF;
            if (l == 0) break;
            if ((l & 0xC0) != 0) break; // compression pointer — not expected here
            i++;
            if (i + l > len) return "";
            if (sb.length() > 0) sb.append('.');
            for (int j = 0; j < l; j++) sb.append((char) (b[i + j] & 0xFF));
            i += l;
        }
        return sb.toString();
    }
}
