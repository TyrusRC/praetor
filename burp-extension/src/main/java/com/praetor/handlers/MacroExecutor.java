package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.praetor.ui.ConfigTab;

import java.net.URI;
import java.util.*;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Executes a stored macro's step sequence, split out of MacroHandler so the
 * handler only routes. The Rule 1 scope gate is passed in as a predicate so the
 * exact BaseHandler.isInScopeQuiet check is preserved without weakening it.
 */
final class MacroExecutor {

    private final MontoyaApi api;
    private final Predicate<String> inScope;

    MacroExecutor(MontoyaApi api, Predicate<String> inScope) {
        this.api = api;
        this.inScope = inScope;
    }

    Map<String, Object> execute(MacroHandler.Macro macro, String name, Map<String, String> variables) {
        List<Map<String, Object>> results = new ArrayList<>();
        int stepNum = 0;

        for (MacroHandler.MacroStep step : macro.steps) {
            stepNum++;

            // Interpolate variables into url, headers, body
            String url = interpolate(step.url, variables);
            String reqBody = interpolate(step.body, variables);
            Map<String, String> headers = new LinkedHashMap<>();
            for (var entry : step.headers.entrySet()) {
                headers.put(entry.getKey(), interpolate(entry.getValue(), variables));
            }

            try {
                // Build and send HTTP request
                URI uri;
                try {
                    uri = new URI(url);
                } catch (java.net.URISyntaxException e) {
                    uri = buildSafeUri(url);
                }

                String host = uri.getHost();
                int port = uri.getPort();
                boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());
                if (port == -1) port = isHttps ? 443 : 80;

                String requestPath = uri.getRawPath();
                if (requestPath == null || requestPath.isEmpty()) requestPath = "/";
                String rawQuery = uri.getRawQuery();
                if (rawQuery != null) requestPath += "?" + rawQuery;

                // Scope gate (Rule 1 HARD): skip out-of-scope steps with a
                // recorded error rather than aborting the whole macro — macros
                // chain steps and the operator may have authored the rule
                // before scope was tightened.
                if (!inScope.test(url)) {
                    Map<String, Object> stepResult = new LinkedHashMap<>();
                    stepResult.put("step", stepNum);
                    stepResult.put("status", 0);
                    stepResult.put("url", url);
                    stepResult.put("error", "out_of_scope");
                    stepResult.put("hint", "Add the URL/host to Burp scope (configure_scope) before running this macro.");
                    results.add(stepResult);
                    continue;
                }

                HttpService service = HttpService.httpService(host, port, isHttps);

                HttpRequest request = HttpRequest.httpRequest()
                    .withMethod(step.method.toUpperCase())
                    .withPath(requestPath)
                    .withService(service)
                    .withHeader("Host", host);

                // Apply step headers
                for (var entry : headers.entrySet()) {
                    request = request.withHeader(entry.getKey(), entry.getValue());
                }

                // Apply body
                if (reqBody != null && !reqBody.isEmpty()) {
                    request = request.withBody(reqBody);
                }

                // Send request
                HttpRequestResponse result = com.praetor.http.ProxyTunnel.sendOrFallback(api, request);
                // Null-guard: proxy tunnel + fallback may both fail (DNS,
                // connection refused, target down). Treat as status=0 step
                // failure so the macro records the attempt without NPEing.
                HttpResponse response = result != null ? result.response() : null;
                int statusCode = response != null ? response.statusCode() : 0;

                ConfigTab.log("Macro " + name + " step " + stepNum + ": "
                    + step.method + " " + url + " -> " + statusCode);

                // Apply extraction rules
                if (response != null) {
                    for (MacroHandler.ExtractionRule rule : step.extractRules) {
                        String extracted = applyExtraction(response, rule);
                        if (extracted != null) {
                            variables.put(rule.name, extracted);
                        }
                    }
                }

                Map<String, Object> stepResult = new LinkedHashMap<>();
                stepResult.put("step", stepNum);
                stepResult.put("status", statusCode);
                stepResult.put("url", url);
                stepResult.put("method", step.method);
                if (response != null) {
                    stepResult.put("response_length", response.bodyToString().length());
                }
                results.add(stepResult);

            } catch (Exception e) {
                Map<String, Object> stepResult = new LinkedHashMap<>();
                stepResult.put("step", stepNum);
                stepResult.put("status", 0);
                stepResult.put("url", url);
                stepResult.put("error", e.getMessage());
                results.add(stepResult);
                ConfigTab.log("Macro " + name + " step " + stepNum + " failed: " + e.getMessage());
                break;
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("name", name);
        out.put("steps_executed", results.size());
        out.put("variables", variables);
        out.put("results", results);
        return out;
    }

    String interpolate(String template, Map<String, String> variables) {
        if (template == null || template.isEmpty() || variables.isEmpty()) {
            return template;
        }
        String result = template;
        for (var entry : variables.entrySet()) {
            result = result.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        return result;
    }

    /**
     * Apply an extraction rule to a response. Returns the matched value or null.
     */
    String applyExtraction(HttpResponse response, MacroHandler.ExtractionRule rule) {
        String text;
        if ("header".equalsIgnoreCase(rule.source)) {
            // Concatenate all response headers for matching
            StringBuilder sb = new StringBuilder();
            for (HttpHeader header : response.headers()) {
                sb.append(header.name()).append(": ").append(header.value()).append("\n");
            }
            text = sb.toString();
        } else {
            // Default: body
            text = response.bodyToString();
        }

        try {
            Pattern pattern = com.praetor.util.PatternCache.get(rule.pattern);
            Matcher matcher = pattern.matcher(text);
            if (matcher.find() && rule.group <= matcher.groupCount()) {
                return matcher.group(rule.group);
            }
        } catch (Exception e) {
            ConfigTab.log("Extraction rule '" + rule.name + "' regex error: " + e.getMessage());
        }
        return null;
    }

    /**
     * Build a URI from a URL string, handling unencoded special characters
     * by manually parsing scheme://host:port and treating the rest as raw path.
     */
    URI buildSafeUri(String url) throws java.net.URISyntaxException {
        // Find scheme
        int schemeEnd = url.indexOf("://");
        if (schemeEnd < 0) {
            return new URI("http://" + url);
        }
        String scheme = url.substring(0, schemeEnd);
        String rest = url.substring(schemeEnd + 3);

        // Find host:port vs path
        int pathStart = rest.indexOf('/');
        String authority = pathStart >= 0 ? rest.substring(0, pathStart) : rest;
        String pathAndQuery = pathStart >= 0 ? rest.substring(pathStart) : "/";

        // Split query
        int qIdx = pathAndQuery.indexOf('?');
        String path = qIdx >= 0 ? pathAndQuery.substring(0, qIdx) : pathAndQuery;
        String query = qIdx >= 0 ? pathAndQuery.substring(qIdx + 1) : null;

        return new URI(scheme, authority, path, query, null);
    }

    /** Returns the stored macros map (for potential use by other handlers). */
}
