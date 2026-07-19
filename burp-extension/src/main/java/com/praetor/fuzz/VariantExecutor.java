package com.praetor.fuzz;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sends a single FuzzVariant through the Burp proxy tunnel and applies
 * grep-match / grep-extract / snippet capture against the response body.
 * Shared by both sequential and parallel fuzz paths so the ProxyTunnel
 * null-guard and timing are identical.
 */
public final class VariantExecutor {

    private final MontoyaApi api;

    public VariantExecutor(MontoyaApi api) {
        this.api = api;
    }

    public FuzzResult execute(int payloadIndex, FuzzVariant variant,
                              List<String> grepMatch, String grepExtract) {
        long startNanos = System.nanoTime();
        HttpRequestResponse reqResp = com.praetor.http.ProxyTunnel.sendOrFallback(api, variant.request);
        long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;

        HttpResponse resp = reqResp != null ? reqResp.response() : null;
        FuzzResult result = new FuzzResult();
        result.payloadIndex = payloadIndex;
        result.parameter = variant.paramName;
        result.payload = variant.payload;
        result.statusCode = resp != null ? resp.statusCode() : 0;
        result.responseLength = resp != null ? resp.body().length() : 0;
        result.responseTimeMs = elapsedMs;

        String respBody = resp != null ? resp.bodyToString() : "";
        if (!grepMatch.isEmpty()) {
            result.grepMatches = countGrepMatches(respBody, grepMatch);
        }
        if (grepExtract != null && !grepExtract.isEmpty()) {
            result.grepExtracted = extractPattern(respBody, grepExtract);
        }
        if (!grepMatch.isEmpty()) {
            result.responseSnippet = extractSnippet(respBody, grepMatch);
        }
        return result;
    }

    static Map<String, Integer> countGrepMatches(String responseBody, List<String> patterns) {
        Map<String, Integer> matches = new LinkedHashMap<>();
        String bodyLower = responseBody.toLowerCase();
        for (String pattern : patterns) {
            String patternLower = pattern.toLowerCase();
            int count = 0;
            int idx = 0;
            while ((idx = bodyLower.indexOf(patternLower, idx)) != -1) {
                count++;
                idx += patternLower.length();
            }
            if (count > 0) {
                matches.put(pattern, count);
            }
        }
        return matches;
    }

    static String extractPattern(String responseBody, String regex) {
        try {
            Pattern p = com.praetor.util.PatternCache.get(regex, Pattern.CASE_INSENSITIVE);
            Matcher m = p.matcher(responseBody);
            if (m.find()) {
                return m.group();
            }
        } catch (Exception ignored) {
            // Invalid regex — skip
        }
        return null;
    }

    static String extractSnippet(String responseBody, List<String> patterns) {
        String bodyLower = responseBody.toLowerCase();
        for (String pattern : patterns) {
            int idx = bodyLower.indexOf(pattern.toLowerCase());
            if (idx >= 0) {
                int start = Math.max(0, idx - 100);
                int end = Math.min(responseBody.length(), idx + pattern.length() + 100);
                String snippet = responseBody.substring(start, end);
                if (start > 0) snippet = "..." + snippet;
                if (end < responseBody.length()) snippet = snippet + "...";
                return snippet;
            }
        }
        return null;
    }
}
