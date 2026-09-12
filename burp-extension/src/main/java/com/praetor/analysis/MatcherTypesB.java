package com.praetor.analysis;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;

import java.util.*;
import java.util.regex.*;
import java.nio.charset.StandardCharsets;

import static com.praetor.analysis.MatcherEngine.compileCached;
import static com.praetor.analysis.MatcherEngine.countWords;
import static com.praetor.analysis.MatcherEngine.shapeFingerprint;
import static com.praetor.analysis.MatcherEngine.shapeFingerprintFor;
/** Second half of the matcher-type switch, split from MatcherTypes to stay under the line ceiling. */
final class MatcherTypesB {

    private MatcherTypesB() {}

    static boolean matchGroupB(String type, Map<String, Object> matcher, MatcherTypes.Ctx c, List<String> matchedDescriptions) {
        boolean matched = false;
        HttpResponse response = c.response();
        HttpResponse baselineResponse = c.baselineResponse();
        long responseTimeMs = c.responseTimeMs();
        String payload = c.payload();
        String body = c.body();
        String bodyLower = c.bodyLower();
        int status = c.status();
        int bodyLen = c.bodyLen();
        int baselineLen = c.baselineLen();
        switch (type) {
                case "reflection" -> {
                    if (payload != null && !payload.isEmpty()) {
                        if (body.contains(payload)) {
                            matched = true;
                            matchedDescriptions.add("reflection:raw");
                        } else {
                            String urlEnc = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8);
                            if (!urlEnc.equals(payload) && body.contains(urlEnc)) {
                                matched = true;
                                matchedDescriptions.add("reflection:url_encoded");
                            }
                        }
                        if (!matched) {
                            String htmlEnc = payload.replace("&", "&amp;").replace("<", "&lt;")
                                    .replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
                            if (!htmlEnc.equals(payload) && body.contains(htmlEnc)) {
                                matched = true;
                                matchedDescriptions.add("reflection:html_encoded");
                            }
                        }
                    }
                }
                case "word_count_diff" -> {
                    Number minDiff = (Number) matcher.get("min_diff");
                    if (minDiff != null && baselineResponse != null) {
                        int baseWords = countWords(baselineResponse.bodyToString());
                        int probeWords = countWords(body);
                        matched = Math.abs(probeWords - baseWords) >= minDiff.intValue();
                    }
                    if (matched) matchedDescriptions.add("word_count_diff:" + countWords(body));
                }
                case "differential_timing" -> {
                    Number minDiff = (Number) matcher.get("min_diff_ms");
                    // baseline_ms can be injected by the caller (e.g. handleAutoProbe) into the matcher map
                    Number baselineMs = (Number) matcher.get("baseline_ms");
                    if (minDiff != null && baselineMs != null) {
                        long diff = responseTimeMs - baselineMs.longValue();
                        matched = diff >= minDiff.longValue();
                    }
                    if (matched) matchedDescriptions.add("diff_timing:" + responseTimeMs + "ms");
                }
                case "header_added" -> {
                    // R10: matcher fires when a named header appears in probe but
                    // NOT in baseline. Use to detect Set-Cookie / Location / WWW-
                    // Authenticate appearing only on the malicious request.
                    if (baselineResponse != null) {
                        String hName = (String) matcher.get("name");
                        if (hName != null) {
                            boolean inBase = false, inProbe = false;
                            for (HttpHeader h : baselineResponse.headers())
                                if (hName.equalsIgnoreCase(h.name())) { inBase = true; break; }
                            for (HttpHeader h : response.headers())
                                if (hName.equalsIgnoreCase(h.name())) { inProbe = true; break; }
                            if (!inBase && inProbe) {
                                matched = true;
                                matchedDescriptions.add("header_added:" + hName);
                            }
                        }
                    }
                }
                case "header_removed" -> {
                    if (baselineResponse != null) {
                        String hName = (String) matcher.get("name");
                        if (hName != null) {
                            boolean inBase = false, inProbe = false;
                            for (HttpHeader h : baselineResponse.headers())
                                if (hName.equalsIgnoreCase(h.name())) { inBase = true; break; }
                            for (HttpHeader h : response.headers())
                                if (hName.equalsIgnoreCase(h.name())) { inProbe = true; break; }
                            if (inBase && !inProbe) {
                                matched = true;
                                matchedDescriptions.add("header_removed:" + hName);
                            }
                        }
                    }
                }
                case "mime_changes" -> {
                    // R10: detect Content-Type shift between baseline and probe.
                    // Catches XSS via JSON-vs-HTML context confusion, file-upload
                    // MIME mismatches, OAuth redirect CT changes, etc.
                    if (baselineResponse != null) {
                        String baseCt = "", probeCt = "";
                        for (HttpHeader h : baselineResponse.headers())
                            if ("content-type".equalsIgnoreCase(h.name())) { baseCt = h.value().toLowerCase(); break; }
                        for (HttpHeader h : response.headers())
                            if ("content-type".equalsIgnoreCase(h.name())) { probeCt = h.value().toLowerCase(); break; }
                        // Strip charset/boundary suffix for type-only compare
                        String baseType = baseCt.split(";")[0].trim();
                        String probeType = probeCt.split(";")[0].trim();
                        if (!baseType.isEmpty() && !probeType.isEmpty() && !baseType.equals(probeType)) {
                            matched = true;
                            matchedDescriptions.add("mime_change:" + baseType + "->" + probeType);
                        }
                    }
                }
                case "length_delta" -> {
                    // R10: alias of length_diff with named threshold key for KB clarity.
                    Number minDelta = (Number) matcher.get("min_delta");
                    if (minDelta == null) minDelta = (Number) matcher.get("min_diff");
                    if (minDelta != null && baselineResponse != null) {
                        int delta = Math.abs(bodyLen - baselineLen);
                        matched = delta >= minDelta.intValue();
                        if (matched) matchedDescriptions.add("length_delta:" + delta);
                    }
                }
                case "header_change" -> {
                    if (baselineResponse != null) {
                        @SuppressWarnings("unchecked")
                        List<String> headerNames = (List<String>) matcher.get("headers");
                        if (headerNames == null) {
                            // Check all headers for any new ones
                            Set<String> baseHeaders = new java.util.HashSet<>();
                            for (HttpHeader h : baselineResponse.headers()) baseHeaders.add(h.name().toLowerCase());
                            for (HttpHeader h : response.headers()) {
                                if (!baseHeaders.contains(h.name().toLowerCase())) {
                                    matched = true;
                                    matchedDescriptions.add("new_header:" + h.name());
                                    break;
                                }
                            }
                        } else {
                            for (String hName : headerNames) {
                                String baseVal = null, probeVal = null;
                                for (HttpHeader h : baselineResponse.headers()) {
                                    if (hName.equalsIgnoreCase(h.name())) { baseVal = h.value(); break; }
                                }
                                for (HttpHeader h : response.headers()) {
                                    if (hName.equalsIgnoreCase(h.name())) { probeVal = h.value(); break; }
                                }
                                if ((baseVal == null && probeVal != null) || (baseVal != null && !baseVal.equals(probeVal))) {
                                    matched = true;
                                    matchedDescriptions.add("header_change:" + hName);
                                    break;
                                }
                            }
                        }
                    }
                }
                case "shape_fingerprint" -> {
                    // Match when the response shape (status + body length bucket
                    // + content-type type) DIFFERS from the baseline. Detects
                    // "real anomaly" through a sanitised-error wall where
                    // length_diff alone gives false negatives.
                    if (baselineResponse != null) {
                        String baseFp = shapeFingerprint(baselineResponse);
                        String probeFp = shapeFingerprintFor(status, bodyLen, response);
                        matched = !baseFp.equals(probeFp);
                        if (matched) matchedDescriptions.add("shape_fingerprint: " + baseFp + " -> " + probeFp);
                    }
                }
                case "valid_vs_invalid_baseline" -> {
                    // Caller passes both the valid baseline (baselineResponse)
                    // AND an invalid-input baseline shape via matcher["invalid_shape"].
                    // Match when the probe response shape matches the VALID baseline,
                    // not the INVALID baseline — i.e. the probe was treated as a real
                    // input, not rejected by the sanitiser. This is the canonical
                    // bypass detector behind error-wall sanitisers.
                    String invalidShape = (String) matcher.get("invalid_shape");
                    if (baselineResponse != null && invalidShape != null) {
                        String validFp = shapeFingerprint(baselineResponse);
                        String probeFp = shapeFingerprintFor(status, bodyLen, response);
                        boolean looksValid = validFp.equals(probeFp);
                        boolean looksInvalid = invalidShape.equals(probeFp);
                        // Match: probe matches valid AND not the canned invalid response
                        matched = looksValid && !looksInvalid;
                        if (matched) matchedDescriptions.add("valid_baseline_match (not error-wall): " + probeFp);
                    }
                }
            default -> { }
        }
        return matched;
    }
}
