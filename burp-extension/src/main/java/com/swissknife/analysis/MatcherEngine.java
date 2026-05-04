package com.swissknife.analysis;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;

import java.util.*;
import java.util.regex.*;
import java.nio.charset.StandardCharsets;

/**
 * Server-side matcher engine for knowledge-base-driven vulnerability detection.
 * Evaluates matchers against HTTP responses without transferring raw body to Claude.
 */
public final class MatcherEngine {

    private MatcherEngine() {}

    private static Pattern compileCached(String pattern, int flags) {
        return com.swissknife.util.PatternCache.get(pattern, flags);
    }

    /**
     * Evaluate a list of matchers against a response.
     * All matchers must match (AND logic). Each matcher can have internal OR/AND for its values.
     *
     * @param matchers List of matcher definitions from knowledge base
     * @param response The HTTP response to check
     * @param responseTimeMs Response time in milliseconds
     * @param baselineResponse The baseline response for comparison (nullable)
     * @param payload The payload that was sent (for reflection detection)
     * @return Map with: matched (bool), matched_matchers (list of descriptions), confidence_boost (int)
     */
    public static Map<String, Object> evaluate(
            List<Map<String, Object>> matchers,
            HttpResponse response,
            long responseTimeMs,
            HttpResponse baselineResponse,
            String payload) {

        Map<String, Object> result = new LinkedHashMap<>();
        List<String> matchedDescriptions = new ArrayList<>();
        boolean allMatched = true;

        if (matchers == null || matchers.isEmpty() || response == null) {
            result.put("matched", false);
            result.put("matched_matchers", List.of());
            result.put("confidence_boost", 0);
            return result;
        }

        String body = response.bodyToString();
        String bodyLower = body.toLowerCase();
        int status = response.statusCode();
        int bodyLen = body.length();
        int baselineLen = baselineResponse != null ? baselineResponse.bodyToString().length() : 0;

        for (Map<String, Object> matcher : matchers) {
            String type = (String) matcher.getOrDefault("type", "");
            boolean matched = false;

            switch (type) {
                case "status" -> {
                    @SuppressWarnings("unchecked")
                    List<Number> statuses = (List<Number>) matcher.get("status");
                    if (statuses != null) {
                        matched = statuses.stream().anyMatch(s -> s.intValue() == status);
                    }
                    if (matched) matchedDescriptions.add("status:" + status);
                }
                case "word" -> {
                    @SuppressWarnings("unchecked")
                    List<String> words = (List<String>) matcher.get("words");
                    String condition = (String) matcher.getOrDefault("condition", "or");
                    if (words != null) {
                        if ("and".equals(condition)) {
                            matched = words.stream().allMatch(w -> bodyLower.contains(w.toLowerCase()));
                        } else {
                            matched = words.stream().anyMatch(w -> bodyLower.contains(w.toLowerCase()));
                        }
                    }
                    if (matched && words != null && !words.isEmpty()) matchedDescriptions.add("word:" + words.get(0));
                }
                case "not_word" -> {
                    @SuppressWarnings("unchecked")
                    List<String> words = (List<String>) matcher.get("words");
                    if (words != null) {
                        matched = words.stream().noneMatch(w -> bodyLower.contains(w.toLowerCase()));
                    }
                    if (matched) matchedDescriptions.add("not_word");
                }
                case "regex" -> {
                    String pattern = (String) matcher.get("pattern");
                    Object flagObj = matcher.get("ignore_case");
                    int regexFlags = (flagObj instanceof Boolean b && !b) ? 0 : Pattern.CASE_INSENSITIVE;
                    if (pattern != null) {
                        try {
                            matched = compileCached(pattern, regexFlags).matcher(body).find();
                        } catch (PatternSyntaxException ignored) {
                            // Invalid KB regex — record but don't kill the whole evaluation
                            matchedDescriptions.add("regex_invalid:" + pattern);
                        } catch (StackOverflowError soe) {
                            // Catastrophic backtracking on adversarial body — fail this matcher,
                            // not the worker thread.
                            matchedDescriptions.add("regex_backtrack_overflow:" + pattern);
                            matched = false;
                        }
                    }
                    if (matched) matchedDescriptions.add("regex:" + pattern);
                }
                case "timing" -> {
                    Number minMs = (Number) matcher.get("min_ms");
                    if (minMs != null) {
                        matched = responseTimeMs >= minMs.longValue();
                    }
                    if (matched) matchedDescriptions.add("timing:" + responseTimeMs + "ms");
                }
                case "length_diff" -> {
                    Number minDiff = (Number) matcher.get("min_diff");
                    if (minDiff != null && baselineResponse != null) {
                        matched = Math.abs(bodyLen - baselineLen) >= minDiff.intValue();
                    }
                    if (matched) matchedDescriptions.add("length_diff:" + Math.abs(bodyLen - baselineLen));
                }
                case "header" -> {
                    String headerName = (String) matcher.get("name");
                    String contains = (String) matcher.get("contains");
                    @SuppressWarnings("unchecked")
                    List<String> headerNames = (List<String>) matcher.get("headers");
                    if (headerName != null) {
                        // Single header check with optional contains
                        for (HttpHeader h : response.headers()) {
                            if (headerName.equalsIgnoreCase(h.name())) {
                                matched = contains == null || h.value().toLowerCase().contains(contains.toLowerCase());
                                break;
                            }
                        }
                        if (matched) matchedDescriptions.add("header:" + headerName);
                    } else if (headerNames != null && !headerNames.isEmpty()) {
                        // Multi-header check: match if ANY of the listed headers is present
                        for (String hn : headerNames) {
                            for (HttpHeader h : response.headers()) {
                                if (hn.equalsIgnoreCase(h.name())) {
                                    matched = true;
                                    matchedDescriptions.add("header:" + hn);
                                    break;
                                }
                            }
                            if (matched) break;
                        }
                    }
                }
                case "not_header" -> {
                    // Inverse of "header": match when the named header is absent,
                    // or — if `contains` is specified — when the header is absent
                    // OR present but the value does not contain the substring.
                    // Used by clickjacking (no X-Frame-Options) and
                    // content_type_confusion (no nosniff) probes.
                    String headerName = (String) matcher.get("name");
                    String contains = (String) matcher.get("contains");
                    @SuppressWarnings("unchecked")
                    List<String> headerNames = (List<String>) matcher.get("headers");
                    if (headerName != null) {
                        boolean present = false;
                        String value = null;
                        for (HttpHeader h : response.headers()) {
                            if (headerName.equalsIgnoreCase(h.name())) {
                                present = true;
                                value = h.value();
                                break;
                            }
                        }
                        if (!present) {
                            matched = true;
                            matchedDescriptions.add("not_header:" + headerName);
                        } else if (contains != null && !value.toLowerCase().contains(contains.toLowerCase())) {
                            matched = true;
                            matchedDescriptions.add("not_header:" + headerName + " (missing '" + contains + "')");
                        }
                    } else if (headerNames != null && !headerNames.isEmpty()) {
                        // Multi-header: match when NONE of the listed headers is present.
                        boolean anyPresent = false;
                        for (String hn : headerNames) {
                            for (HttpHeader h : response.headers()) {
                                if (hn.equalsIgnoreCase(h.name())) { anyPresent = true; break; }
                            }
                            if (anyPresent) break;
                        }
                        if (!anyPresent) {
                            matched = true;
                            matchedDescriptions.add("not_header:" + String.join(",", headerNames));
                        }
                    }
                }
                case "literal" -> {
                    // Case-sensitive substring match against body. Used by
                    // cloud_webapp.json for exact field-name and SDK marker
                    // detection ("SecretAccessKey", "projects/-/serviceAccounts/").
                    // For case-insensitive substring use "word" instead.
                    String pattern = (String) matcher.get("pattern");
                    if (pattern != null && !pattern.isEmpty()) {
                        matched = body.contains(pattern);
                        if (matched) matchedDescriptions.add("literal:" + pattern);
                    }
                }
                case "collaborator" -> {
                    // OOB receipt matcher. The auto-probe driver injects a
                    // pre-polled `_interactions` list (per-probe poll after
                    // send) into the matcher map at runtime; the list shape is
                    // [{"type":"DNS|HTTP|SMTP", ...}, ...]. The probe payload
                    // is expected to embed the Collaborator host where the
                    // template said {{collaborator}}.
                    //
                    // Without injection (e.g. the driver did not call
                    // SessionProbeHelpers.attachInteractions), this case fails
                    // closed — better than the previous fail-open default.
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> interactions = (List<Map<String, Object>>) matcher.get("_interactions");
                    String wantProto = (String) matcher.get("protocol");
                    if (interactions != null && !interactions.isEmpty()) {
                        if (wantProto == null || wantProto.isBlank()) {
                            matched = true;
                        } else {
                            String want = wantProto.toLowerCase();
                            for (Map<String, Object> i : interactions) {
                                Object t = i.get("type");
                                if (t != null && t.toString().toLowerCase().equals(want)) {
                                    matched = true;
                                    break;
                                }
                            }
                        }
                        if (matched) matchedDescriptions.add("collaborator:" + interactions.size() + " " + (wantProto == null ? "any" : wantProto));
                    }
                }
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
            }

            // Unknown matcher type: fail closed. Probes whose ONLY matcher is
            // unknown would otherwise return matched=true (false positive),
            // because allMatched starts true and never flips. Failing closed
            // is more correct: a probe author who lists matchers expects ALL
            // of them to be evaluable. Drift in KB stays detectable via the
            // "unknown_matcher_type:" tag in matchedDescriptions.
            if (!KNOWN_MATCHER_TYPES.contains(type)) {
                matchedDescriptions.add("unknown_matcher_type:" + type);
                allMatched = false;
                continue;
            }

            if (!matched) allMatched = false;
        }

        result.put("matched", allMatched);
        result.put("matched_matchers", matchedDescriptions);
        result.put("confidence_boost", allMatched ? matchedDescriptions.size() * 15 : 0);
        return result;
    }

    private static final java.util.Set<String> KNOWN_MATCHER_TYPES = java.util.Set.of(
        "status", "word", "not_word", "regex", "timing", "differential_timing",
        "length_diff", "length_delta", "word_count_diff",
        "header", "not_header", "header_change", "header_added", "header_removed",
        "mime_changes", "reflection", "literal", "collaborator",
        "shape_fingerprint", "valid_vs_invalid_baseline"
    );

    private static int countWords(String text) {
        if (text == null || text.isEmpty()) return 0;
        return text.split("\\s+").length;
    }

    /**
     * Bucket-and-stringify a response: status + content-type-major + length-bucket.
     * Two responses sharing the same fingerprint are likely the same shape (e.g. canned
     * sanitised-error JSON), even if individual byte content differs. Used by the
     * shape_fingerprint and valid_vs_invalid_baseline matchers to defeat error-wall
     * false negatives.
     */
    public static String shapeFingerprint(HttpResponse r) {
        if (r == null) return "null";
        String ctype = "";
        for (HttpHeader h : r.headers()) {
            if ("Content-Type".equalsIgnoreCase(h.name())) {
                String v = h.value();
                int sc = v.indexOf(';');
                ctype = (sc >= 0 ? v.substring(0, sc) : v).trim().toLowerCase();
                int slash = ctype.indexOf('/');
                if (slash > 0) ctype = ctype.substring(0, slash);
                break;
            }
        }
        return shapeFingerprintFor(r.statusCode(), r.body().length(), r);
    }

    public static String shapeFingerprintFor(int status, int bodyLen, HttpResponse r) {
        String ctypeMajor = "";
        if (r != null) {
            for (HttpHeader h : r.headers()) {
                if ("Content-Type".equalsIgnoreCase(h.name())) {
                    String v = h.value();
                    int sc = v.indexOf(';');
                    String cleaned = (sc >= 0 ? v.substring(0, sc) : v).trim().toLowerCase();
                    int slash = cleaned.indexOf('/');
                    ctypeMajor = slash > 0 ? cleaned.substring(0, slash) : cleaned;
                    break;
                }
            }
        }
        return status + "|" + ctypeMajor + "|" + lengthBucket(bodyLen);
    }

    private static String lengthBucket(int n) {
        // Coarse bucket so trivial differences (timestamp / id) collapse to the
        // same shape; structural differences land in different buckets.
        if (n < 100) return "<100";
        if (n < 500) return "100-500";
        if (n < 1024) return "500-1k";
        if (n < 4096) return "1k-4k";
        if (n < 16384) return "4k-16k";
        if (n < 65536) return "16k-64k";
        if (n < 262144) return "64k-256k";
        return ">256k";
    }
}
