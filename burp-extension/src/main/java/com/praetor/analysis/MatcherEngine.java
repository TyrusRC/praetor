package com.praetor.analysis;

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

    static Pattern compileCached(String pattern, int flags) {
        return com.praetor.util.PatternCache.get(pattern, flags);
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
    /**
     * True when a matcher set can actually distinguish a vulnerable response
     * from an ordinary one.
     *
     * A `status` matcher listing only success codes does not: the baseline
     * returns 200 too, so `status:200` is satisfied by an untouched page. A
     * `status` naming an error or redirect (500, 403, 302) IS a discriminator —
     * a 500 where the baseline gave 200 is the signal that confirms blind SQLi —
     * and so is `not_status`, which asserts a deviation outright.
     *
     * A negative matcher carrying no terms (`not_word` with an empty word list,
     * `not_header` with no header name) is a no-op that always passes. A set
     * built only from non-discriminators is unfalsifiable.
     */
    static boolean isDiscriminating(List<Map<String, Object>> matchers) {
        for (Map<String, Object> m : matchers) {
            if (m == null) continue;
            String type = String.valueOf(m.getOrDefault("type", ""));
            switch (type) {
                case "status":
                    if (onlySuccessCodes(m)) continue;
                    return true;
                case "not_word":
                case "not_words":
                    if (isEmptyTerms(m, "words") && isEmptyTerms(m, "word")) continue;
                    return true;
                case "not_header":
                    if (isBlank(m.get("header")) && isBlank(m.get("name"))) continue;
                    return true;
                default:
                    return true;   // word/regex/reflection/timing/collaborator/...
            }
        }
        return false;
    }

    /** True when a status matcher lists nothing but 2xx codes. */
    private static boolean onlySuccessCodes(Map<String, Object> m) {
        Object v = m.get("status");
        if (v == null) v = m.get("codes");
        if (v == null) v = m.get("value");
        List<?> codes = (v instanceof List<?> l) ? l : (v == null ? List.of() : List.of(v));
        if (codes.isEmpty()) return true;
        for (Object c : codes) {
            try {
                int code = Integer.parseInt(String.valueOf(c).trim());
                if (code < 200 || code > 299) return false;
            } catch (NumberFormatException e) {
                return false;   // unparseable — assume it means something
            }
        }
        return true;
    }

    private static boolean isEmptyTerms(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v == null) return true;
        if (v instanceof List<?> list) return list.isEmpty();
        return isBlank(v);
    }

    private static boolean isBlank(Object v) {
        return v == null || String.valueOf(v).trim().isEmpty();
    }

    public static Map<String, Object> evaluate(
            List<Map<String, Object>> matchers,
            HttpResponse response,
            long responseTimeMs,
            HttpResponse baselineResponse,
            String payload) {
        return evaluate(matchers, response, responseTimeMs, baselineResponse, payload, "and");
    }

    /**
     * As {@link #evaluate(List, HttpResponse, long, HttpResponse, String)} but with an
     * explicit combining condition (nuclei-style {@code matchers-condition}).
     *
     * @param condition "or" → the set matches when ANY matcher matches; anything
     *                  else (default "and") → ALL must match. Per-matcher internal
     *                  OR/AND over its own values is unchanged. Unknown matcher
     *                  types never count as a match under either condition.
     */
    public static Map<String, Object> evaluate(
            List<Map<String, Object>> matchers,
            HttpResponse response,
            long responseTimeMs,
            HttpResponse baselineResponse,
            String payload,
            String condition) {

        Map<String, Object> probe = runMatchers(matchers, response, responseTimeMs, baselineResponse, payload, condition);

        // Baseline-equivalence guard. isDiscriminating() judges matcher SHAPE and
        // cannot see that the untouched baseline already satisfies the set:
        // status:200 + not_word:[unauthorized] "looks" discriminating, but on a
        // page that was already 200 without those words the probe changed nothing.
        // The fail_open_on_parser_error and xff_403_bypass classes fire on every
        // public endpoint exactly this way. Re-run the same matchers against the
        // baseline with time=0 and payload="" so baseline-relative matchers
        // (length_diff, timing, reflection, collaborator) can only FAIL that
        // second pass, never spuriously suppress a genuine delta (blind-SQLi
        // 500-vs-200, a real 403->200 ACL flip). If the baseline matches too,
        // refuse to score — same fail-closed stance as unknown matcher types.
        if (Boolean.TRUE.equals(probe.get("matched")) && baselineResponse != null) {
            Map<String, Object> base = runMatchers(matchers, baselineResponse, 0L, baselineResponse, "", condition);
            if (Boolean.TRUE.equals(base.get("matched"))) {
                Map<String, Object> suppressed = new LinkedHashMap<>();
                suppressed.put("matched", false);
                suppressed.put("matched_matchers", List.of());
                suppressed.put("confidence_boost", 0);
                suppressed.put("baseline_equivalent", true);
                return suppressed;
            }
        }
        return probe;
    }

    private static Map<String, Object> runMatchers(
            List<Map<String, Object>> matchers,
            HttpResponse response,
            long responseTimeMs,
            HttpResponse baselineResponse,
            String payload,
            String setCondition) {

        boolean orCondition = "or".equalsIgnoreCase(setCondition);
        Map<String, Object> result = new LinkedHashMap<>();
        List<String> matchedDescriptions = new ArrayList<>();
        boolean allMatched = true;
        int matchedCount = 0;

        if (matchers == null || matchers.isEmpty() || response == null) {
            result.put("matched", false);
            result.put("matched_matchers", List.of());
            result.put("confidence_boost", 0);
            return result;
        }

        // A matcher set that every successful response satisfies cannot be
        // evidence of anything. Some knowledge entries ship `status:200` plus a
        // `not_word` carrying no words — the negative match is a no-op, so the
        // probe "hit" on any 200 and reported a HIGH finding on a page it never
        // tested. Those entries fire on every endpoint while genuinely
        // discriminating probes fire rarely, so they dominated the output: a
        // live run returned 16 findings, all of them from this shape.
        //
        // Refusing to score them is the same fail-closed rule already applied
        // to unknown matcher types — a matcher that cannot fail is not a
        // matcher.
        if (!isDiscriminating(matchers)) {
            result.put("matched", false);
            result.put("matched_matchers", List.of());
            result.put("confidence_boost", 0);
            result.put("non_discriminating", true);
            return result;
        }

        String body = response.bodyToString();
        String bodyLower = body.toLowerCase();
        int status = response.statusCode();
        int bodyLen = body.length();
        int baselineLen = baselineResponse != null ? baselineResponse.bodyToString().length() : 0;

       
        MatcherTypes.Ctx ctx = new MatcherTypes.Ctx(
            response, baselineResponse, responseTimeMs, payload,
            body, bodyLower, status, bodyLen, baselineLen);

        for (Map<String, Object> matcher : matchers) {
            String type = (String) matcher.getOrDefault("type", "");
            boolean matched = MatcherTypes.matches(type, matcher, ctx, matchedDescriptions);

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

            if (matched) matchedCount++;
            else allMatched = false;
        }

        // AND (default): every evaluable matcher matched. OR: at least one did.
        boolean overall = orCondition ? matchedCount > 0 : allMatched;
        result.put("matched", overall);
        result.put("matched_matchers", matchedDescriptions);
        result.put("confidence_boost", overall ? matchedCount * 15 : 0);
        return result;
    }

    private static final java.util.Set<String> KNOWN_MATCHER_TYPES = java.util.Set.of(
        "status", "not_status", "word", "not_word", "regex", "timing", "differential_timing",
        "length_diff", "length_delta", "word_count_diff",
        "header", "not_header", "header_change", "header_added", "header_removed",
        "mime_changes", "reflection", "literal", "collaborator",
        "shape_fingerprint", "valid_vs_invalid_baseline"
    );

    static int countWords(String text) {
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
