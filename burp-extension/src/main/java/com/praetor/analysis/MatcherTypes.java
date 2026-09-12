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

/**
 * Per-matcher-type evaluation, split out of MatcherEngine so the engine stays under
 * the line ceiling. One case per known matcher type; sets `matched` and appends a
 * human tag to `matchedDescriptions`. Behaviour is byte-identical to the inline switch.
 */
final class MatcherTypes {

    private MatcherTypes() {}

    /** Immutable per-response context shared by every matcher in a set. */
    record Ctx(HttpResponse response, HttpResponse baselineResponse, long responseTimeMs,
               String payload, String body, String bodyLower, int status, int bodyLen, int baselineLen) {}

    static boolean matches(String type, Map<String, Object> matcher, Ctx c, List<String> matchedDescriptions) {
        return matchGroupA(type, matcher, c, matchedDescriptions)
            || MatcherTypesB.matchGroupB(type, matcher, c, matchedDescriptions);
    }

    static boolean matchGroupA(String type, Map<String, Object> matcher, Ctx c, List<String> matchedDescriptions) {
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
                case "status" -> {
                    @SuppressWarnings("unchecked")
                    List<Number> statuses = (List<Number>) matcher.get("status");
                    if (statuses != null) {
                        matched = statuses.stream().anyMatch(s -> s.intValue() == status);
                    }
                    if (matched) matchedDescriptions.add("status:" + status);
                }
                case "not_status" -> {
                    @SuppressWarnings("unchecked")
                    List<Number> statuses = (List<Number>) matcher.get("status");
                    if (statuses != null) {
                        matched = statuses.stream().noneMatch(s -> s.intValue() == status);
                    }
                    if (matched) matchedDescriptions.add("not_status:" + status);
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
            default -> { }
        }
        return matched;
    }
}
