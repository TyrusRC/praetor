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
                    if (matched) matchedDescriptions.add("word:" + words.get(0));
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
                    if (pattern != null) {
                        try {
                            matched = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(body).find();
                        } catch (PatternSyntaxException ignored) {}
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
                    if (headerName != null) {
                        for (HttpHeader h : response.headers()) {
                            if (headerName.equalsIgnoreCase(h.name())) {
                                matched = contains == null || h.value().toLowerCase().contains(contains.toLowerCase());
                                break;
                            }
                        }
                    }
                    if (matched) matchedDescriptions.add("header:" + headerName);
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
            }

            if (!matched) allMatched = false;
        }

        result.put("matched", allMatched);
        result.put("matched_matchers", matchedDescriptions);
        result.put("confidence_boost", allMatched ? matchedDescriptions.size() * 15 : 0);
        return result;
    }
}
