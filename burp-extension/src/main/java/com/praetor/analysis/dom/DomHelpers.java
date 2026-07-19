package com.praetor.analysis.dom;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shared helpers for HtmlAnalyzer and JsFlowAnalyzer: pattern→match-list
 * collection, context extraction, line-number lookup with per-thread cache,
 * and length truncation.
 */
final class DomHelpers {

    private DomHelpers() {}

    static final int MAX_CONTEXT_LENGTH = 200;

    static void findPatternMatches(List<Map<String, Object>> results, String body,
                                   Pattern pattern, String type, String risk) {
        Matcher m = pattern.matcher(body);
        while (m.find()) {
            Map<String, Object> match = new LinkedHashMap<>();
            match.put("type", type);
            match.put("context", truncate(extractContext(body, m.start(), m.end())));
            match.put("line_approx", lineNumber(body, m.start()));
            match.put("risk", risk);
            results.add(match);
        }
    }

    static String extractContext(String body, int matchStart, int matchEnd) {
        int lineStart = body.lastIndexOf('\n', matchStart);
        lineStart = (lineStart < 0) ? 0 : lineStart + 1;

        int lineEnd = body.indexOf('\n', matchEnd);
        if (lineEnd < 0) lineEnd = body.length();

        return body.substring(lineStart, Math.min(lineEnd, body.length())).trim();
    }

    /**
     * Cached newline offsets per body (per-thread). The naive implementation
     * walked from 0 every call; with N regex matches and a 1MB body that's
     * O(N·body_len) just to attach line numbers. We build a sorted int[] of
     * newline indices once per body, then binary-search per match.
     */
    private static final ThreadLocal<java.lang.ref.WeakReference<int[]>> LINE_OFFSETS =
        ThreadLocal.withInitial(() -> new java.lang.ref.WeakReference<>(null));
    private static final ThreadLocal<java.lang.ref.WeakReference<String>> LINE_OFFSETS_BODY =
        ThreadLocal.withInitial(() -> new java.lang.ref.WeakReference<>(null));

    static int lineNumber(String body, int position) {
        if (body == null || body.isEmpty()) return 1;
        String cachedBody = LINE_OFFSETS_BODY.get().get();
        int[] offsets = LINE_OFFSETS.get().get();
        if (cachedBody != body || offsets == null) {
            java.util.List<Integer> tmp = new java.util.ArrayList<>();
            for (int i = 0; i < body.length(); i++) {
                if (body.charAt(i) == '\n') tmp.add(i);
            }
            offsets = new int[tmp.size()];
            for (int i = 0; i < tmp.size(); i++) offsets[i] = tmp.get(i);
            LINE_OFFSETS.set(new java.lang.ref.WeakReference<>(offsets));
            LINE_OFFSETS_BODY.set(new java.lang.ref.WeakReference<>(body));
        }
        // Binary search for first newline >= position. Line number = idx + 1
        // (line 1 has no newlines preceding it).
        int idx = java.util.Arrays.binarySearch(offsets, position);
        if (idx < 0) idx = -idx - 1;
        return idx + 1;
    }

    static String truncate(String s) {
        if (s == null) return "";
        return s.length() > MAX_CONTEXT_LENGTH ? s.substring(0, MAX_CONTEXT_LENGTH) + "..." : s;
    }
}
