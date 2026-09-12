package com.praetor.handlers;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.*;

/** Response-diff computation helpers, split out of SearchHandler (pure, no handler state). */
final class ResponseDiffComputer {

    private ResponseDiffComputer() {}

    // ── Compare helpers ───────────────────────────────────────

    static List<Map<String, Object>> computeHeaderDiffs(HttpResponse resp1, HttpResponse resp2) {
        List<Map<String, Object>> diffs = new ArrayList<>();

        Map<String, String> headers1 = new LinkedHashMap<>();
        Map<String, String> headers2 = new LinkedHashMap<>();

        if (resp1 != null) {
            for (HttpHeader h : resp1.headers()) {
                headers1.put(h.name().toLowerCase(), h.value());
            }
        }
        if (resp2 != null) {
            for (HttpHeader h : resp2.headers()) {
                headers2.put(h.name().toLowerCase(), h.value());
            }
        }

        // All header names from both
        Set<String> allNames = new LinkedHashSet<>();
        allNames.addAll(headers1.keySet());
        allNames.addAll(headers2.keySet());

        for (String name : allNames) {
            String val1 = headers1.get(name);
            String val2 = headers2.get(name);
            if (!Objects.equals(val1, val2)) {
                Map<String, Object> diff = new LinkedHashMap<>();
                diff.put("name", name);
                diff.put("item1", val1 != null ? val1 : "");
                diff.put("item2", val2 != null ? val2 : "");
                diffs.add(diff);
            }
        }
        return diffs;
    }

    static Map<String, Object> computeBodyDiff(String body1, String body2) {
        Map<String, Object> diff = new LinkedHashMap<>();

        diff.put("identical", body1.equals(body2));

        // Similarity percentage (simple character-level Jaccard-like)
        if (body1.isEmpty() && body2.isEmpty()) {
            diff.put("similarity_pct", 100.0);
        } else {
            diff.put("similarity_pct", computeSimilarity(body1, body2));
        }

        // Line-by-line diff
        String[] lines1 = body1.split("\n", -1);
        String[] lines2 = body2.split("\n", -1);

        List<String> diffLines = new ArrayList<>();
        int added = 0;
        int removed = 0;
        int maxLines = Math.max(lines1.length, lines2.length);

        for (int i = 0; i < maxLines && diffLines.size() < 200; i++) {
            String l1 = i < lines1.length ? lines1[i] : null;
            String l2 = i < lines2.length ? lines2[i] : null;

            if (l1 != null && l2 != null && l1.equals(l2)) continue;

            if (l1 != null && (l2 == null || !l1.equals(l2))) {
                diffLines.add("- " + truncateLine(l1, 200));
                removed++;
            }
            if (l2 != null && (l1 == null || !l1.equals(l2))) {
                diffLines.add("+ " + truncateLine(l2, 200));
                added++;
            }
        }

        diff.put("added_lines", added);
        diff.put("removed_lines", removed);
        diff.put("diff_lines", diffLines);

        return diff;
    }

    static double computeSimilarity(String s1, String s2) {
        // Use line-level similarity for efficiency
        Set<String> set1 = new HashSet<>(Arrays.asList(s1.split("\n")));
        Set<String> set2 = new HashSet<>(Arrays.asList(s2.split("\n")));

        Set<String> intersection = new HashSet<>(set1);
        intersection.retainAll(set2);

        Set<String> union = new HashSet<>(set1);
        union.addAll(set2);

        if (union.isEmpty()) return 100.0;
        double similarity = (double) intersection.size() / union.size() * 100.0;
        return Math.round(similarity * 10.0) / 10.0;
    }

    static int countWords(String text) {
        if (text == null || text.isBlank()) return 0;
        return text.split("\\s+").length;
    }

    static Set<String> extractWords(String text) {
        if (text == null || text.isBlank()) return Collections.emptySet();
        Set<String> words = new LinkedHashSet<>();
        for (String word : text.split("\\s+")) {
            String cleaned = word.toLowerCase().replaceAll("[^a-z0-9]", "");
            if (cleaned.length() >= 3) {
                words.add(cleaned);
            }
        }
        return words;
    }

    static List<String> limitSet(Set<String> set, int max) {
        List<String> list = new ArrayList<>();
        int count = 0;
        for (String s : set) {
            if (count >= max) break;
            list.add(s);
            count++;
        }
        return list;
    }

    static String truncateLine(String line, int max) {
        if (line.length() <= max) return line;
        return line.substring(0, max) + "...";
    }
}
