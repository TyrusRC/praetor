package com.praetor.handlers;

import java.util.*;
import java.util.regex.*;

/** JSON-path traversal, split out of ExtractDataHandler (pure; no handler state). */
final class JsonPathTraverser {

    private JsonPathTraverser() {}

    /** Sentinel returned by traverseJsonPath when a path segment cannot be
     *  resolved (key absent, index out of range, type mismatch). Callers
     *  compare against this with reference equality and translate to a
     *  found=false response so a literal JSON null doesn't get misread as
     *  a missing path. */
    static final Object MISSING = new Object();

    static Object traverseJsonPath(Object current, String pathExpr) {
        String[] segments = splitPathSegments(pathExpr);

        for (String segment : segments) {
            if (current == null) return MISSING;

            // Handle array wildcard: field[*]
            if (segment.contains("[*]")) {
                String fieldName = segment.substring(0, segment.indexOf("[*]"));
                if (!fieldName.isEmpty() && current instanceof Map<?, ?> map) {
                    current = map.get(fieldName);
                }
                // current should be a list — will be expanded by next segment
                continue;
            }

            // Handle array index: field[N]
            Matcher arrayMatcher = Pattern.compile("^(.+?)\\[(\\d+)]$").matcher(segment);
            if (arrayMatcher.matches()) {
                String fieldName = arrayMatcher.group(1);
                int arrayIndex = Integer.parseInt(arrayMatcher.group(2));
                if (current instanceof Map<?, ?> map) {
                    current = map.get(fieldName);
                }
                if (current instanceof List<?> list) {
                    if (arrayIndex >= 0 && arrayIndex < list.size()) {
                        current = list.get(arrayIndex);
                    } else {
                        return MISSING;
                    }
                } else {
                    return MISSING;
                }
                continue;
            }

            // Handle bare array index: [N]
            Matcher bareIndex = Pattern.compile("^\\[(\\d+)]$").matcher(segment);
            if (bareIndex.matches()) {
                int idx = Integer.parseInt(bareIndex.group(1));
                if (current instanceof List<?> list) {
                    if (idx >= 0 && idx < list.size()) {
                        current = list.get(idx);
                    } else {
                        return MISSING;
                    }
                } else {
                    return MISSING;
                }
                continue;
            }

            // If current is a list (from wildcard), extract field from each element
            if (current instanceof List<?> list) {
                List<Object> collected = new ArrayList<>();
                for (Object item : list) {
                    if (item instanceof Map<?, ?> map) {
                        Object val = map.get(segment);
                        if (val != null) collected.add(val);
                    }
                }
                current = collected;
                continue;
            }

            // Simple key access. containsKey() is the discriminator that
            // turns "key absent" into MISSING vs a literal null.
            if (current instanceof Map<?, ?> map) {
                if (!map.containsKey(segment)) {
                    return MISSING;
                }
                current = map.get(segment);
            } else {
                return MISSING;
            }
        }

        return current;
    }

    /**
     * Split a JSON path expression into segments, respecting brackets.
     * "data.users[0].name" -> ["data", "users[0]", "name"]
     * "data.items[*].id"   -> ["data", "items[*]", "id"]
     */
    static String[] splitPathSegments(String pathExpr) {
        List<String> segments = new ArrayList<>();
        StringBuilder current = new StringBuilder();

        for (int i = 0; i < pathExpr.length(); i++) {
            char c = pathExpr.charAt(i);
            if (c == '.' && !isInsideBracket(current.toString())) {
                if (!current.isEmpty()) {
                    segments.add(current.toString());
                    current.setLength(0);
                }
            } else {
                current.append(c);
            }
        }
        if (!current.isEmpty()) {
            segments.add(current.toString());
        }

        return segments.toArray(new String[0]);
    }

    static boolean isInsideBracket(String s) {
        int open = 0;
        for (char c : s.toCharArray()) {
            if (c == '[') open++;
            if (c == ']') open--;
        }
        return open > 0;
    }
}
