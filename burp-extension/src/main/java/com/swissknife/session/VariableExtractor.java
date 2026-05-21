package com.swissknife.session;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.swissknife.handlers.Session;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure utilities for response-value extraction, variable merging into
 * sessions, and step interpolation. Lifted verbatim from SessionHandler.
 *
 * Thread-locals carry the last extraction's warning list so the calling
 * handler can attach {@code extract_warnings} to the JSON response without
 * changing the helper's return signature — same contract as the original.
 */
public final class VariableExtractor {

    /**
     * Per-thread last extraction-warning list. Read by SessionExtractHandler /
     * SessionRequestExecutor / FlowRunner immediately after each
     * extractFromResponse() call.
     */
    public static final ThreadLocal<List<String>> LAST_EXTRACT_WARNINGS =
        ThreadLocal.withInitial(ArrayList::new);

    private VariableExtractor() { }

    /**
     * Extract values from a response per the supplied rules map. Returns the
     * extracted name → value map. Warnings (rule did not fire / unknown
     * source / etc.) are pushed to {@link #LAST_EXTRACT_WARNINGS}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, String> extractFromResponse(HttpRequestResponse result, Map<String, Object> rules) {
        Map<String, String> extracted = new LinkedHashMap<>();
        List<String> warnings = new ArrayList<>();
        HttpResponse resp = result.response();
        if (resp == null) {
            warnings.add("(no response — extraction skipped)");
            LAST_EXTRACT_WARNINGS.set(warnings);
            return extracted;
        }

        for (var entry : rules.entrySet()) {
            String varName = entry.getKey();
            Object ruleObj = entry.getValue();
            if (!(ruleObj instanceof Map)) {
                warnings.add(varName + ": rule must be an object");
                continue;
            }

            Map<String, Object> rule = (Map<String, Object>) ruleObj;
            String type = (String) rule.get("type");
            String defaultSource = "body";
            if (type != null) {
                switch (type) {
                    case "regex", "json_path" -> defaultSource = "body";
                    case "header" -> defaultSource = "header";
                    case "cookie" -> defaultSource = "cookie";
                }
            }
            String source = (String) rule.getOrDefault("from", rule.getOrDefault("source", defaultSource));
            String regex = (String) rule.getOrDefault("regex", rule.get("pattern"));
            String jsonPath = (String) rule.getOrDefault("json_path", rule.get("path"));
            String value = null;

            switch (source) {
                case "body" -> {
                    String bodyStr = resp.bodyToString();
                    if (regex != null) {
                        value = extractByRegex(bodyStr, regex);
                        if (value == null) warnings.add(varName + ": regex did not match (/" + truncate(regex, 60) + "/)");
                    } else if (jsonPath != null) {
                        value = simpleJsonExtract(bodyStr, jsonPath);
                        if (value == null) warnings.add(varName + ": json_path did not resolve (" + jsonPath + ")");
                    } else {
                        warnings.add(varName + ": body rule needs 'regex' (or 'pattern') / 'json_path' (or 'path')");
                    }
                }
                case "header" -> {
                    String headerName = (String) rule.get("name");
                    if (headerName == null) {
                        warnings.add(varName + ": header rule needs 'name'");
                        break;
                    }
                    for (HttpHeader h : resp.headers()) {
                        if (headerName.equalsIgnoreCase(h.name())) {
                            value = h.value();
                            break;
                        }
                    }
                    if (value == null) warnings.add(varName + ": header '" + headerName + "' not present in response");
                }
                case "cookie" -> {
                    String cookieName = (String) rule.get("name");
                    if (cookieName == null) {
                        warnings.add(varName + ": cookie rule needs 'name'");
                        break;
                    }
                    for (HttpHeader h : resp.headers()) {
                        if ("Set-Cookie".equalsIgnoreCase(h.name())) {
                            String cv = h.value();
                            int semi = cv.indexOf(';');
                            String nv = semi > 0 ? cv.substring(0, semi).trim() : cv.trim();
                            int eq = nv.indexOf('=');
                            if (eq > 0 && nv.substring(0, eq).trim().equals(cookieName)) {
                                value = nv.substring(eq + 1).trim();
                                break;
                            }
                        }
                    }
                    if (value == null) warnings.add(varName + ": Set-Cookie '" + cookieName + "' not present in response");
                }
                default -> warnings.add(varName + ": unknown source '" + source + "' (use body/header/cookie)");
            }

            if (value != null) {
                extracted.put(varName, value);
            }
        }

        LAST_EXTRACT_WARNINGS.set(warnings);
        return extracted;
    }

    /** Merge extracted variables into a session, capped at 200 entries to
     *  prevent unbounded growth. */
    public static void mergeVariables(Session session, Map<String, String> extracted) {
        session.variables.putAll(extracted);
        while (session.variables.size() > 200) {
            String oldest = session.variables.keySet().iterator().next();
            session.variables.remove(oldest);
        }
    }

    public static String extractByRegex(String text, String regex) {
        try {
            Matcher m = Pattern.compile(regex).matcher(text);
            if (m.find()) {
                return m.groupCount() >= 1 ? m.group(1) : m.group(0);
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Simple JSON path extraction supporting $.key and $.parent.child using regex.
     * Not a full JSON path implementation — handles the common cases.
     */
    public static String simpleJsonExtract(String json, String path) {
        if (path == null || !path.startsWith("$.")) return null;

        String[] keys = path.substring(2).split("\\.");
        String current = json;

        for (String key : keys) {
            String pattern = "\"" + Pattern.quote(key) + "\"\\s*:\\s*";
            Matcher m = Pattern.compile(pattern).matcher(current);
            if (!m.find()) return null;

            int valueStart = m.end();
            if (valueStart >= current.length()) return null;

            char first = current.charAt(valueStart);
            if (first == '"') {
                int strStart = valueStart + 1;
                int strEnd = strStart;
                while (strEnd < current.length()) {
                    if (current.charAt(strEnd) == '\\') {
                        strEnd += 2;
                        continue;
                    }
                    if (current.charAt(strEnd) == '"') break;
                    strEnd++;
                }
                return current.substring(strStart, strEnd);
            } else if (first == '{' || first == '[') {
                current = current.substring(valueStart);
            } else {
                int end = valueStart;
                while (end < current.length() && current.charAt(end) != ',' && current.charAt(end) != '}' && current.charAt(end) != ']') {
                    end++;
                }
                return current.substring(valueStart, end).trim();
            }
        }

        return null;
    }

    /** Deep-copy a step map, replacing {{variable}} in all string values. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> interpolateStep(Map<String, Object> step, Map<String, String> variables) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (var entry : step.entrySet()) {
            Object val = entry.getValue();
            if (val instanceof String s) {
                result.put(entry.getKey(), interpolateString(s, variables));
            } else if (val instanceof Map) {
                result.put(entry.getKey(), interpolateStep((Map<String, Object>) val, variables));
            } else if (val instanceof List) {
                List<Object> interpolated = new ArrayList<>();
                for (Object item : (List<Object>) val) {
                    if (item instanceof String s) {
                        interpolated.add(interpolateString(s, variables));
                    } else if (item instanceof Map) {
                        interpolated.add(interpolateStep((Map<String, Object>) item, variables));
                    } else {
                        interpolated.add(item);
                    }
                }
                result.put(entry.getKey(), interpolated);
            } else {
                result.put(entry.getKey(), val);
            }
        }
        return result;
    }

    public static String interpolateString(String s, Map<String, String> variables) {
        if (s == null || !s.contains("{{")) return s;
        String result = s;
        for (var entry : variables.entrySet()) {
            result = result.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        return result;
    }

    public static String truncate(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n) + "...";
    }
}
