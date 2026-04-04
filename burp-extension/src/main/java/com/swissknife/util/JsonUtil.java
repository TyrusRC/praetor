package com.swissknife.util;

import java.util.*;

/**
 * Minimal JSON builder/parser — zero external dependencies.
 * Handles the simple flat/shallow JSON the REST API produces and consumes.
 */
public final class JsonUtil {

    private JsonUtil() {}

    // ── Building JSON ──────────────────────────────────────────────

    public static String object(Object... kvPairs) {
        if (kvPairs.length % 2 != 0) throw new IllegalArgumentException("Need key-value pairs");
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kvPairs.length; i += 2) {
            if (i > 0) sb.append(",");
            sb.append(quoted(String.valueOf(kvPairs[i]))).append(":");
            sb.append(toJson(kvPairs[i + 1]));
        }
        return sb.append("}").toString();
    }

    public static String array(List<?> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(toJson(items.get(i)));
        }
        return sb.append("]").toString();
    }

    public static String toJson(Object val) {
        if (val == null) return "null";
        if (val instanceof Number || val instanceof Boolean) return val.toString();
        if (val instanceof String s) return quoted(s);
        if (val instanceof List<?> list) return array(list);
        if (val instanceof Map<?, ?> map) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (var entry : map.entrySet()) {
                if (!first) sb.append(",");
                first = false;
                sb.append(quoted(String.valueOf(entry.getKey()))).append(":").append(toJson(entry.getValue()));
            }
            return sb.append("}").toString();
        }
        return quoted(val.toString());
    }

    public static String quoted(String s) {
        return "\"" + escape(s) + "\"";
    }

    public static String escape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    // ── Parsing JSON (simple recursive descent) ────────────────────

    public static Map<String, Object> parseObject(String json) {
        return new JsonParser(json.trim()).readObject();
    }

    public static List<Object> parseArray(String json) {
        return new JsonParser(json.trim()).readArray();
    }

    private static class JsonParser {
        private final String src;
        private int pos;

        JsonParser(String src) {
            this.src = src;
            this.pos = 0;
        }

        Map<String, Object> readObject() {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') { pos++; return map; }
            while (true) {
                skipWhitespace();
                String key = readString();
                skipWhitespace();
                expect(':');
                Object value = readValue();
                map.put(key, value);
                skipWhitespace();
                if (peek() == ',') { pos++; continue; }
                expect('}');
                break;
            }
            return map;
        }

        List<Object> readArray() {
            expect('[');
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') { pos++; return list; }
            while (true) {
                list.add(readValue());
                skipWhitespace();
                if (peek() == ',') { pos++; continue; }
                expect(']');
                break;
            }
            return list;
        }

        Object readValue() {
            skipWhitespace();
            char c = peek();
            if (c == '"') return readString();
            if (c == '{') return readObject();
            if (c == '[') return readArray();
            if (c == 't' || c == 'f') return readBoolean();
            if (c == 'n') return readNull();
            return readNumber();
        }

        String readString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    char esc = src.charAt(pos++);
                    switch (esc) {
                        case '"', '\\', '/' -> sb.append(esc);
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'u' -> {
                            String hex = src.substring(pos, pos + 4);
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                        }
                        default -> sb.append(esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new RuntimeException("Unterminated string");
        }

        Number readNumber() {
            int start = pos;
            if (peek() == '-') pos++;
            while (pos < src.length() && (Character.isDigit(src.charAt(pos)) || src.charAt(pos) == '.' || src.charAt(pos) == 'e' || src.charAt(pos) == 'E' || src.charAt(pos) == '+' || src.charAt(pos) == '-')) {
                if (src.charAt(pos) == '.' || src.charAt(pos) == 'e' || src.charAt(pos) == 'E') {
                    pos++;
                    while (pos < src.length() && (Character.isDigit(src.charAt(pos)) || src.charAt(pos) == '+' || src.charAt(pos) == '-')) pos++;
                    return Double.parseDouble(src.substring(start, pos));
                }
                pos++;
            }
            long val = Long.parseLong(src.substring(start, pos));
            if (val >= Integer.MIN_VALUE && val <= Integer.MAX_VALUE) return (int) val;
            return val;
        }

        Boolean readBoolean() {
            if (src.startsWith("true", pos)) { pos += 4; return true; }
            if (src.startsWith("false", pos)) { pos += 5; return false; }
            throw new RuntimeException("Expected boolean at " + pos);
        }

        Object readNull() {
            if (src.startsWith("null", pos)) { pos += 4; return null; }
            throw new RuntimeException("Expected null at " + pos);
        }

        char peek() {
            if (pos >= src.length()) throw new RuntimeException("Unexpected end of JSON");
            return src.charAt(pos);
        }

        void expect(char c) {
            skipWhitespace();
            if (pos >= src.length() || src.charAt(pos) != c) {
                throw new RuntimeException("Expected '" + c + "' at " + pos + ", got '" + (pos < src.length() ? src.charAt(pos) : "EOF") + "'");
            }
            pos++;
        }

        void skipWhitespace() {
            while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) pos++;
        }
    }
}
