package com.swissknife.http;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Case-insensitive multi-value header map. Preserves first-seen casing of header
 * names for write-out but looks them up case-insensitively.
 *
 * Mirrors the surface of com.sun.net.httpserver.Headers that BaseHandler and
 * handlers actually use: add(name, value), set(name, value), get(name),
 * getFirst(name), keySet().
 */
public final class Headers {

    /** Lower-cased name -> list of values. */
    private final Map<String, List<String>> values = new LinkedHashMap<>();
    /** Lower-cased name -> original-casing name (for write-out). */
    private final Map<String, String> originalCasing = new LinkedHashMap<>();

    public synchronized void add(String name, String value) {
        String key = name.toLowerCase(Locale.ROOT);
        values.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
        originalCasing.putIfAbsent(key, name);
    }

    public synchronized void set(String name, String value) {
        String key = name.toLowerCase(Locale.ROOT);
        List<String> list = new ArrayList<>();
        list.add(value);
        values.put(key, list);
        originalCasing.put(key, name);
    }

    public synchronized List<String> get(String name) {
        List<String> v = values.get(name.toLowerCase(Locale.ROOT));
        return v == null ? null : Collections.unmodifiableList(new ArrayList<>(v));
    }

    public synchronized String getFirst(String name) {
        List<String> v = values.get(name.toLowerCase(Locale.ROOT));
        return (v == null || v.isEmpty()) ? null : v.get(0);
    }

    public synchronized Set<String> keySet() {
        return Collections.unmodifiableSet(new LinkedHashMap<>(originalCasing).keySet());
    }

    /** Internal: iterate (originalName, value) pairs for write-out. */
    synchronized void forEachEntry(java.util.function.BiConsumer<String, String> out) {
        for (Map.Entry<String, List<String>> e : values.entrySet()) {
            String original = originalCasing.get(e.getKey());
            for (String v : e.getValue()) {
                out.accept(original, v);
            }
        }
    }

    /** Internal: does this contain a given (case-insensitive) header? */
    synchronized boolean containsKey(String name) {
        return values.containsKey(name.toLowerCase(Locale.ROOT));
    }
}
