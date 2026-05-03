package com.swissknife.util;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Bounded shared cache of compiled regex patterns. Knowledge-base probes,
 * macro extraction rules, fuzz grep patterns, and analysis rules all hit
 * the same regex repeatedly across a session — recompiling per evaluation
 * was the dominant CPU cost for the matcher engine.
 *
 * Thread-safe via synchronizedMap on a LinkedHashMap with LRU eviction.
 */
public final class PatternCache {

    private static final int MAX = 256;

    private static final Map<String, Pattern> CACHE =
        Collections.synchronizedMap(new LinkedHashMap<>(64, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Pattern> eldest) {
                return size() > MAX;
            }
        });

    private PatternCache() {}

    /** Compile-or-return-cached. Throws PatternSyntaxException for invalid input. */
    public static Pattern get(String pattern, int flags) throws PatternSyntaxException {
        String key = pattern + "\0" + flags;
        Pattern p = CACHE.get(key);
        if (p != null) return p;
        Pattern compiled = Pattern.compile(pattern, flags);
        CACHE.put(key, compiled);
        return compiled;
    }

    public static Pattern get(String pattern) throws PatternSyntaxException {
        return get(pattern, 0);
    }
}
