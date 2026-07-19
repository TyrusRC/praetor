package com.praetor.session;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Shared static helpers used by BatchProbeHandler + AutoProbeOrchestrator.
 * Lifted verbatim from SessionHandler.
 */
public final class ProbeHelpers {

    private ProbeHelpers() { }

    /** Inject a parameter value into the query string of a path. Body
     *  injection is a no-op here — caller supplies the body separately. */
    public static String injectParam(String path, String param, String value, String injectionPoint) {
        if ("query".equals(injectionPoint)) {
            return path.contains("?") ? path + "&" + param + "=" + value : path + "?" + param + "=" + value;
        }
        return path;
    }

    /**
     * Match a parameter name against a knowledge-base param_match list.
     * Exact-lowercase match wins first; then tokenize camelCase / snake_case /
     * kebab-case and check each token, plus an entry-is-prefix-of-parameter
     * check (entry length ≥ 3 to avoid "id" → "identifier" false hits already
     * caught by the token split).
     */
    public static boolean paramMatcherHits(String parameter, List<String> paramMatch) {
        if (parameter == null || paramMatch == null || paramMatch.isEmpty()) return true;
        String lower = parameter.toLowerCase();
        Set<String> tokens = new HashSet<>();
        tokens.add(lower);
        for (String t : lower.split("[_\\-\\s\\.]+")) {
            if (!t.isEmpty()) tokens.add(t);
        }
        for (String t : parameter.split("(?<!^)(?=[A-Z])")) {
            if (!t.isEmpty()) tokens.add(t.toLowerCase());
        }
        for (String entry : paramMatch) {
            if (entry == null) continue;
            String e = entry.toLowerCase();
            if (tokens.contains(e)) return true;
            if (e.length() >= 3 && lower.startsWith(e)) return true;
        }
        return false;
    }
}
