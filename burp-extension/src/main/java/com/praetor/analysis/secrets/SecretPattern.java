package com.praetor.analysis.secrets;

import java.util.regex.Pattern;

/**
 * Pre-compiled secret pattern with optional entropy gating and a literal
 * pre-filter for cheap substring rejection before running the regex.
 */
public record SecretPattern(
    String name,
    String regex,
    String severity,
    boolean requiresEntropy,
    Pattern compiled,
    String preFilter
) {
    public SecretPattern(String name, String regex, String severity, boolean requiresEntropy) {
        this(name, regex, severity, requiresEntropy, Pattern.compile(regex), derivePreFilter(regex));
    }

    /**
     * Derive a cheap substring pre-filter from the pattern's literal prefix.
     * If the pattern starts with a literal token (e.g. "AKIA", "ASIA",
     * "secret_", "ATATT3xFfGF0", "00", "PMAK-"), that token MUST appear in
     * the body for the regex to ever match. We can short-circuit the full
     * regex scan by checking {@code body.contains(preFilter)} first —
     * {@code String.contains} uses Boyer-Moore-style search and is
     * dramatically faster than running 120+ regex engines over a 3MB JS
     * bundle.
     *
     * Conservative: returns null when no obvious literal prefix exists
     * (e.g. patterns starting with {@code (?i)}, character classes, or
     * digit shorthands).
     */
    private static String derivePreFilter(String regex) {
        String r = regex;
        if (r.startsWith("(?i)")) r = r.substring(4);
        if (r.startsWith("^")) r = r.substring(1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < r.length(); i++) {
            char c = r.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '_' || c == '-' || c == '.') {
                sb.append(c);
            } else {
                break;
            }
        }
        // Require >=4 char literal prefix; shorter prefixes have too many
        // false-positive substrings and the savings disappear.
        if (sb.length() < 4) return null;
        return sb.toString();
    }
}
