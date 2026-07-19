package com.praetor.analysis;

import com.praetor.analysis.secrets.SecretPattern;
import com.praetor.analysis.secrets.SecretPatterns;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * Extracts potential secrets, API keys, tokens, and sensitive data from
 * JavaScript responses. Patterns modeled after TruffleHog/Gitleaks with
 * Shannon entropy checks for generic detectors.
 *
 * Thin façade: the pattern catalog lives in {@link SecretPatterns}; this
 * class holds the run-the-catalog-over-a-body loop and the entropy / dedup /
 * context-window helpers.
 */
public final class JsSecretExtractor {

    private JsSecretExtractor() {}

    // Entropy threshold for generic patterns (passwords, generic API keys, etc.)
    private static final double ENTROPY_THRESHOLD = 3.5;

    /**
     * Extract secrets from a response body (typically JavaScript).
     *
     * @param body the response body text
     * @return map with total_secrets, secrets list
     */
    public static Map<String, Object> extract(String body) {
        if (body == null || body.isEmpty()) {
            Map<String, Object> empty = new LinkedHashMap<>();
            empty.put("total_secrets", 0);
            empty.put("secrets", Collections.emptyList());
            return empty;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> secrets = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        // Build a lower-cased view once for case-insensitive pre-filter checks.
        String bodyLower = body.toLowerCase(java.util.Locale.ROOT);
        for (SecretPattern sp : SecretPatterns.PATTERNS) {
            // Cheap-substring pre-filter: skip the regex scan entirely when
            // the pattern's literal prefix isn't in the body.
            if (sp.preFilter() != null) {
                String key = sp.preFilter().toLowerCase(java.util.Locale.ROOT);
                if (!bodyLower.contains(key)) continue;
            }
            Matcher matcher = sp.compiled().matcher(body);

            while (matcher.find()) {
                String match = matcher.group();

                if (sp.requiresEntropy()) {
                    String candidate = extractCandidate(match);
                    if (shannonEntropy(candidate) < ENTROPY_THRESHOLD) {
                        continue;
                    }
                }

                String dedupeKey = sp.name() + ":" + match;
                if (!seen.add(dedupeKey)) {
                    continue;
                }

                int ctxStart = Math.max(0, matcher.start() - 50);
                int ctxEnd = Math.min(body.length(), matcher.end() + 50);
                String context = body.substring(ctxStart, ctxEnd).replaceAll("[\\r\\n]+", " ");

                Map<String, Object> secret = new LinkedHashMap<>();
                secret.put("type", sp.name());
                secret.put("severity", sp.severity());
                secret.put("match", truncate(match, 200));
                secret.put("context", truncate(context, 300));
                secret.put("position", matcher.start());
                secrets.add(secret);
            }
        }

        // Sort by severity descending (CRITICAL > HIGH > MEDIUM > LOW)
        secrets.sort((a, b) -> severityRank((String) b.get("severity")) - severityRank((String) a.get("severity")));

        result.put("total_secrets", secrets.size());
        result.put("secrets", secrets);
        return result;
    }

    /**
     * Calculate Shannon entropy of a string. Higher values indicate more randomness.
     * Typical thresholds: random API keys >= 4.0, English words ~3.0, placeholders < 3.0.
     */
    static double shannonEntropy(String s) {
        if (s == null || s.length() < 2) return 0.0;

        int[] freq = new int[256];
        for (int i = 0; i < s.length(); i++) {
            freq[s.charAt(i) & 0xFF]++;
        }

        double entropy = 0.0;
        double len = s.length();
        for (int f : freq) {
            if (f == 0) continue;
            double p = f / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    /**
     * Extract the value portion from a key=value or key: value match.
     * For patterns like `password = "hunter2"`, returns `hunter2`.
     */
    private static String extractCandidate(String match) {
        int idx = -1;
        for (int i = 0; i < match.length(); i++) {
            char c = match.charAt(i);
            if (c == '=' || c == ':') {
                idx = i;
                break;
            }
        }
        if (idx < 0) return match;

        String valuePart = match.substring(idx + 1).trim();
        if (valuePart.length() >= 2) {
            char first = valuePart.charAt(0);
            char last = valuePart.charAt(valuePart.length() - 1);
            if ((first == '\'' || first == '"') && first == last) {
                return valuePart.substring(1, valuePart.length() - 1);
            }
        }
        return valuePart;
    }

    private static int severityRank(String severity) {
        return switch (severity) {
            case SecretPatterns.CRITICAL -> 4;
            case SecretPatterns.HIGH -> 3;
            case SecretPatterns.MEDIUM -> 2;
            case SecretPatterns.LOW -> 1;
            default -> 0;
        };
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }
}
