package com.praetor.ui;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Safe-by-default catalogs for render-time redaction — the secret-bearing header
 * names, the body/URL secret patterns, and the noisy-header hide groups. The
 * extension owns this set so EVERY host (Claude or not) gets the same safe
 * default without shipping the rules over the wire. {@link MessageRedactor}
 * applies them to a request/response BEFORE the capture, so a secret is gone
 * from the pixels — not merely blurred after the fact, which OCR can miss.
 *
 * <p>Pure data + helpers. No Burp types, so it is unit-tested without a running
 * Burp (see {@code MessageRedactorTest}).
 */
public final class RedactRules {

    private RedactRules() {}

    /** The redaction glyph. A run of full blocks reads clearly as "removed". */
    public static final String GLYPH = "████████";

    /** Header names whose VALUE carries a secret — value is replaced, name kept
     *  so the reader still sees which header it was (e.g. {@code Cookie: ████}). */
    public static final Set<String> SECRET_HEADERS = lower(
        "cookie", "set-cookie", "authorization", "proxy-authorization",
        "x-api-key", "api-key", "apikey", "x-auth-token", "auth-token",
        "x-csrf-token", "x-xsrf-token", "x-session-token", "x-access-token",
        "x-amz-security-token", "x-amz-credential", "x-goog-api-key",
        "x-functions-key", "x-vault-token", "x-vercel-protection-bypass",
        "www-authenticate", "proxy-authenticate");

    /** URL query-parameter names whose VALUE carries a secret. */
    public static final Set<String> SECRET_QUERY_PARAMS = lower(
        "token", "access_token", "refresh_token", "id_token", "auth",
        "api_key", "apikey", "key", "secret", "client_secret", "code",
        "sig", "signature", "password", "pwd", "passwd", "session",
        "sessionid", "sid", "jwt", "x-amz-signature", "x-goog-signature");

    /** JSON/body field names whose VALUE carries a secret (JSON or form-encoded). */
    public static final Set<String> SECRET_BODY_FIELDS = lower(
        "password", "passwd", "pwd", "secret", "client_secret", "token",
        "access_token", "refresh_token", "id_token", "api_key", "apikey",
        "private_key", "session", "otp", "pin", "cvv", "card", "ssn");

    /** A JWT anywhere in text (header.payload.signature, base64url parts). */
    public static final Pattern JWT =
        Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}");

    /** Noisy header groups a report does not need. Hidden on request, kept out of
     *  the shot to make the evidence line itself the prominent element. Grouped so
     *  a caller hides by theme; {@link #hideGroup} expands a group name to names. */
    public static final Set<String> HIDE_BROWSER = lower(
        "accept", "accept-encoding", "accept-language", "accept-charset",
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "sec-ch-ua-arch", "sec-ch-ua-full-version", "sec-ch-ua-full-version-list",
        "sec-ch-ua-model", "sec-ch-ua-platform-version", "sec-ch-ua-bitness",
        "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
        "sec-gpc", "upgrade-insecure-requests", "dnt", "priority", "te");

    public static final Set<String> HIDE_CACHING = lower(
        "cache-control", "pragma", "expires", "age", "etag", "if-none-match",
        "if-modified-since", "last-modified", "vary", "x-cache", "x-cache-hits",
        "cf-cache-status", "x-served-by", "x-timer", "cf-ray");

    public static final Set<String> HIDE_CORS = lower(
        "access-control-allow-origin", "access-control-allow-methods",
        "access-control-allow-headers", "access-control-allow-credentials",
        "access-control-expose-headers", "access-control-max-age",
        "access-control-request-method", "access-control-request-headers",
        "origin", "timing-allow-origin");

    public static final Set<String> HIDE_SECURITY_NOISE = lower(
        "strict-transport-security", "x-content-type-options", "x-frame-options",
        "x-xss-protection", "content-security-policy",
        "content-security-policy-report-only", "referrer-policy",
        "permissions-policy", "cross-origin-opener-policy",
        "cross-origin-embedder-policy", "cross-origin-resource-policy",
        "report-to", "nel", "expect-ct");

    public static final Set<String> HIDE_TRACING = lower(
        "x-request-id", "x-correlation-id", "x-trace-id", "x-amzn-trace-id",
        "traceparent", "tracestate", "x-b3-traceid", "x-b3-spanid",
        "x-b3-parentspanid", "x-b3-sampled", "x-datadog-trace-id",
        "x-datadog-parent-id", "x-envoy-upstream-service-time",
        "server-timing", "x-powered-by", "via", "x-served-time");

    /** Expand a hide-group name to its header names. Unknown group -&gt; empty. */
    public static Set<String> hideGroup(String group) {
        if (group == null) {
            return Set.of();
        }
        switch (group.trim().toLowerCase()) {
            case "browser": return HIDE_BROWSER;
            case "caching": return HIDE_CACHING;
            case "cors": return HIDE_CORS;
            case "security": return HIDE_SECURITY_NOISE;
            case "tracing": return HIDE_TRACING;
            case "all": {
                Set<String> all = new LinkedHashSet<>();
                all.addAll(HIDE_BROWSER);
                all.addAll(HIDE_CACHING);
                all.addAll(HIDE_CORS);
                all.addAll(HIDE_SECURITY_NOISE);
                all.addAll(HIDE_TRACING);
                return all;
            }
            default: return Set.of();
        }
    }

    private static Set<String> lower(String... names) {
        Set<String> s = new LinkedHashSet<>();
        for (String n : names) {
            s.add(n.toLowerCase());
        }
        return s;
    }

    /** True when {@code name} matches any entry of {@code set}, case-insensitively. */
    public static boolean matches(Set<String> set, String name) {
        return name != null && set.contains(name.trim().toLowerCase());
    }

    /** Case-insensitive copy of {@code names} as a mutable set (for merges). */
    public static Set<String> toLowerSet(Iterable<String> names) {
        Set<String> s = new LinkedHashSet<>();
        if (names != null) {
            for (String n : names) {
                if (n != null && !n.isBlank()) {
                    s.add(n.trim().toLowerCase());
                }
            }
        }
        return s;
    }

    static Set<String> union(Set<String> a, Iterable<String> b) {
        Set<String> s = new LinkedHashSet<>(a);
        s.addAll(toLowerSet(b));
        return s;
    }
}
