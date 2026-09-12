package com.praetor.analysis.secrets;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Catalog of compiled secret-detection patterns. Modeled after TruffleHog and
 * Gitleaks, organized by provider (cloud / payment / chat / dev tools / SaaS).
 * Generic patterns (password=, api_key=) carry the requiresEntropy flag so
 * the consumer can Shannon-gate them.
 *
 * 120+ patterns; static-initialized once at class load. The pattern definitions
 * live in the SecretPatterns{Cloud,Services,AuthMisc} contributors to keep each
 * file under 300 lines; this class is the public facade.
 */
public final class SecretPatterns {

    private SecretPatterns() {}

    public static final String CRITICAL = "CRITICAL";
    public static final String HIGH = "HIGH";
    public static final String MEDIUM = "MEDIUM";
    public static final String LOW = "LOW";

    public static final List<SecretPattern> PATTERNS;

    static {
        List<SecretPattern> p = new ArrayList<>();
        SecretPatternsCloud.contribute(p);
        SecretPatternsServices.contribute(p);
        SecretPatternsAuthMisc.contribute(p);
        PATTERNS = Collections.unmodifiableList(p);
    }
}
