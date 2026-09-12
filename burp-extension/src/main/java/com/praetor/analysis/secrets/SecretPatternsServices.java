package com.praetor.analysis.secrets;

import java.util.List;

/** Payment / registry / SaaS secret patterns — split from SecretPatterns to keep each file under 300 lines. */
final class SecretPatternsServices {
    private SecretPatternsServices() {}

    private static final String CRITICAL = SecretPatterns.CRITICAL;
    private static final String HIGH = SecretPatterns.HIGH;
    private static final String MEDIUM = SecretPatterns.MEDIUM;
    private static final String LOW = SecretPatterns.LOW;

    static void contribute(List<SecretPattern> p) {
        // =========================================================================
        // PAYMENT PLATFORMS
        // =========================================================================

        // Stripe
        p.add(new SecretPattern("stripe-secret-key",
                "sk_(?:test|live)_[0-9a-zA-Z]{24,}", CRITICAL, false));
        p.add(new SecretPattern("stripe-publishable-key",
                "pk_(?:test|live)_[0-9a-zA-Z]{24,}", MEDIUM, false));
        p.add(new SecretPattern("stripe-restricted-key",
                "rk_(?:test|live)_[0-9a-zA-Z]{24,}", HIGH, false));
        p.add(new SecretPattern("stripe-webhook-secret",
                "whsec_[A-Za-z0-9]{32,}", HIGH, false));

        // Square
        p.add(new SecretPattern("square-access-token",
                "sq0atp-[0-9A-Za-z_-]{22}", HIGH, false));
        p.add(new SecretPattern("square-oauth-secret",
                "sq0csp-[0-9A-Za-z_-]{43}", HIGH, false));

        // Braintree
        p.add(new SecretPattern("braintree-access-token",
                "access_token\\$(?:production|sandbox)\\$[a-z0-9]{16}\\$[a-f0-9]{32}", HIGH, false));

        // PayPal
        p.add(new SecretPattern("paypal-braintree-token",
                "(?i)(?:paypal|braintree).{0,15}(?:secret|token)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_-]{32,}", HIGH, true));

        // =========================================================================
        // EMAIL / SMS SERVICES
        // =========================================================================

        p.add(new SecretPattern("twilio-api-key",
                "SK[0-9a-fA-F]{32}", HIGH, false));
        p.add(new SecretPattern("twilio-account-sid",
                "AC[0-9a-fA-F]{32}", MEDIUM, false));
        p.add(new SecretPattern("sendgrid-api-key",
                "SG\\.[0-9A-Za-z_-]{22,}\\.[0-9A-Za-z_-]{22,}", HIGH, false));
        p.add(new SecretPattern("mailgun-api-key",
                "key-[0-9a-zA-Z]{32}", HIGH, false));
        p.add(new SecretPattern("mailchimp-api-key",
                "[0-9a-f]{32}-us[0-9]{1,2}", HIGH, false));
        p.add(new SecretPattern("postmark-server-token",
                "(?i)(?:postmark|pmak).{0,10}(?:token|key)[\"'\\s]*[:=][\"'\\s]*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", HIGH, false));

        // =========================================================================
        // PACKAGE REGISTRIES
        // =========================================================================

        p.add(new SecretPattern("npm-token",
                "npm_[A-Za-z0-9]{36}", HIGH, false));
        p.add(new SecretPattern("pypi-token",
                "pypi-[A-Za-z0-9_-]{50,}", HIGH, false));
        p.add(new SecretPattern("nuget-api-key",
                "oy2[a-z0-9]{43}", HIGH, false));
        p.add(new SecretPattern("rubygems-api-key",
                "rubygems_[a-f0-9]{48}", HIGH, false));
        p.add(new SecretPattern("docker-config-auth",
                "(?i)\"auth\"\\s*:\\s*\"[A-Za-z0-9+/=]{20,}\"", MEDIUM, false));

        // =========================================================================
        // MONITORING / OBSERVABILITY
        // =========================================================================

        p.add(new SecretPattern("datadog-api-key",
                "(?i)(?:datadog|dd).{0,15}(?:api.?key|key)[\"'\\s]*[:=][\"'\\s]*[a-f0-9]{32}", HIGH, false));
        p.add(new SecretPattern("datadog-app-key",
                "(?i)(?:datadog|dd).{0,15}app.?key[\"'\\s]*[:=][\"'\\s]*[a-f0-9]{40}", HIGH, false));
        p.add(new SecretPattern("new-relic-key",
                "(?i)(?:new.?relic).{0,15}(?:key|license)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_-]{32,}", HIGH, true));
        p.add(new SecretPattern("sentry-dsn",
                "https://[a-f0-9]{32}@(?:o[0-9]+\\.)?(?:sentry\\.io|[^/]+)/[0-9]+", HIGH, false));
        p.add(new SecretPattern("grafana-api-key",
                "eyJrIjoi[A-Za-z0-9+/=]{40,}", HIGH, false));
        p.add(new SecretPattern("pagerduty-token",
                "(?i)(?:pagerduty).{0,15}(?:key|token)[\"'\\s]*[:=][\"'\\s]*[A-Za-z0-9_+/-]{20}", HIGH, true));

        // =========================================================================
        // BACKEND / INFRASTRUCTURE
        // =========================================================================

        // Supabase
        p.add(new SecretPattern("supabase-anon-key",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.[A-Za-z0-9_-]{50,}\\.[A-Za-z0-9_-]{20,}", MEDIUM, false));
        p.add(new SecretPattern("supabase-service-role-key",
                "(?i)(?:supabase.{0,10}service.{0,5}(?:role|key))[\"'\\s]*[:=][\"'\\s]*eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+", CRITICAL, false));

        // HashiCorp Vault
        p.add(new SecretPattern("vault-token",
                "hvs\\.[A-Za-z0-9_-]{24,}", CRITICAL, false));
        p.add(new SecretPattern("vault-batch-token",
                "hvb\\.[A-Za-z0-9_-]{24,}", HIGH, false));

        // Doppler
        p.add(new SecretPattern("doppler-token",
                "dp\\.(?:st|ct|sa|scim|audit)\\.[A-Za-z0-9_-]{40,}", HIGH, false));

        // Mapbox
        p.add(new SecretPattern("mapbox-secret-token",
                "sk\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{20,}", HIGH, false));
        p.add(new SecretPattern("mapbox-public-token",
                "pk\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{20,}", LOW, false));

        // Shopify
        p.add(new SecretPattern("shopify-access-token",
                "shpat_[a-fA-F0-9]{32}", HIGH, false));
        p.add(new SecretPattern("shopify-shared-secret",
                "shpss_[a-fA-F0-9]{32}", HIGH, false));
        p.add(new SecretPattern("shopify-custom-app-token",
                "shpca_[a-fA-F0-9]{32}", HIGH, false));
        p.add(new SecretPattern("shopify-private-app-password",
                "shppa_[a-fA-F0-9]{32}", HIGH, false));

        // Algolia
        p.add(new SecretPattern("algolia-api-key",
                "(?i)(?:algolia).{0,15}(?:api.?key|admin.?key|key)[\"'\\s]*[:=][\"'\\s]*[a-f0-9]{32}", HIGH, true));

    }
}
