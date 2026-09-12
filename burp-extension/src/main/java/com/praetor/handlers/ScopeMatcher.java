package com.praetor.handlers;

import java.util.*;
import java.util.regex.*;

/** Auto-filter domain list + pure domain/URL matchers, split from ScopeHandler.
 *  Scope decision logic stays in ScopeHandler; only these pure helpers moved. */
final class ScopeMatcher {

    private ScopeMatcher() {}

    public static final List<String> AUTO_FILTER_DOMAINS = List.of(
        // Trackers
        "google-analytics.com", "analytics.google.com", "mixpanel.com",
        "hotjar.com", "segment.io", "segment.com", "amplitude.com",
        "heap.io", "heapanalytics.com", "pendo.io",
        // Ad networks
        "googlesyndication.com", "doubleclick.net", "adroll.com",
        "criteo.com", "criteo.net", "amazon-adsystem.com", "adnxs.com",
        "adsrvr.org", "taboola.com", "outbrain.com",
        // CDN
        "cloudflare.com", "cdnjs.cloudflare.com", "fastly.net",
        "akamai.net", "akamaized.net", "cloudfront.net", "jsdelivr.net",
        "unpkg.com", "cdnjs.com",
        // Fonts
        "fonts.googleapis.com", "fonts.gstatic.com", "use.typekit.net",
        "use.fontawesome.com",
        // Social
        "connect.facebook.net", "platform.twitter.com",
        "platform.linkedin.com", "apis.google.com",
        // Analytics
        "googletagmanager.com", "tealiumiq.com", "tags.tiqcdn.com",
        "assets.adobedtm.com", "bat.bing.com",
        // Error tracking
        "sentry.io", "bugsnag.com", "browser-intake-datadoghq.com",
        "js-agent.newrelic.com", "bam.nr-data.net", "clarity.ms",
        "fullstory.com", "mouseflow.com", "crazyegg.com", "inspectlet.com",
        // Misc
        "recaptcha.net", "gstatic.com", "gravatar.com", "wp.com",
        "stats.wp.com", "pixel.wp.com", "cookielaw.org", "onetrust.com",
        "trustarc.com", "intercom.io", "intercomcdn.com", "pusher.com",
        "pusherapp.com",
        // Stripe is intentionally NOT auto-filtered: payment integrations are
        // first-class attack surface for fintech engagements (webhook
        // verification, IAP bypass, setup_intent business logic, BOLA on
        // payment_method/customer IDs). Operators who want to drop Stripe can
        // exclude it explicitly via configure_scope(exclude=[...]).
        "maps.googleapis.com", "maps.gstatic.com"
    );

    static boolean matchesDomainPattern(String domain, String pattern) {
        if (domain == null || pattern == null) return false;
        String d = domain.toLowerCase(Locale.ROOT);
        String p = pattern.toLowerCase(Locale.ROOT);
        if (p.startsWith("*.")) {
            String suffix = p.substring(1); // ".google.com"
            return d.equals(suffix.substring(1)) || d.endsWith(suffix);
        }
        if (d.equals(p)) return true;
        return d.endsWith("." + p);
    }

    /**
     * Normalizes a scope pattern to a URL suitable for the Montoya scope API.
     * - Already http/https: returned as-is
     * - Starts with *.: strip wildcard prefix, prepend https://
     * - Bare domain: prepend https://
     */
    static String normalizeToUrl(String pattern) {
        if (pattern.startsWith("http://") || pattern.startsWith("https://")) {
            return pattern;
        }
        if (pattern.startsWith("*.")) {
            return "https://" + pattern.substring(2);
        }
        return "https://" + pattern;
    }
}
