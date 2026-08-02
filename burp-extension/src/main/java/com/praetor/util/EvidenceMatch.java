package com.praetor.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.List;

/**
 * Cross-validates a cited history index against the endpoint a finding /
 * annotation claims to be about.
 *
 * <p>Every evidence path in Praetor (save_finding's evidence.logger_index,
 * reproductions[].logger_index, annotate_request's index) used to check only
 * that the integer was in range. An in-range index pointing at completely
 * unrelated traffic passed the gate, and every downstream artifact — the Burp
 * comment, the generated finding markdown, the client report — then cited a
 * request that had nothing to do with the finding. This class is the shared
 * check that closes that hole.
 *
 * <p>Deliberately lenient: it only fires when host or path actively disagree.
 * Unparseable input, an empty endpoint, or a path that is a prefix/suffix of
 * the other returns "match" so legitimate flows (path params, trailing
 * slashes, endpoint recorded without a scheme) are never blocked.
 */
public final class EvidenceMatch {

    private EvidenceMatch() {}

    /**
     * @return null when the index plausibly belongs to {@code endpoint};
     *         otherwise a one-line human description of the disagreement.
     */
    public static String describeMismatch(MontoyaApi api, int index, String endpoint) {
        if (endpoint == null || endpoint.isBlank()) return null;

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index < 0 || index >= history.size()) return null;  // bounds are the caller's job

        HttpRequest req;
        try {
            req = history.get(index).finalRequest();
        } catch (Exception e) {
            return null;
        }
        if (req == null) return null;

        String actualUrl;
        try {
            actualUrl = req.url();
        } catch (Exception e) {
            return null;
        }
        if (actualUrl == null || actualUrl.isBlank()) return null;

        String wantHost = hostOf(endpoint);
        String gotHost = hostOf(actualUrl);
        if (!wantHost.isEmpty() && !gotHost.isEmpty() && !hostsAgree(wantHost, gotHost)) {
            return "index #" + index + " is " + req.method() + " " + actualUrl
                 + " (host " + gotHost + "), finding endpoint is " + endpoint
                 + " (host " + wantHost + ")";
        }

        String wantPath = pathOf(endpoint);
        String gotPath = pathOf(actualUrl);
        if (!wantPath.isEmpty() && !gotPath.isEmpty() && !pathsAgree(wantPath, gotPath)) {
            return "index #" + index + " is " + req.method() + " " + actualUrl
                 + ", finding endpoint is " + endpoint;
        }
        return null;
    }

    /** Host portion of a URL or bare authority, lowercased and port-stripped. "" when absent. */
    static String hostOf(String url) {
        String s = url.trim();
        int scheme = s.indexOf("://");
        if (scheme >= 0) {
            s = s.substring(scheme + 3);
        } else if (s.startsWith("/")) {
            return "";  // path-only endpoint — nothing to compare
        }
        int slash = s.indexOf('/');
        if (slash >= 0) s = s.substring(0, slash);
        int at = s.indexOf('@');
        if (at >= 0) s = s.substring(at + 1);
        int colon = s.indexOf(':');
        if (colon >= 0) s = s.substring(0, colon);
        return s.toLowerCase();
    }

    /** Path portion, query/fragment stripped, trailing slash normalised. "" when absent. */
    static String pathOf(String url) {
        String s = url.trim();
        int scheme = s.indexOf("://");
        if (scheme >= 0) {
            int slash = s.indexOf('/', scheme + 3);
            s = (slash < 0) ? "/" : s.substring(slash);
        } else if (!s.startsWith("/")) {
            int slash = s.indexOf('/');
            s = (slash < 0) ? "" : s.substring(slash);
        }
        int q = s.indexOf('?');
        if (q >= 0) s = s.substring(0, q);
        int h = s.indexOf('#');
        if (h >= 0) s = s.substring(0, h);
        while (s.length() > 1 && s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s.toLowerCase();
    }

    /** Equal, or one is a subdomain-style suffix of the other (api.x.com vs x.com). */
    static boolean hostsAgree(String a, String b) {
        return a.equals(b) || a.endsWith("." + b) || b.endsWith("." + a);
    }

    /**
     * Equal, or one contains the other as a path segment — covers endpoints
     * recorded with a path parameter substituted ({@code /users/{id}} vs
     * {@code /users/42}) and base-path-vs-full-path records.
     */
    static boolean pathsAgree(String a, String b) {
        if (a.equals(b)) return true;
        if (a.equals("/") || b.equals("/")) return true;
        if (a.startsWith(b + "/") || b.startsWith(a + "/")) return true;
        // Placeholder-tolerant segment compare: /users/{id}/orders vs /users/42/orders
        String[] as = a.split("/");
        String[] bs = b.split("/");
        if (as.length != bs.length) return false;
        for (int i = 0; i < as.length; i++) {
            if (as[i].equals(bs[i])) continue;
            if (isPlaceholder(as[i]) || isPlaceholder(bs[i])) continue;
            return false;
        }
        return true;
    }

    private static boolean isPlaceholder(String seg) {
        if (seg.isEmpty()) return false;
        if (seg.startsWith("{") || seg.startsWith(":") || seg.startsWith("<")) return true;
        // A bare id segment on one side and a concrete id on the other.
        return seg.chars().allMatch(Character::isDigit);
    }
}
