package com.praetor.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.ArrayList;
import java.util.List;

/**
 * Resolve the Proxy → HTTP history index of a request Praetor just sent.
 *
 * <p>The obvious approach — {@code history.size() - 1} right after the send —
 * is wrong whenever the last entry is not the request we sent. That happens in
 * two routine cases, and every downstream artifact (evidence.logger_index, the
 * Burp annotation the operator screenshots, the exported PoC bundle) then cites
 * the wrong traffic:
 *
 * <ul>
 *   <li><b>Redirect following.</b> Each followed hop appends its own history
 *       entry, so {@code size()-1} is the final hop (the redirect target), not
 *       the payload-carrying request the finding is about.</li>
 *   <li><b>Concurrent traffic.</b> A browser crawl, a parallel probe, or any
 *       other tool can append between the send and the size read, so
 *       {@code size()-1} is some other tool's request.</li>
 * </ul>
 *
 * <p>Instead we record the history size <em>before</em> the send and, among the
 * entries added since, pick the one whose (method, URL[, body]) matches the
 * request we sent. Following the {@link EvidenceMatch} pattern, the matching
 * logic is a pure method ({@link #pick}) that unit tests exercise directly; the
 * Montoya-facing {@link #locate} only adapts live history into it.
 *
 * <p>NOTE (ceiling): two in-flight requests identical in method+URL+body from
 * different tools are indistinguishable here — {@code pick} returns the earliest
 * such entry. Upgrade path if that ever bites: stamp a per-send nonce header and
 * match on it.
 */
public final class ProxyHistoryLocator {

    private ProxyHistoryLocator() {}

    /** Minimal projection of a history entry's request needed to identify it. */
    public record Entry(String method, String url, String body) {}

    /**
     * Locate the entry for {@code target} among the history entries added since
     * {@code preSize}.
     *
     * @return the absolute proxy-history index, or -1 when nothing new landed
     *         (the send did not reach Proxy history).
     */
    public static int locate(MontoyaApi api, HttpRequest target, int preSize) {
        if (api == null || target == null) return -1;
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        int postSize = history.size();
        if (preSize < 0) preSize = 0;
        if (postSize <= preSize) return -1;

        // Only project the new window, not the whole (possibly 50K-entry) history.
        List<Entry> window = new ArrayList<>(postSize - preSize);
        for (int i = preSize; i < postSize; i++) {
            Entry e = null;
            try {
                HttpRequest r = history.get(i).finalRequest();
                if (r != null) e = new Entry(safe(r::method), safe(r::url), safe(r::bodyToString));
            } catch (Exception ignored) {}
            window.add(e);
        }
        return pick(window, preSize, safe(target::method), safe(target::url), safe(target::bodyToString));
    }

    /**
     * Pure matcher. {@code window} holds the entries added since the send, in
     * order; {@code windowStart} is the absolute index of {@code window.get(0)}.
     *
     * <p>Returns the absolute index of the earliest full (method+URL+body) match,
     * else the earliest method+URL match, else the last new entry (legacy
     * {@code size()-1} behaviour — only reached when identity matching fails,
     * e.g. header/URL normalisation or async-flush lag).
     */
    static int pick(List<Entry> window, int windowStart,
                    String wantMethod, String wantUrl, String wantBody) {
        if (window == null || window.isEmpty()) return -1;
        String wm = wantMethod == null ? "" : wantMethod;
        String wu = wantUrl == null ? "" : wantUrl;
        String wb = wantBody == null ? "" : wantBody;

        int urlOnly = -1;
        for (int i = 0; i < window.size(); i++) {
            Entry e = window.get(i);
            if (e == null) continue;
            if (!wm.equalsIgnoreCase(e.method() == null ? "" : e.method())) continue;
            if (!urlsEqual(wu, e.url())) continue;
            if (wb.isEmpty() || wb.equals(e.body() == null ? "" : e.body())) {
                return windowStart + i;  // earliest exact identity match wins
            }
            if (urlOnly < 0) urlOnly = windowStart + i;
        }
        if (urlOnly >= 0) return urlOnly;
        return windowStart + window.size() - 1;
    }

    /** Equal, or equal after stripping a default port and one trailing slash. */
    static boolean urlsEqual(String a, String b) {
        if (a == null || b == null) return false;
        if (a.equals(b)) return true;
        return normalize(a).equals(normalize(b));
    }

    static String normalize(String url) {
        if (url == null) return "";
        String s = url.trim();
        s = s.replace(":80/", "/").replace(":443/", "/");
        if (s.endsWith(":80")) s = s.substring(0, s.length() - 3);
        else if (s.endsWith(":443")) s = s.substring(0, s.length() - 4);
        // Drop a single trailing slash on the whole URL (no path/query beyond it).
        if (s.length() > 1 && s.endsWith("/") && s.indexOf('?') < 0) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    private interface Getter { String get(); }

    private static String safe(Getter g) {
        try {
            String v = g.get();
            return v == null ? "" : v;
        } catch (Exception e) {
            return "";
        }
    }
}
