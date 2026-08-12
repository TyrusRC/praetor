package com.praetor.util;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression cover for the "wrong PoC highlighted / commented" defect.
 *
 * The send handlers used to report {@code history.size() - 1} as the index of
 * the request they sent. That is the LAST proxy-history entry, which is not the
 * request we sent whenever a redirect hop or another tool's request landed after
 * it. The wrong index then flowed into evidence.logger_index, the Burp
 * annotation, the screenshot, and the exported PoC bundle.
 *
 * These tests exercise the pure matcher against a simulated history window. The
 * {@code E(...)} helper builds an entry; {@code windowStart} is the pre-send
 * size, i.e. the absolute index of the first new entry.
 */
class ProxyHistoryLocatorTest {

    private static ProxyHistoryLocator.Entry E(String method, String url, String body) {
        return new ProxyHistoryLocator.Entry(method, url, body);
    }

    @Test
    void redirectChain_picksTheOriginalRequestNotTheFinalHop() {
        // Sent POST /login?next=... (the PoC); it 302'd to GET /dashboard.
        // Both hops appended, so size()-1 pointed at /dashboard.
        List<ProxyHistoryLocator.Entry> window = Arrays.asList(
            E("POST", "https://target.tld/login?next=x", "user=a&pw=b"),  // abs idx 5 — the PoC
            E("GET",  "https://target.tld/dashboard", "")                 // abs idx 6 — redirect hop
        );
        int idx = ProxyHistoryLocator.pick(window, 5, "POST", "https://target.tld/login?next=x", "user=a&pw=b");
        assertEquals(5, idx, "must resolve the payload-carrying request, not the redirect target");
        assertNotEquals(6, idx, "size()-1 (the final hop) is the old, wrong answer");
    }

    @Test
    void concurrentTraffic_skipsAnotherToolsRequest() {
        // Our GET landed, then a browser crawl appended an asset fetch.
        List<ProxyHistoryLocator.Entry> window = Arrays.asList(
            E("GET", "https://target.tld/api/orders/42", ""),   // abs idx 10 — ours
            E("GET", "https://cdn.other.tld/logo.png", "")       // abs idx 11 — someone else's
        );
        int idx = ProxyHistoryLocator.pick(window, 10, "GET", "https://target.tld/api/orders/42", "");
        assertEquals(10, idx);
    }

    @Test
    void identicalUrlDifferentBody_disambiguatesByBody() {
        // Two probes to the same endpoint in the window; body picks ours.
        List<ProxyHistoryLocator.Entry> window = Arrays.asList(
            E("POST", "https://target.tld/api/x", "id=1"),
            E("POST", "https://target.tld/api/x", "id=2' OR '1'='1")
        );
        int idx = ProxyHistoryLocator.pick(window, 3, "POST", "https://target.tld/api/x", "id=2' OR '1'='1");
        assertEquals(4, idx);
    }

    @Test
    void noMatch_fallsBackToLastNewEntry() {
        // Nothing matches method+URL (e.g. normalisation surprise). Preserve the
        // legacy last-entry behaviour rather than returning -1 and breaking the flow.
        List<ProxyHistoryLocator.Entry> window = Arrays.asList(
            E("GET", "https://a.tld/1", ""),
            E("GET", "https://a.tld/2", "")
        );
        int idx = ProxyHistoryLocator.pick(window, 7, "GET", "https://a.tld/999", "");
        assertEquals(8, idx, "windowStart(7) + size(2) - 1");
    }

    @Test
    void emptyWindow_returnsMinusOne() {
        assertEquals(-1, ProxyHistoryLocator.pick(List.of(), 4, "GET", "https://a.tld/", ""));
    }

    @Test
    void nullEntriesInWindowAreSkipped() {
        List<ProxyHistoryLocator.Entry> window = Arrays.asList(
            null,
            E("GET", "https://a.tld/hit", "")
        );
        int idx = ProxyHistoryLocator.pick(window, 0, "GET", "https://a.tld/hit", "");
        assertEquals(1, idx);
    }

    @Test
    void urlEqualityToleratesDefaultPortAndTrailingSlash() {
        assertTrue(ProxyHistoryLocator.urlsEqual("https://a.tld:443/x", "https://a.tld/x"));
        assertTrue(ProxyHistoryLocator.urlsEqual("http://a.tld:80/x", "http://a.tld/x"));
        assertTrue(ProxyHistoryLocator.urlsEqual("https://a.tld/x/", "https://a.tld/x"));
        assertFalse(ProxyHistoryLocator.urlsEqual("https://a.tld/x", "https://a.tld/y"));
    }
}
