package com.praetor.handlers.http;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cookie-jar carry-over across followed redirects. The bug: the redirect loop
 * copied the previous request's Cookie header verbatim and ignored the
 * response's Set-Cookie, so an auth cookie set by a 302 never reached the
 * followed request — a login POST that 302s to /my-account bounced back to
 * /login. A browser keeps a jar; these helpers give CurlSender the same.
 */
class CurlSenderCookieJarTest {

    @Test
    void setCookieOverwritesSeededValue() {
        // Reproduces the login flow: jar seeded with the pre-auth session,
        // the 302 sets the authenticated session, the next hop must send it.
        Map<String, String> jar = new LinkedHashMap<>();
        jar.put("session", "PRE_AUTH");
        CurlSender.mergeSetCookieHeaders(jar,
            List.of("session=AUTHED; Secure; HttpOnly; SameSite=None; Path=/"));
        assertEquals("AUTHED", jar.get("session"),
            "302's Set-Cookie must overwrite the seeded session in the jar");
        assertEquals("session=AUTHED", CurlSender.renderCookieHeader(jar));
    }

    @Test
    void mergeAddsNewCookieAndKeepsExisting() {
        Map<String, String> jar = new LinkedHashMap<>();
        jar.put("TrackingId", "abc");
        CurlSender.mergeSetCookieHeaders(jar, List.of("session=xyz; Path=/"));
        assertEquals("abc", jar.get("TrackingId"));
        assertEquals("xyz", jar.get("session"));
        assertEquals("TrackingId=abc; session=xyz", CurlSender.renderCookieHeader(jar));
    }

    @Test
    void attributesAndValuelessEntriesAreIgnored() {
        Map<String, String> jar = new LinkedHashMap<>();
        // no name= before ';' -> skipped; attribute-only garbage -> skipped
        CurlSender.mergeSetCookieHeaders(jar, List.of("=orphan; Path=/", "; HttpOnly"));
        assertTrue(jar.isEmpty(), "malformed Set-Cookie must not enter the jar");
    }

    @Test
    void valueMayContainEquals() {
        Map<String, String> jar = new LinkedHashMap<>();
        CurlSender.mergeSetCookieHeaders(jar, List.of("token=a=b=c; Path=/"));
        assertEquals("a=b=c", jar.get("token"), "only the first '=' splits name/value");
    }

    @Test
    void nullListAndNullEntryAreSafe() {
        Map<String, String> jar = new LinkedHashMap<>();
        CurlSender.mergeSetCookieHeaders(jar, null);
        assertTrue(jar.isEmpty());
        java.util.List<String> withNull = new java.util.ArrayList<>();
        withNull.add(null);
        withNull.add("a=b");
        CurlSender.mergeSetCookieHeaders(jar, withNull);
        assertEquals("b", jar.get("a"));
    }

    @Test
    void renderEmptyJarIsEmptyString() {
        assertEquals("", CurlSender.renderCookieHeader(new LinkedHashMap<>()));
    }
}
