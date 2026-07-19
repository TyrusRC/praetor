package com.praetor.attack;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Smoke + behaviour coverage for {@link HppHandler}. The {@code handle}
 * method needs Montoya, so we test the package-private {@code buildUrl}
 * helper directly — same code path used to compose baseline + variant
 * request URLs for HPP probes.
 *
 * Behaviour-preserving from the pre-split AttackHandler.buildUrl.
 */
class HppHandlerTest {

    @Test
    void constructorAcceptsApi() {
        assertNotNull(new HppHandler(null));
    }

    @Test
    void buildUrlWithoutParamReturnsBasePlusPath() {
        assertEquals("https://t.example/api/users",
            HppHandler.buildUrl("https://t.example", "/api/users", null, null));
    }

    @Test
    void buildUrlStripsTrailingSlashWhenPathLeads() {
        // base has trailing slash AND path starts with slash -> single slash, not double.
        assertEquals("https://t.example/api/users",
            HppHandler.buildUrl("https://t.example/", "/api/users", null, null));
    }

    @Test
    void buildUrlAppendsEncodedQueryParam() {
        String url = HppHandler.buildUrl("https://t.example", "/q", "name", "alice & bob");
        assertTrue(url.startsWith("https://t.example/q?name="), "got " + url);
        assertTrue(url.contains("alice"), "got " + url);
        // Space encoded as '+', '&' encoded as %26 by URLEncoder.
        assertTrue(url.contains("%26"), "expected '&' to be encoded as %26, got " + url);
    }

    @Test
    void buildUrlEncodesReservedCharsInParamName() {
        String url = HppHandler.buildUrl("https://t.example", "/q", "weird name", "v");
        // Parameter name with space -> URLEncoder produces 'weird+name'.
        assertTrue(url.contains("weird+name=v"), "got " + url);
    }
}
