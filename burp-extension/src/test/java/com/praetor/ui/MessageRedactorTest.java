package com.praetor.ui;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure-transform cover for render-time redaction. A secret that survives any of
 * these would reach the screenshot pixels — the exact leak this feature exists to
 * stop — so each case asserts the raw secret is GONE, not merely that a glyph
 * appears somewhere.
 */
class MessageRedactorTest {

    private static final String G = RedactRules.GLYPH;

    // ── header values ──

    @Test
    void cookieHeaderRedactsEveryValueKeepsNames() {
        String out = MessageRedactor.redactHeaderValue("Cookie",
            "SESSION=abc123; csrftoken=deadbeef", G);
        assertTrue(out.contains("SESSION="), "cookie name kept");
        assertTrue(out.contains("csrftoken="), "second cookie name kept");
        assertFalse(out.contains("abc123"), "first value gone");
        assertFalse(out.contains("deadbeef"), "second value gone");
    }

    @Test
    void setCookieRedactsOnlyTheCookieValueKeepsAttributes() {
        String out = MessageRedactor.redactHeaderValue("Set-Cookie",
            "SESSION=secretval; Path=/; HttpOnly; SameSite=Lax", G);
        assertFalse(out.contains("secretval"), "cookie value gone");
        assertTrue(out.contains("Path=/"), "Path attribute kept");
        assertTrue(out.contains("HttpOnly"), "HttpOnly attribute kept");
        assertTrue(out.contains("SameSite=Lax"), "SameSite attribute kept");
    }

    @Test
    void authorizationKeepsSchemeHidesCredential() {
        String out = MessageRedactor.redactHeaderValue("Authorization",
            "Bearer eyJhbGciOiJIUzI1NiJ9.Zm9v.c2ln", G);
        assertTrue(out.startsWith("Bearer "), "scheme kept");
        assertFalse(out.contains("eyJhbGciOiJIUzI1NiJ9"), "token gone");
    }

    @Test
    void authorizationWithoutSchemeIsGlyphedWhole() {
        assertEquals(G, MessageRedactor.redactHeaderValue("Authorization", "rawtokenonly", G));
    }

    @Test
    void genericSecretHeaderGlyphsWholeValue() {
        assertEquals(G, MessageRedactor.redactHeaderValue("X-Api-Key", "sk_live_abcdef", G));
    }

    // ── query string ──

    @Test
    void queryRedactsNamedParamsOnly() {
        String out = MessageRedactor.redactPath("/u?id=42&token=abcdef&q=hi",
            Set.of("token"), G);
        assertTrue(out.contains("id=42"), "non-secret param kept");
        assertTrue(out.contains("q=hi"), "non-secret param kept");
        assertFalse(out.contains("abcdef"), "token value gone");
        assertTrue(out.contains("token="), "token key kept");
    }

    @Test
    void pathWithoutQueryIsUnchanged() {
        assertEquals("/a/b", MessageRedactor.redactPath("/a/b", Set.of("token"), G));
    }

    // ── body ──

    @Test
    void bodyRedactsJwt() {
        String body = "{\"data\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123\"}";
        String out = MessageRedactor.redactBodyText(body, Set.of(), true, G);
        assertFalse(out.contains("eyJhbGciOiJIUzI1NiJ9"), "JWT gone");
    }

    @Test
    void bodyRedactsJsonFieldValueKeepsKey() {
        String body = "{\"password\":\"hunter2\",\"user\":\"bob\"}";
        String out = MessageRedactor.redactBodyText(body, Set.of("password"), false, G);
        assertFalse(out.contains("hunter2"), "password value gone");
        assertTrue(out.contains("\"password\""), "password key kept");
        assertTrue(out.contains("\"user\":\"bob\""), "other field untouched");
    }

    @Test
    void bodyRedactsFormEncodedValue() {
        String out = MessageRedactor.redactBodyText(
            "user=bob&password=hunter2&remember=1", Set.of("password"), false, G);
        assertFalse(out.contains("hunter2"), "password value gone");
        assertTrue(out.contains("user=bob"), "other field kept");
        assertTrue(out.contains("remember=1"), "trailing field kept");
    }

    // ── config parsing ──

    @Test
    void defaultsConfigIsActiveAndCoversKnownSecrets() {
        MessageRedactor.Config cfg = MessageRedactor.configFrom(Map.of("redact", true));
        assertTrue(cfg.isActive());
        assertTrue(RedactRules.matches(cfg.secretHeaders, "cookie"));
        assertTrue(cfg.queryParams.contains("access_token"));
        assertTrue(cfg.bodyFields.contains("password"));
    }

    @Test
    void noRedactKeyMeansInactive() {
        assertFalse(MessageRedactor.configFrom(Map.of()).isActive());
    }

    @Test
    void hideGroupsExpandToHeaderNames() {
        MessageRedactor.Config cfg = MessageRedactor.configFrom(
            Map.of("hide_groups", List.of("browser")));
        assertTrue(cfg.isActive());
        assertTrue(RedactRules.matches(cfg.hideHeaders, "accept-encoding"));
        assertTrue(RedactRules.matches(cfg.hideHeaders, "sec-ch-ua"));
    }

    @Test
    void customHeaderListMergesOntoDefaults() {
        MessageRedactor.Config cfg = MessageRedactor.configFrom(Map.of(
            "redact", true, "redact_headers", List.of("X-Secret-Thing")));
        assertTrue(RedactRules.matches(cfg.secretHeaders, "x-secret-thing"));
        assertTrue(RedactRules.matches(cfg.secretHeaders, "cookie"), "defaults kept");
    }

    @Test
    void customGlyphOverrides() {
        MessageRedactor.Config cfg = MessageRedactor.configFrom(Map.of(
            "redact", true, "redact_glyph", "[REDACTED]"));
        assertEquals("[REDACTED]", cfg.glyph);
    }
}
