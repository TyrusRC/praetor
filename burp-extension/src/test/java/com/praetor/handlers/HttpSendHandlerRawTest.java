package com.praetor.handlers;

import burp.api.montoya.http.HttpMode;
import org.junit.jupiter.api.Test;

import static com.praetor.handlers.HttpSendHandler.hasHeader;
import static com.praetor.handlers.HttpSendHandler.insertHeaderBeforeBody;
import static com.praetor.handlers.HttpSendHandler.normalizeCrlf;
import static com.praetor.handlers.HttpSendHandler.parseHttpMode;
import static com.praetor.handlers.HttpSendHandler.requestTarget;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Calibration for the raw-send HTTP-version pin and CRLF normalisation added
 * for routing-based SSRF (absolute-URI request line must reach the target over
 * HTTP/1 verbatim, not be rewritten into HTTP/2 pseudo-headers).
 */
class HttpSendHandlerRawTest {

    @Test
    void unspecifiedVersionKeepsProxyTunnelDefault() {
        // null / blank => null => caller uses the proxy-tunnel path (AUTO).
        assertNull(parseHttpMode(null));
        assertNull(parseHttpMode(""));
        assertNull(parseHttpMode("   "));
    }

    @Test
    void http1SynonymsMapToHttp1() {
        for (String v : new String[]{"1", "1.0", "1.1", "HTTP/1", "http/1.1", " 1.1 "}) {
            assertEquals(HttpMode.HTTP_1, parseHttpMode(v), v);
        }
    }

    @Test
    void http2SynonymsMapToHttp2() {
        for (String v : new String[]{"2", "2.0", "HTTP/2"}) {
            assertEquals(HttpMode.HTTP_2, parseHttpMode(v), v);
        }
    }

    @Test
    void autoIsExplicitlySelectable() {
        assertEquals(HttpMode.AUTO, parseHttpMode("auto"));
    }

    @Test
    void unknownVersionFallsBackToTunnelDefault() {
        // Garbage must not silently become HTTP_1/2 — return null (tunnel default).
        assertNull(parseHttpMode("3"));
        assertNull(parseHttpMode("h2c"));
    }

    @Test
    void directIsNotAWireProtocolMode() {
        // "direct" selects the byte-exact direct-socket path (smuggling), not a
        // Montoya HttpMode — it must parse as null so the handler routes it to the
        // forceDirect branch instead of pinning HTTP_1/HTTP_2 via api.http().
        assertNull(parseHttpMode("direct"));
        assertNull(parseHttpMode("DIRECT"));
    }

    @Test
    void normalizeCrlfConvertsLoneLf() {
        String in = "GET https://t/ HTTP/1.1\nHost: 192.168.0.1\n\n";
        String out = normalizeCrlf(in);
        assertEquals("GET https://t/ HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n", out);
    }

    @Test
    void normalizeCrlfIsIdempotentOnWellFormed() {
        String good = "GET / HTTP/1.1\r\nHost: t\r\n\r\n";
        assertEquals(good, normalizeCrlf(good));
    }

    @Test
    void normalizeCrlfHandlesLoneCr() {
        assertEquals("a\r\nb", normalizeCrlf("a\rb"));
    }

    @Test
    void requestTargetExtractsAbsoluteUri() {
        // The routing-SSRF payload: the absolute target must survive so the
        // HTTP/1 send can re-assert it and keep the wire request line absolute.
        String raw = "GET https://lab.example/admin HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n";
        assertEquals("https://lab.example/admin", requestTarget(raw));
    }

    @Test
    void requestTargetExtractsOriginForm() {
        assertEquals("/admin", requestTarget("GET /admin HTTP/1.1\r\nHost: t\r\n\r\n"));
    }

    @Test
    void requestTargetHandlesLfOnlyAndMalformed() {
        assertEquals("/x", requestTarget("POST /x HTTP/1.1\nHost: t\n\n"));
        assertNull(requestTarget("GARBAGE"));
        assertNull(requestTarget(""));
        assertNull(requestTarget(null));
    }

    @Test
    void hasHeaderIsCaseInsensitiveAndScopedToHeaderBlock() {
        String raw = "GET / HTTP/1.1\r\nHost: t\r\nCookie: a=1\r\n\r\nbody-with-cookie-word";
        assertTrue(hasHeader(raw, "Cookie"));
        assertTrue(hasHeader(raw, "cookie"));
        assertTrue(hasHeader(raw, "HOST"));
        // A header-looking token only in the body is not a header.
        assertFalse(hasHeader("GET / HTTP/1.1\r\nHost: t\r\n\r\nCookie: x", "Cookie"));
    }

    @Test
    void insertHeaderGoesBeforeBlankLineAndPreservesBody() {
        String raw = "GET https://lab/admin HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n";
        String out = insertHeaderBeforeBody(raw, "Cookie: session=abc");
        assertEquals(
            "GET https://lab/admin HTTP/1.1\r\nHost: 192.168.0.1\r\nCookie: session=abc\r\n\r\n",
            out);
    }

    @Test
    void insertHeaderKeepsRequestLineAndBodyIntact() {
        String raw = "POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\n\r\nbody";
        String out = insertHeaderBeforeBody(raw, "Cookie: s=1");
        assertTrue(out.startsWith("POST /x HTTP/1.1\r\n"), out);
        assertTrue(out.endsWith("\r\n\r\nbody"), out);
        assertTrue(out.contains("Cookie: s=1\r\n"), out);
    }

    @Test
    void insertHeaderNoOpWithoutTerminator() {
        String raw = "GET / HTTP/1.1\r\nHost: t";
        assertEquals(raw, insertHeaderBeforeBody(raw, "Cookie: s=1"));
    }
}
