package com.praetor.http;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Calibration for ProxyWire.ensureConnectionClose — the verbatim-send path
 * relies on Connection: close so readAll() terminates at EOF. It must add the
 * header when absent, never duplicate one the operator set, and never mangle
 * the absolute-URI request line (the routing-SSRF payload).
 */
class ProxyWireConnectionCloseTest {

    private static byte[] b(String s) { return s.getBytes(StandardCharsets.ISO_8859_1); }
    private static String s(byte[] x) { return new String(x, StandardCharsets.ISO_8859_1); }

    @Test
    void addsConnectionCloseWhenAbsent() {
        String raw = "GET https://lab/ HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n";
        String out = s(ProxyWire.ensureConnectionClose(b(raw)));
        assertTrue(out.contains("Connection: close"), out);
        // Absolute-URI request line must be untouched.
        assertTrue(out.startsWith("GET https://lab/ HTTP/1.1\r\n"), out);
        // Header block still terminates with a blank line + preserves the target Host.
        assertTrue(out.contains("Host: 192.168.0.1\r\n"), out);
        assertTrue(out.endsWith("\r\n\r\n"), out);
    }

    @Test
    void doesNotDuplicateExistingConnectionHeader() {
        String raw = "GET / HTTP/1.1\r\nHost: t\r\nConnection: keep-alive\r\n\r\n";
        String out = s(ProxyWire.ensureConnectionClose(b(raw)));
        // Respect the operator's value; do not append a second Connection line.
        assertEquals(raw, out);
    }

    @Test
    void connectionHeaderMatchIsCaseInsensitive() {
        String raw = "GET / HTTP/1.1\r\nHost: t\r\nCONNECTION: close\r\n\r\n";
        assertEquals(raw, s(ProxyWire.ensureConnectionClose(b(raw))));
    }

    @Test
    void leavesBodyIntact() {
        String raw = "POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nhello";
        String out = s(ProxyWire.ensureConnectionClose(b(raw)));
        assertTrue(out.endsWith("\r\n\r\nhello"), out);
        assertTrue(out.contains("Connection: close"), out);
    }

    @Test
    void malformedRequestWithoutTerminatorReturnedUnchanged() {
        String raw = "GET / HTTP/1.1\r\nHost: t";
        assertEquals(raw, s(ProxyWire.ensureConnectionClose(b(raw))));
    }
}
