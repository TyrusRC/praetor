package com.praetor.handlers;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.praetor.handlers.WebSocketSendHandler.appendHandshakeHeaders;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Calibration for handshake-header injection added so a caller can manipulate
 * the WebSocket upgrade (Origin spoof, session Cookie, X-Forwarded-For to
 * bypass an IP ban — the "manipulating the handshake" lab class).
 */
class WebSocketHandshakeHeaderTest {

    private String build(Object headers) {
        StringBuilder sb = new StringBuilder();
        appendHandshakeHeaders(sb, headers);
        return sb.toString();
    }

    @Test
    void appendsCallerHeaderVerbatim() {
        assertEquals("X-Forwarded-For: 1.1.1.1\r\n",
            build(Map.of("X-Forwarded-For", "1.1.1.1")));
    }

    @Test
    void dropsReservedUpgradeHeadersCaseInsensitively() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Host", "evil");
        h.put("Upgrade", "h2c");
        h.put("Connection", "close");
        h.put("Sec-WebSocket-Key", "AAAA");
        h.put("SEC-WEBSOCKET-VERSION", "8");
        // Only the non-reserved header survives.
        h.put("Origin", "https://lab.example");
        assertEquals("Origin: https://lab.example\r\n", build(h));
    }

    @Test
    void stripsCrlfToPreventHandshakeInjection() {
        String out = build(Map.of(
            "X-Forwarded-For", "1.1.1.1\r\nEvil: injected"));
        assertEquals("X-Forwarded-For: 1.1.1.1Evil: injected\r\n", out);
        // The injected value must not become its own header line.
        assertFalse(out.contains("\r\nEvil:"));
        assertEquals(1, out.split("\r\n").length);
    }

    @Test
    void skipsBlankNamesAndNullMap() {
        assertEquals("", build(null));
        assertEquals("", build("not-a-map"));
        Map<String, String> h = new LinkedHashMap<>();
        h.put("   ", "x");
        assertEquals("", build(h));
    }

    @Test
    void emitsMultipleHeadersInOrder() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Origin", "https://lab.example");
        h.put("Cookie", "session=abc");
        h.put("X-Forwarded-For", "1.1.1.1");
        String out = build(h);
        assertTrue(out.startsWith("Origin: https://lab.example\r\n"), out);
        assertTrue(out.contains("Cookie: session=abc\r\n"), out);
        assertTrue(out.endsWith("X-Forwarded-For: 1.1.1.1\r\n"), out);
    }
}
