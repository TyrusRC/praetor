package com.praetor.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;

/**
 * {@code forceHttp11} normalizes the request-line version for the HTTP/1.1
 * proxy tunnel. A proxy-history-sourced request can be HTTP/2; sending its
 * {@code HTTP/2} request line to Burp's listener returns 400 (the bug behind
 * repeater_resend failing while a fresh HTTP/1.1 curl_request worked).
 */
class ProxyWireHttp11Test {

    private static String s(byte[] b) {
        return new String(b, StandardCharsets.US_ASCII);
    }

    @Test
    void rewritesHttp2VersionToHttp11() {
        byte[] in = "GET /sqli/?id=1&Submit=Submit HTTP/2\r\nHost: t\r\nCookie: a=b\r\n\r\n"
            .getBytes(StandardCharsets.US_ASCII);
        String out = s(ProxyWire.forceHttp11(in));
        assertTrue(out.startsWith("GET /sqli/?id=1&Submit=Submit HTTP/1.1\r\n"), out);
        assertTrue(out.contains("Host: t"));
        assertTrue(out.contains("Cookie: a=b"));
        assertFalse(out.contains("HTTP/2"));
    }

    @Test
    void http11IsLeftUnchanged() {
        byte[] in = "GET /x HTTP/1.1\r\nHost: t\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(in, ProxyWire.forceHttp11(in));
    }

    @Test
    void preservesBodyBytesVerbatim() {
        byte[] in = "POST /x HTTP/2\r\nContent-Length: 5\r\n\r\nhello".getBytes(StandardCharsets.US_ASCII);
        String out = s(ProxyWire.forceHttp11(in));
        assertTrue(out.startsWith("POST /x HTTP/1.1\r\n"));
        assertTrue(out.endsWith("\r\n\r\nhello"));
    }

    @Test
    void noRequestLineIsNoop() {
        byte[] in = "not-a-request".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(in, ProxyWire.forceHttp11(in));
    }
}
