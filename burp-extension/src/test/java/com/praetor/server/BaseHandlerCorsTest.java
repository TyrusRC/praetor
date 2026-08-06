package com.praetor.server;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The control API is unauthenticated and binds loopback, so its CORS policy is
 * the only thing stopping a website the operator is browsing from reading and
 * driving Burp through the victim's browser. {@link BaseHandler#isLoopbackOrigin}
 * is the gate: it must accept ephemeral-port localhost origins and reject
 * everything else — including hostnames an attacker points at 127.0.0.1
 * (DNS rebinding), which must never be resolved.
 */
class BaseHandlerCorsTest {

    @Test
    void acceptsLoopbackOrigins() {
        assertTrue(BaseHandler.isLoopbackOrigin("http://localhost"));
        assertTrue(BaseHandler.isLoopbackOrigin("http://localhost:52341"));
        assertTrue(BaseHandler.isLoopbackOrigin("http://127.0.0.1:8111"));
        assertTrue(BaseHandler.isLoopbackOrigin("http://127.7.0.9:3000"));
        assertTrue(BaseHandler.isLoopbackOrigin("https://LOCALHOST:9000"));
        assertTrue(BaseHandler.isLoopbackOrigin("http://[::1]:8080"));
    }

    @Test
    void rejectsNonLoopbackOrigins() {
        assertFalse(BaseHandler.isLoopbackOrigin("https://evil.com"));
        assertFalse(BaseHandler.isLoopbackOrigin("http://attacker.example:8111"));
        // DNS-rebinding hostname that would resolve to 127.0.0.1 — must not be
        // accepted, because the check never resolves DNS.
        assertFalse(BaseHandler.isLoopbackOrigin("http://localhost.evil.com"));
        assertFalse(BaseHandler.isLoopbackOrigin("http://127.0.0.1.evil.com"));
        // Not actually loopback despite the leading digits.
        assertFalse(BaseHandler.isLoopbackOrigin("http://12.7.0.1"));
    }

    @Test
    void malformedOrNullOriginsFailClosed() {
        assertFalse(BaseHandler.isLoopbackOrigin(null));
        assertFalse(BaseHandler.isLoopbackOrigin(""));
        assertFalse(BaseHandler.isLoopbackOrigin("   "));
        assertFalse(BaseHandler.isLoopbackOrigin("not a url"));
    }
}
