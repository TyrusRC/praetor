package com.praetor.server;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * DNS-rebinding Host allowlist. The CORS/Origin gate stops classic cross-origin
 * reads, but rebinding (attacker DNS for evil.com -> 127.0.0.1) makes the
 * request same-origin, so the Host header is the only remaining tell: a browser
 * always sends the page's host. {@link BaseHandler#isHostAllowed} must reject a
 * foreign Host while leaving loopback/localhost/the configured bind host and
 * non-browser (blank-Host) clients working.
 */
class BaseHandlerHostGuardTest {

    @AfterEach
    void reset() {
        BaseHandler.setBindHost("127.0.0.1");   // static state — don't leak
    }

    @Test
    void loopbackBindAllowsLoopbackAndRejectsForeignHost() {
        BaseHandler.setBindHost("127.0.0.1");
        // allowed: local tooling + loopback literals
        assertTrue(BaseHandler.isHostAllowed(null));            // non-browser, no Host
        assertTrue(BaseHandler.isHostAllowed(""));
        assertTrue(BaseHandler.isHostAllowed("127.0.0.1:8111"));
        assertTrue(BaseHandler.isHostAllowed("localhost:8111"));
        assertTrue(BaseHandler.isHostAllowed("[::1]:8111"));
        assertTrue(BaseHandler.isHostAllowed("127.0.0.1"));
        // rejected: the rebinding case + any routable host
        assertFalse(BaseHandler.isHostAllowed("evil.com:8111"));
        assertFalse(BaseHandler.isHostAllowed("evil.com"));
        assertFalse(BaseHandler.isHostAllowed("192.168.1.5:8111"));
    }

    @Test
    void configuredBindHostIsAllowedByThatName() {
        BaseHandler.setBindHost("192.168.1.5");
        assertTrue(BaseHandler.isHostAllowed("192.168.1.5:8111"));
        assertTrue(BaseHandler.isHostAllowed("127.0.0.1:8111"));   // loopback always ok
        assertFalse(BaseHandler.isHostAllowed("evil.com:8111"));
    }

    @Test
    void wildcardBindSkipsTheCheck() {
        BaseHandler.setBindHost("0.0.0.0");
        assertTrue(BaseHandler.isHostAllowed("anything.example:8111"));
    }
}
