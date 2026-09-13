package com.praetor.handlers;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * QNAME extraction from a raw DNS query. This is what makes DNS-channel OOB
 * exfil readable — the leaked value rides in the queried subdomain
 * (&lt;data&gt;.&lt;id&gt;.oastify.com), and before this the interactions JSON
 * dropped the name entirely.
 */
class CollaboratorHandlerDnsTest {

    /** Build a minimal DNS query message: 12-byte header + QNAME labels + 0x00. */
    private static byte[] dnsQuery(String name) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < 12; i++) out.write(0);          // header (contents irrelevant)
        for (String label : name.split("\\.")) {
            out.write(label.length());
            for (byte ch : label.getBytes()) out.write(ch);
        }
        out.write(0);                                        // root terminator
        return out.toByteArray();
    }

    @Test
    void extractsExfiltratedSubdomain() {
        // password prepended as the leftmost label — the real exfil shape
        String host = "s3cr3tpw.q0r3sozyuh0xea8ts3v3zfo9p0vqjf.oastify.com";
        assertEquals(host, CollaboratorHandler.extractDnsQname(dnsQuery(host)));
    }

    @Test
    void simpleName() {
        assertEquals("abc.example.com",
            CollaboratorHandler.extractDnsQname(dnsQuery("abc.example.com")));
    }

    @Test
    void nullAndTooShortReturnEmpty() {
        assertEquals("", CollaboratorHandler.extractDnsQname((byte[]) null));
        assertEquals("", CollaboratorHandler.extractDnsQname(new byte[]{0, 1, 2}));
    }

    @Test
    void truncatedLabelReturnsEmpty() {
        // header + a label claiming 9 bytes but only 3 present -> malformed
        byte[] b = new byte[12 + 1 + 3];
        b[12] = 9;
        b[13] = 'a'; b[14] = 'b'; b[15] = 'c';
        assertEquals("", CollaboratorHandler.extractDnsQname(b));
    }
}
