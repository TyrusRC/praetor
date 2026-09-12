package com.praetor.server;

import java.net.URI;

/**
 * CORS loopback-origin validation, split out of BaseHandler. Matches only
 * literal loopback forms (localhost, 127.0.0.0/8, ::1) and never resolves DNS,
 * so a rebinding hostname pointed at 127.0.0.1 is not accepted; malformed
 * origins fail closed.
 */
final class OriginCheck {

    private OriginCheck() {}

    static boolean isLoopbackOrigin(String origin) {
        if (origin == null || origin.isBlank()) return false;
        try {
            String host = URI.create(origin).getHost();
            if (host == null) return false;
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            return host.equalsIgnoreCase("localhost")
                || isLoopbackIpv4(host)
                || host.equals("::1")
                || host.equals("0:0:0:0:0:0:0:1");
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** True iff {@code host} is a dotted-quad IPv4 literal in 127.0.0.0/8.
     *  A plain {@code startsWith("127.")} would wrongly accept a hostname such
     *  as {@code 127.0.0.1.evil.com}, so every octet must be numeric. */
    private static boolean isLoopbackIpv4(String host) {
        String[] octets = host.split("\\.", -1);
        if (octets.length != 4) return false;
        for (String o : octets) {
            if (o.isEmpty() || o.length() > 3) return false;
            for (int i = 0; i < o.length(); i++) {
                if (!Character.isDigit(o.charAt(i))) return false;
            }
            int v = Integer.parseInt(o);
            if (v < 0 || v > 255) return false;
        }
        return octets[0].equals("127");
    }

    // ── Request helpers ────────────────────────────────────────────

    /** Hard cap on inbound request body. The MCP server is the only legitimate
     *  caller; even macros/raw-request payloads should fit comfortably. */
}
