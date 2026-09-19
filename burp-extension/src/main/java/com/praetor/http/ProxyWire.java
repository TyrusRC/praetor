package com.praetor.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Raw proxy-wire helpers (request rewrite + stream readers), split from ProxyTunnel (pure). */
final class ProxyWire {

    private ProxyWire() {}

    /**
     * Force the request-line HTTP version to {@code HTTP/1.1}.
     *
     * A request captured from Burp's proxy history can be HTTP/2 (Burp negotiated
     * h2 with the target), and Montoya's {@code toByteArray()} serializes it with
     * an {@code HTTP/2} version token. The proxy tunnel speaks HTTP/1.1 to Burp's
     * listener, so an {@code HTTP/2} request line is rejected with 400 — which is
     * why re-sending a proxy-history-sourced Repeater tab failed while a freshly
     * built (HTTP/1.1) request succeeded. Rewrite only the version token; the
     * method, target and everything after the first line are byte-preserved.
     * No-op when already HTTP/1.1 or when the first line isn't a request line.
     */
    static byte[] forceHttp11(byte[] raw) {
        int lf = -1;
        for (int i = 0; i < raw.length; i++) {
            if (raw[i] == '\n') { lf = i; break; }
        }
        if (lf < 0) return raw;
        int lineEnd = (lf > 0 && raw[lf - 1] == '\r') ? lf - 1 : lf;
        String requestLine = new String(raw, 0, lineEnd, StandardCharsets.US_ASCII);
        int lastSpace = requestLine.lastIndexOf(' ');
        if (lastSpace < 0) return raw;
        String version = requestLine.substring(lastSpace + 1);
        if (!version.startsWith("HTTP/") || version.equals("HTTP/1.1")) return raw;
        String newLine = requestLine.substring(0, lastSpace) + " HTTP/1.1\r\n";
        byte[] newLineBytes = newLine.getBytes(StandardCharsets.US_ASCII);
        int restStart = lf + 1;
        int restLen = raw.length - restStart;
        byte[] out = new byte[newLineBytes.length + restLen];
        System.arraycopy(newLineBytes, 0, out, 0, newLineBytes.length);
        if (restLen > 0) {
            System.arraycopy(raw, restStart, out, newLineBytes.length, restLen);
        }
        return out;
    }

    static byte[] rewriteAsProxyRequest(byte[] raw, String host, int port) {
        int lf = -1;
        for (int i = 0; i < raw.length; i++) {
            if (raw[i] == '\n') { lf = i; break; }
        }
        if (lf < 0) return raw;
        // Request line bytes (without trailing '\n', stripping CR if present).
        int lineEnd = (lf > 0 && raw[lf - 1] == '\r') ? lf - 1 : lf;
        String requestLine = new String(raw, 0, lineEnd, StandardCharsets.US_ASCII);
        int first = requestLine.indexOf(' ');
        int second = requestLine.indexOf(' ', first + 1);
        if (first < 0 || second < 0) return raw;
        String method = requestLine.substring(0, first);
        String path = requestLine.substring(first + 1, second);
        String rest = requestLine.substring(second);
        String authority = (port == 80) ? host : host + ":" + port;
        String newLine = method + " http://" + authority + path + rest + "\r\n";
        byte[] newLineBytes = newLine.getBytes(StandardCharsets.US_ASCII);
        int restStart = lf + 1;
        int restLen = raw.length - restStart;
        byte[] out = new byte[newLineBytes.length + restLen];
        System.arraycopy(newLineBytes, 0, out, 0, newLineBytes.length);
        if (restLen > 0) {
            System.arraycopy(raw, restStart, out, newLineBytes.length, restLen);
        }
        return out;
    }

    /** True when the HTTP/x.y response status line indicates 200. Splits on space rather than substring-matching " 200". */
    static boolean isHttp200(String statusLine) {
        if (statusLine == null) return false;
        String[] parts = statusLine.split(" ", 3);
        return parts.length >= 2 && "200".equals(parts[1]);
    }

    static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                int len = sb.length();
                if (len > 0 && sb.charAt(len - 1) == '\r') sb.setLength(len - 1);
                return sb.toString();
            }
            sb.append((char) b);
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    /**
     * Ensure a raw HTTP/1 request carries "Connection: close" so a verbatim
     * send's response stream terminates (readAll loops until EOF). If a
     * Connection header is already present (any value/case) the bytes are
     * returned unchanged; otherwise the header is inserted just before the
     * blank line that ends the header block. Requests without a proper
     * "\r\n\r\n" terminator are returned unchanged (nothing safe to do).
     */
    static byte[] ensureConnectionClose(byte[] raw) {
        if (raw == null) return null;
        String s = new String(raw, StandardCharsets.ISO_8859_1);
        int sep = s.indexOf("\r\n\r\n");
        if (sep < 0) return raw;
        String headerBlock = s.substring(0, sep);
        // Case-insensitive scan for a "connection:" header line.
        for (String line : headerBlock.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("connection")) {
                return raw; // already present — respect the operator's value
            }
        }
        String rebuilt = headerBlock + "\r\nConnection: close" + s.substring(sep);
        return rebuilt.getBytes(StandardCharsets.ISO_8859_1);
    }

}
