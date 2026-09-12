package com.praetor.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Raw proxy-wire helpers (request rewrite + stream readers), split from ProxyTunnel (pure). */
final class ProxyWire {

    private ProxyWire() {}

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

}
