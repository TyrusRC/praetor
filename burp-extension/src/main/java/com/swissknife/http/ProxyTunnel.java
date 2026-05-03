package com.swissknife.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * Route a Montoya {@link HttpRequest} through Burp's own proxy listener
 * at 127.0.0.1:8080 so the request/response lands in Proxy → HTTP history.
 *
 * Rationale: {@code api.http().sendRequest(...)} writes to the Logger tab
 * only. Hunters review history from the Proxy → HTTP history panel, so we
 * must force requests down through the proxy listener. There is no
 * Montoya API for "add to proxy history" — tunnelling through the listener
 * is the supported path.
 *
 * HTTPS flow: open a socket to 127.0.0.1:8080, send {@code CONNECT host:port},
 * read the 200 response, then do a direct TLS handshake with a trust-all
 * context (Burp MITMs the cert so JVM default trust won't match).
 *
 * HTTP flow: send a proxy-style request with an absolute URI on the
 * request line ({@code GET http://host/path HTTP/1.1}).
 */
public final class ProxyTunnel {

    /**
     * Proxy host for outbound tunnel. Resolved once at class init via (in order):
     *   1. JVM system property -Dswissknife.proxy.host (highest precedence,
     *      survives Burp launch scripts).
     *   2. Environment variable BURP_PROXY_HOST (matches the MCP server's
     *      config.py and the user's .env — works when Burp was launched
     *      from a shell that loaded the env).
     *   3. Fallback "127.0.0.1".
     */
    public static final String BURP_PROXY_HOST = resolveHost();
    public static final int BURP_PROXY_PORT = resolvePort();

    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int READ_TIMEOUT_MS = 30_000;

    private static String resolveHost() {
        String v = System.getProperty("swissknife.proxy.host");
        if (v != null && !v.isBlank()) return v.trim();
        v = System.getenv("BURP_PROXY_HOST");
        if (v != null && !v.isBlank()) return v.trim();
        return "127.0.0.1";
    }

    /**
     * The trust-all SSLContext is only safe when we are talking to a Burp
     * proxy that we expect to MITM the upstream cert. If the operator points
     * the tunnel at a non-loopback proxy host, we'd be building a real
     * cert-validation bypass for every outbound request. Refuse that with
     * a clear error so the misconfiguration is visible at handshake time.
     */
    private static boolean isLoopbackProxyHost(String host) {
        if (host == null) return false;
        if ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host)) return true;
        try {
            return java.net.InetAddress.getByName(host).isLoopbackAddress();
        } catch (java.net.UnknownHostException e) {
            return false;
        }
    }

    private static int resolvePort() {
        String v = System.getProperty("swissknife.proxy.port");
        if (v == null || v.isBlank()) v = System.getenv("BURP_PROXY_PORT");
        if (v != null && !v.isBlank()) {
            try { return Integer.parseInt(v.trim()); } catch (NumberFormatException ignored) {}
        }
        return 8080;
    }

    private static final TrustManager[] TRUST_ALL = {
        new X509TrustManager() {
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            @Override public void checkClientTrusted(X509Certificate[] c, String a) { /* trust all */ }
            @Override public void checkServerTrusted(X509Certificate[] c, String a) { /* trust all */ }
        }
    };

    private ProxyTunnel() {}

    /**
     * Send {@code request} via Burp's proxy listener. Returns null if the
     * tunnel can't reach the proxy (caller should fall back to direct send).
     */
    public static HttpRequestResponse send(MontoyaApi api, HttpRequest request) {
        HttpService service = request.httpService();
        if (service == null) return null;

        // Force Connection: close so the server closes after the response and
        // our readAll() terminates cleanly. Keeps the tunnel logic simple and
        // avoids needing a full HTTP/1.1 framing parser on our side — Burp's
        // proxy + the response parser in Montoya already handle the content.
        HttpRequest outgoing = request.withUpdatedHeader("Connection", "close");

        byte[] rawResponse;
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(BURP_PROXY_HOST, BURP_PROXY_PORT), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(READ_TIMEOUT_MS);

            if (service.secure()) {
                rawResponse = tunnelHttps(socket, outgoing, service);
            } else {
                rawResponse = tunnelHttp(socket, outgoing, service);
            }
        } catch (IOException e) {
            api.logging().logToError("ProxyTunnel send failed: " + e.getMessage());
            return null;
        }

        if (rawResponse == null || rawResponse.length == 0) return null;
        HttpResponse response = HttpResponse.httpResponse(ByteArray.byteArray(rawResponse));
        return HttpRequestResponse.httpRequestResponse(request, response);
    }

    private static byte[] tunnelHttps(Socket socket, HttpRequest request, HttpService service) throws IOException {
        String host = service.host();
        int port = service.port();
        String connect = "CONNECT " + host + ":" + port + " HTTP/1.1\r\n" +
                         "Host: " + host + ":" + port + "\r\n" +
                         "Connection: close\r\n\r\n";
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();
        out.write(connect.getBytes(StandardCharsets.US_ASCII));
        out.flush();

        String statusLine = readLine(in);
        if (statusLine == null || !isHttp200(statusLine)) {
            throw new IOException("Burp proxy refused CONNECT: " + statusLine);
        }
        // drain CONNECT headers until blank line
        while (true) {
            String ln = readLine(in);
            if (ln == null || ln.isEmpty()) break;
        }

        if (!isLoopbackProxyHost(BURP_PROXY_HOST)) {
            throw new IOException(
                "Refusing TLS tunnel: BURP_PROXY_HOST=" + BURP_PROXY_HOST +
                " is not a loopback address. The trust-all context is only safe " +
                "for a local Burp instance. Set BURP_PROXY_HOST to 127.0.0.1 / localhost / ::1, " +
                "or front the tunnel with a real CA-trusted proxy."
            );
        }
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, TRUST_ALL, new SecureRandom());
            SSLSocketFactory sf = ctx.getSocketFactory();
            try (SSLSocket tls = (SSLSocket) sf.createSocket(socket, host, port, true)) {
                tls.startHandshake();
                tls.getOutputStream().write(request.toByteArray().getBytes());
                tls.getOutputStream().flush();
                return readAll(tls.getInputStream());
            }
        } catch (Exception e) {
            throw new IOException("TLS tunnel failed: " + e.getMessage(), e);
        }
    }

    private static byte[] tunnelHttp(Socket socket, HttpRequest request, HttpService service) throws IOException {
        byte[] raw = request.toByteArray().getBytes();
        byte[] proxied = rewriteAsProxyRequest(raw, service.host(), service.port());
        socket.getOutputStream().write(proxied);
        socket.getOutputStream().flush();
        return readAll(socket.getInputStream());
    }

    /**
     * Change "METHOD /path HTTP/x" to "METHOD http://host[:port]/path HTTP/x".
     *
     * Only the request line is text — find the first '\n' byte, rewrite the
     * line (ASCII), then concatenate the original byte array's remainder
     * unchanged. This preserves UTF-8 / binary bodies.
     */
    private static byte[] rewriteAsProxyRequest(byte[] raw, String host, int port) {
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
    private static boolean isHttp200(String statusLine) {
        if (statusLine == null) return false;
        String[] parts = statusLine.split(" ", 3);
        return parts.length >= 2 && "200".equals(parts[1]);
    }

    private static String readLine(InputStream in) throws IOException {
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

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    /** Set true by {@link #sendOrFallback} when the most recent send fell through to a non-proxied path. */
    private static final ThreadLocal<Boolean> LAST_FELL_BACK = ThreadLocal.withInitial(() -> Boolean.FALSE);

    /**
     * Returns whether the most recent {@link #sendOrFallback} call on this thread
     * had to bypass Burp's proxy listener. Handlers can read this and surface
     * a {@code history_index=-1} note so callers know the request did NOT
     * land in Proxy history (Rule 26a).
     */
    public static boolean lastSendFellBack() {
        return LAST_FELL_BACK.get();
    }

    /**
     * Convenience: send via tunnel, fall back to {@code api.http().sendRequest}
     * if the tunnel is unavailable. Callers that always want proxy-history
     * visibility should use {@link #send} directly and handle null.
     */
    public static HttpRequestResponse sendOrFallback(MontoyaApi api, HttpRequest request) {
        HttpRequestResponse result = send(api, request);
        if (result != null && result.response() != null) {
            LAST_FELL_BACK.set(Boolean.FALSE);
            return result;
        }
        LAST_FELL_BACK.set(Boolean.TRUE);
        api.logging().logToOutput("ProxyTunnel: falling back to direct sendRequest — request will NOT appear in Proxy history (Rule 26a). Check Burp proxy listener at " + BURP_PROXY_HOST + ":" + BURP_PROXY_PORT + ".");
        return api.http().sendRequest(request);
    }
}
