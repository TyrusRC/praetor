package com.praetor.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
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
     *   1. JVM system property -Dpraetor.proxy.host (highest precedence,
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

    private static String prop(String suffix) {
        return System.getProperty("praetor." + suffix);
    }

    private static String resolveHost() {
        String v = prop("proxy.host");
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
        String v = prop("proxy.port");
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
        // Refuse early — before the CONNECT round-trip — when an HTTPS request
        // would land on a non-loopback proxy with TRUST_ALL. Saves the wasted
        // socket connect on misconfig.
        if (service.secure() && !isLoopbackProxyHost(BURP_PROXY_HOST)) {
            api.logging().logToError("ProxyTunnel: refusing HTTPS tunnel via non-loopback BURP_PROXY_HOST="
                + BURP_PROXY_HOST + " (trust-all context unsafe).");
            return null;
        }

        // Force Connection: close so the server closes after the response and
        // our ProxyWire.readAll() terminates cleanly. Keeps the tunnel logic simple and
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
            String msg = e.getClass().getSimpleName() + ": " + (e.getMessage() == null ? "(no detail)" : e.getMessage());
            LAST_SEND_ERROR.set("proxy tunnel — " + msg);
            api.logging().logToError("ProxyTunnel send failed: " + msg);
            return null;
        }

        if (rawResponse == null || rawResponse.length == 0) {
            LAST_SEND_ERROR.set("proxy tunnel returned empty response from " + service.host() + ":" + service.port());
            return null;
        }
        HttpResponse response = HttpResponse.httpResponse(ByteArray.byteArray(rawResponse));
        return HttpRequestResponse.httpRequestResponse(request, response);
    }

    private static byte[] tunnelHttps(Socket socket, HttpRequest request, HttpService service) throws IOException {
        // Force HTTP/1.1 on the request line — a proxy-history-sourced request may
        // be HTTP/2, and the tunnel speaks HTTP/1.1 to Burp's listener (else 400).
        return tunnelHttpsWire(socket, ProxyWire.forceHttp11(request.toByteArray().getBytes()), service);
    }

    /**
     * HTTPS tunnel that writes exact request bytes over the MITM'd TLS socket.
     * Used both by the Montoya path (bytes = request.toByteArray()) and the
     * verbatim path (bytes = the operator's original raw request), so an
     * absolute-URI request line survives to the wire.
     */
    private static byte[] tunnelHttpsWire(Socket socket, byte[] wire, HttpService service) throws IOException {
        String host = service.host();
        int port = service.port();
        String connect = "CONNECT " + host + ":" + port + " HTTP/1.1\r\n" +
                         "Host: " + host + ":" + port + "\r\n" +
                         "Connection: close\r\n\r\n";
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();
        out.write(connect.getBytes(StandardCharsets.US_ASCII));
        out.flush();

        String statusLine = ProxyWire.readLine(in);
        if (statusLine == null || !ProxyWire.isHttp200(statusLine)) {
            throw new IOException("Burp proxy refused CONNECT: " + statusLine);
        }
        // drain CONNECT headers until blank line
        while (true) {
            String ln = ProxyWire.readLine(in);
            if (ln == null || ln.isEmpty()) break;
        }

        // Loopback gate is now also enforced in send() before CONNECT (lines below);
        // keep the redundant check here as a defense-in-depth backstop.
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
                tls.getOutputStream().write(wire);
                tls.getOutputStream().flush();
                return ProxyWire.readAll(tls.getInputStream());
            }
        } catch (Exception e) {
            throw new IOException("TLS tunnel failed: " + e.getMessage(), e);
        }
    }

    /**
     * Send exact raw request bytes DIRECTLY to the target (bypassing Burp's
     * proxy listener), so the wire request line survives verbatim.
     *
     * This is the only faithful delivery for a routing-based SSRF / host-header
     * attack: the request-target is an absolute URI (GET https://target/path)
     * and the Host header diverges from it. Every path through Burp normalises
     * the absolute target to origin-form — Montoya's toByteArray()/api.http()
     * re-serialize it, and the proxy listener rewrites it even inside a CONNECT
     * tunnel — silently degrading the attack to a plain modified-Host request
     * the target blocks.
     *
     * HTTPS: TLS with ALPN pinned to http/1.1 (a divergent Host is impossible
     * over HTTP/2's SNI-bound :authority) and SNI set to the connection host.
     * A trust-all context is used because the operator is targeting an
     * authorized host and controls the raw bytes; this send does NOT go through
     * Burp, so it is Logger-style (no Proxy-history entry). A Connection: close
     * is appended if absent so the response stream terminates at EOF. Returns
     * null on failure (caller falls back to the normalising path).
     *
     * @param forRecord HttpRequest used only to populate the returned
     *        HttpRequestResponse's request side.
     */
    public static HttpRequestResponse sendDirectVerbatim(MontoyaApi api, HttpService service,
                                                         byte[] rawBytes, HttpRequest forRecord) {
        if (service == null || rawBytes == null) return null;
        byte[] wire = ProxyWire.ensureConnectionClose(rawBytes);
        byte[] rawResponse;
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(service.host(), service.port()), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(READ_TIMEOUT_MS);
            if (service.secure()) {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, TRUST_ALL, new SecureRandom());
                SSLSocketFactory sf = ctx.getSocketFactory();
                try (SSLSocket tls = (SSLSocket) sf.createSocket(socket, service.host(), service.port(), true)) {
                    SSLParameters p = tls.getSSLParameters();
                    p.setApplicationProtocols(new String[]{"http/1.1"});
                    p.setServerNames(java.util.List.of(new SNIHostName(service.host())));
                    tls.setSSLParameters(p);
                    tls.startHandshake();
                    tls.getOutputStream().write(wire);
                    tls.getOutputStream().flush();
                    rawResponse = ProxyWire.readAll(tls.getInputStream());
                }
            } else {
                socket.getOutputStream().write(wire);
                socket.getOutputStream().flush();
                rawResponse = ProxyWire.readAll(socket.getInputStream());
            }
        } catch (Exception e) {
            String msg = e.getClass().getSimpleName() + ": " + (e.getMessage() == null ? "(no detail)" : e.getMessage());
            LAST_SEND_ERROR.set("direct verbatim — " + msg);
            api.logging().logToError("ProxyTunnel.sendDirectVerbatim failed: " + msg);
            return null;
        }
        if (rawResponse == null || rawResponse.length == 0) {
            LAST_SEND_ERROR.set("direct verbatim returned empty response from " + service.host() + ":" + service.port());
            return null;
        }
        HttpResponse response = HttpResponse.httpResponse(ByteArray.byteArray(rawResponse));
        return HttpRequestResponse.httpRequestResponse(forRecord, response);
    }

    private static byte[] tunnelHttp(Socket socket, HttpRequest request, HttpService service) throws IOException {
        byte[] raw = ProxyWire.forceHttp11(request.toByteArray().getBytes());
        byte[] proxied = ProxyWire.rewriteAsProxyRequest(raw, service.host(), service.port());
        socket.getOutputStream().write(proxied);
        socket.getOutputStream().flush();
        return ProxyWire.readAll(socket.getInputStream());
    }

    /**
     * Change "METHOD /path HTTP/x" to "METHOD http://host[:port]/path HTTP/x".
     *
     * Only the request line is text — find the first '\n' byte, rewrite the
     * line (ASCII), then concatenate the original byte array's remainder
     * unchanged. This preserves UTF-8 / binary bodies.
     */
    /** Set true by {@link #sendOrFallback} when the most recent send fell through to a non-proxied path. */
    private static final ThreadLocal<Boolean> LAST_FELL_BACK = ThreadLocal.withInitial(() -> Boolean.FALSE);

    /**
     * Cause-of-failure for the most recent {@link #sendOrFallback} call on this
     * thread when it returned null. Captured so handlers can surface a real
     * diagnostic ("Unknown host", "Connection refused", "Read timed out") to
     * the operator instead of an opaque "No response from target".
     */
    private static final ThreadLocal<String> LAST_SEND_ERROR = ThreadLocal.withInitial(() -> "");

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
     * Returns the last underlying send-failure message for this thread, or "" if
     * the most recent send succeeded. Useful for sendError(..., reason) when
     * sendOrFallback returns null.
     */
    public static String lastSendError() {
        return LAST_SEND_ERROR.get();
    }

    /** Clears the per-thread fallback flag. Workers reused across unrelated calls
     *  should call this at the start of each new request to avoid stale state. */
    public static void clearLastSendFellBack() {
        LAST_FELL_BACK.remove();
        LAST_SEND_ERROR.remove();
    }

    /**
     * Convenience: send via tunnel, fall back to {@code api.http().sendRequest}
     * if the tunnel is unavailable. Callers that always want proxy-history
     * visibility should use {@link #send} directly and handle null.
     */
    public static HttpRequestResponse sendOrFallback(MontoyaApi api, HttpRequest request) {
        // Clear any stale per-thread error state from a previous send.
        LAST_SEND_ERROR.set("");
        HttpRequestResponse result = send(api, request);
        if (result != null && result.response() != null) {
            LAST_FELL_BACK.set(Boolean.FALSE);
            LAST_SEND_ERROR.set("");
            return result;
        }
        LAST_FELL_BACK.set(Boolean.TRUE);
        api.logging().logToOutput("ProxyTunnel: falling back to direct sendRequest — request will NOT appear in Proxy history (Rule 26a). Check Burp proxy listener at " + BURP_PROXY_HOST + ":" + BURP_PROXY_PORT + ".");
        // Wrap the fallback so a transient HTTP error (DNS failure, connection
        // refused, malformed payload) does not propagate up as an uncaught
        // RuntimeException and abort the calling loop (fuzz / macro / probe).
        // Callers already null-handle missing responses.
        try {
            HttpRequestResponse fallback = api.http().sendRequest(request);
            if (fallback != null && fallback.response() != null) {
                // Direct send worked — clear the tunnel-side error (it succeeded via fallback).
                LAST_SEND_ERROR.set("");
                return fallback;
            }
            // Fallback returned null/empty — preserve any earlier tunnel error
            // if we captured one, otherwise note the empty fallback.
            if (LAST_SEND_ERROR.get().isEmpty()) {
                LAST_SEND_ERROR.set("direct send returned no response");
            }
            return null;
        } catch (RuntimeException e) {
            String msg = e.getClass().getSimpleName() + ": " + (e.getMessage() == null ? "(no detail)" : e.getMessage());
            // Surface the underlying cause when present (UnknownHostException,
            // ConnectException nested under RuntimeExceptions).
            Throwable cause = e.getCause();
            if (cause != null && cause != e) {
                msg += " (cause: " + cause.getClass().getSimpleName()
                    + ": " + (cause.getMessage() == null ? "(no detail)" : cause.getMessage()) + ")";
            }
            LAST_SEND_ERROR.set("direct send — " + msg);
            api.logging().logToError("ProxyTunnel.sendOrFallback: direct send threw " + msg);
            return null;
        }
    }
}
