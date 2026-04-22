package com.swissknife.http;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;

/**
 * Drop-in replacement for com.sun.net.httpserver.HttpServer that uses only
 * java.base (no jdk.httpserver module). Supports the subset of HTTP/1.1 actually
 * used by BaseHandler and the handler classes:
 *
 *   - Request line: METHOD PATH?QUERY HTTP/1.x
 *   - Headers terminated by CRLF CRLF
 *   - Request body framed by Content-Length (no chunked)
 *   - Response with status line + headers + Content-Length-framed body
 *   - Connection: close after every response (no keep-alive)
 *
 * Context matching: longest-prefix match on the request path.
 */
public final class HttpServer {

    private static final int MAX_HEADER_BYTES = 64 * 1024;   // 64 KB of headers max
    private static final int MAX_REQUEST_BODY = 64 * 1024 * 1024; // 64 MB body max

    private final InetSocketAddress address;
    private final int backlog;
    private final List<Context> contexts = new CopyOnWriteArrayList<>();
    private Executor executor = Runnable::run;
    private ServerSocket serverSocket;
    private Thread acceptor;
    private volatile boolean running = false;

    private HttpServer(InetSocketAddress address, int backlog) {
        this.address = address;
        this.backlog = backlog;
    }

    public static HttpServer create(InetSocketAddress address, int backlog) {
        return new HttpServer(address, backlog);
    }

    public void setExecutor(Executor executor) {
        this.executor = (executor == null) ? Runnable::run : executor;
    }

    public void createContext(String path, HttpHandler handler) {
        if (path == null || !path.startsWith("/")) {
            throw new IllegalArgumentException("Context path must start with '/'");
        }
        contexts.add(new Context(path, handler));
    }

    public void start() throws IOException {
        if (running) return;
        serverSocket = new ServerSocket();
        // Bind only to the configured address (e.g. 127.0.0.1) so we never leak to the network.
        serverSocket.bind(address, backlog);
        running = true;
        acceptor = new Thread(this::acceptLoop, "swissknife-http-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    public void stop(int delaySeconds) {
        running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        // Best-effort: executor in ApiServer is a fixed thread pool — ApiServer doesn't own shutdown,
        // so we simply stop accepting. In-flight workers finish naturally.
        if (acceptor != null) {
            try { acceptor.join(Math.max(0, delaySeconds) * 1000L); } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
    }

    // ── Internals ──────────────────────────────────────────────────────

    private void acceptLoop() {
        while (running) {
            Socket client;
            try {
                client = serverSocket.accept();
            } catch (IOException e) {
                if (running) {
                    // accept() failed for some reason other than shutdown — brief pause then continue.
                    try { Thread.sleep(10); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                }
                continue;
            }
            executor.execute(() -> handleClient(client));
        }
    }

    private void handleClient(Socket client) {
        try {
            // Reasonable socket timeouts to avoid leaking threads on dead clients.
            client.setSoTimeout(30_000);

            InputStream in = new BufferedInputStream(client.getInputStream(), 8192);
            OutputStream out = client.getOutputStream();

            // 1. Read request line.
            String requestLine = readLine(in, MAX_HEADER_BYTES);
            if (requestLine == null || requestLine.isEmpty()) {
                try { client.close(); } catch (IOException ignored) {}
                return;
            }
            String[] parts = requestLine.split(" ");
            if (parts.length < 3) {
                writeSimpleError(out, 400, "Bad Request");
                try { client.close(); } catch (IOException ignored) {}
                return;
            }
            String method = parts[0];
            String pathAndQuery = parts[1];

            // 2. Read headers.
            Headers headers = new Headers();
            int headerBytes = requestLine.length();
            while (true) {
                String line = readLine(in, MAX_HEADER_BYTES - headerBytes);
                if (line == null) { writeSimpleError(out, 400, "Bad Request"); try { client.close(); } catch (IOException ignored) {} return; }
                if (line.isEmpty()) break;
                headerBytes += line.length();
                int colon = line.indexOf(':');
                if (colon <= 0) continue; // ignore malformed header
                String name = line.substring(0, colon).trim();
                String value = line.substring(colon + 1).trim();
                headers.add(name, value);
            }

            // 3. Read body based on Content-Length (no chunked support).
            byte[] body = new byte[0];
            String contentLength = headers.getFirst("Content-Length");
            if (contentLength != null) {
                int len;
                try { len = Integer.parseInt(contentLength.trim()); }
                catch (NumberFormatException e) { writeSimpleError(out, 400, "Bad Content-Length"); try { client.close(); } catch (IOException ignored) {} return; }
                if (len < 0 || len > MAX_REQUEST_BODY) { writeSimpleError(out, 413, "Payload Too Large"); try { client.close(); } catch (IOException ignored) {} return; }
                body = readExactly(in, len);
            }

            // 4. Route to the longest-prefix context.
            HttpHandler handler = findHandler(pathOnly(pathAndQuery));
            if (handler == null) {
                writeSimpleError(out, 404, "No matching context");
                try { client.close(); } catch (IOException ignored) {}
                return;
            }

            // 5. Build exchange and invoke handler. Handler closes the socket on return.
            HttpExchange exchange;
            try {
                exchange = new HttpExchange(client, method, pathAndQuery, headers, body, out);
            } catch (URISyntaxException e) {
                writeSimpleError(out, 400, "Bad URI");
                try { client.close(); } catch (IOException ignored) {}
                return;
            }
            try {
                handler.handle(exchange);
            } finally {
                exchange.close();
            }
        } catch (IOException e) {
            try { client.close(); } catch (IOException ignored) {}
        }
    }

    private HttpHandler findHandler(String path) {
        Context best = null;
        for (Context c : contexts) {
            if (path.equals(c.path) || path.startsWith(c.path + "/") || path.startsWith(c.path)) {
                if (best == null || c.path.length() > best.path.length()) best = c;
            }
        }
        return best == null ? null : best.handler;
    }

    private static String pathOnly(String pathAndQuery) {
        int q = pathAndQuery.indexOf('?');
        return q < 0 ? pathAndQuery : pathAndQuery.substring(0, q);
    }

    private static String readLine(InputStream in, int maxBytes) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(256);
        int prev = -1;
        int total = 0;
        while (true) {
            int b = in.read();
            if (b == -1) {
                if (buf.size() == 0) return null;
                return buf.toString(StandardCharsets.ISO_8859_1);
            }
            total++;
            if (total > maxBytes) throw new IOException("Header too large");
            if (prev == '\r' && b == '\n') {
                byte[] bytes = buf.toByteArray();
                // Trim trailing \r (we appended it before we saw the \n).
                int len = bytes.length - 1;
                return new String(bytes, 0, Math.max(0, len), StandardCharsets.ISO_8859_1);
            }
            buf.write(b);
            prev = b;
        }
    }

    private static byte[] readExactly(InputStream in, int len) throws IOException {
        byte[] out = new byte[len];
        int off = 0;
        while (off < len) {
            int n = in.read(out, off, len - off);
            if (n < 0) throw new IOException("Premature EOF reading body (got " + off + "/" + len + ")");
            off += n;
        }
        return out;
    }

    private static void writeSimpleError(OutputStream out, int code, String msg) throws IOException {
        String body = "{\"error\":\"" + msg.replace("\"", "\\\"") + "\"}";
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        String head = "HTTP/1.1 " + code + " " + msg + "\r\n"
                + "Content-Type: application/json; charset=utf-8\r\n"
                + "Content-Length: " + bodyBytes.length + "\r\n"
                + "Connection: close\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.ISO_8859_1));
        out.write(bodyBytes);
        out.flush();
    }

    private record Context(String path, HttpHandler handler) {}
}
