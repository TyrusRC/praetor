package com.swissknife.http;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

/**
 * Drop-in replacement for com.sun.net.httpserver.HttpExchange.
 *
 * One instance per request. Holds the parsed request (method, URI, headers,
 * body) and exposes a write path for the response. After sendResponseHeaders()
 * is called, the response status line and headers are flushed to the socket;
 * subsequent writes to getResponseBody() go directly to the socket output stream.
 *
 * Not thread-safe — a single worker thread owns one exchange from request parse
 * to close.
 */
public final class HttpExchange implements AutoCloseable {

    private final Socket socket;
    private final String method;
    private final URI uri;
    private final Headers requestHeaders;
    private final InputStream requestBody;
    private final OutputStream rawOut;

    private final Headers responseHeaders = new Headers();
    private boolean responseHeadersSent = false;
    private OutputStream responseBody;

    /**
     * Package-private constructor — only the server constructs exchanges from
     * the parsed request line + headers + already-buffered body bytes.
     */
    HttpExchange(Socket socket,
                 String method,
                 String rawPathAndQuery,
                 Headers requestHeaders,
                 byte[] requestBodyBytes,
                 OutputStream rawOut) throws URISyntaxException {
        this.socket = socket;
        this.method = method;
        // Build a relative URI; full URI isn't needed, handlers only use getPath()/getRawQuery().
        this.uri = new URI(rawPathAndQuery);
        this.requestHeaders = requestHeaders;
        this.requestBody = new ByteArrayInputStream(requestBodyBytes == null ? new byte[0] : requestBodyBytes);
        this.rawOut = rawOut;
    }

    public String getRequestMethod() {
        return method;
    }

    public URI getRequestURI() {
        return uri;
    }

    public Headers getRequestHeaders() {
        return requestHeaders;
    }

    public Headers getResponseHeaders() {
        return responseHeaders;
    }

    public InputStream getRequestBody() {
        return requestBody;
    }

    /**
     * Writes the status line and headers to the socket. If contentLength &gt;= 0,
     * sets Content-Length and the handler MUST write exactly that many bytes.
     * If contentLength == -1, sends no Content-Length and the handler writes nothing
     * (used for 204 No Content responses).
     * If contentLength == 0, sends Content-Length: 0 and no body is expected.
     */
    public void sendResponseHeaders(int statusCode, long contentLength) throws IOException {
        if (responseHeadersSent) {
            throw new IOException("Response headers already sent");
        }
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(statusCode).append(' ').append(reasonPhrase(statusCode)).append("\r\n");

        if (contentLength == -1) {
            // No body. Do not emit Content-Length.
            // Connection: close ensures the client reads until EOF and doesn't wait.
        } else {
            responseHeaders.set("Content-Length", Long.toString(contentLength));
        }
        // Always close the connection after this response (simplest protocol model).
        if (!responseHeaders.containsKey("Connection")) {
            responseHeaders.set("Connection", "close");
        }
        responseHeaders.forEachEntry((name, value) -> sb.append(name).append(": ").append(value).append("\r\n"));
        sb.append("\r\n");

        rawOut.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        rawOut.flush();
        responseHeadersSent = true;
        // For -1 (no body) give handlers a no-op stream so they can safely close it.
        this.responseBody = (contentLength == -1)
            ? OutputStream.nullOutputStream()
            : rawOut;
    }

    /**
     * Must be called after sendResponseHeaders(). Handler writes the body here.
     */
    public OutputStream getResponseBody() {
        if (!responseHeadersSent) {
            throw new IllegalStateException("sendResponseHeaders() must be called before getResponseBody()");
        }
        return responseBody;
    }

    /**
     * Closes the exchange. Flushes any pending output and closes the socket.
     * Safe to call multiple times.
     */
    @Override
    public void close() {
        try { if (rawOut != null) rawOut.flush(); } catch (IOException ignored) {}
        try { socket.close(); } catch (IOException ignored) {}
    }

    /** Minimal reason-phrase table. Unknown codes get "Status". */
    private static String reasonPhrase(int code) {
        return switch (code) {
            case 200 -> "OK";
            case 201 -> "Created";
            case 204 -> "No Content";
            case 301 -> "Moved Permanently";
            case 302 -> "Found";
            case 304 -> "Not Modified";
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 409 -> "Conflict";
            case 413 -> "Payload Too Large";
            case 415 -> "Unsupported Media Type";
            case 500 -> "Internal Server Error";
            case 501 -> "Not Implemented";
            case 503 -> "Service Unavailable";
            default -> "Status";
        };
    }
}
