package com.swissknife.server;

import burp.api.montoya.MontoyaApi;
import com.swissknife.http.HttpServer;
import com.swissknife.handlers.*;
import com.swissknife.handlers.SessionHandler;
import com.swissknife.store.FindingsStore;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class ApiServer {

    private final MontoyaApi api;
    private final String host;
    private final int port;
    private HttpServer server;
    private ExecutorService executor;
    private final FindingsStore findingsStore = new FindingsStore();
    private SessionHandler sessionHandler;

    private final String version;

    public ApiServer(MontoyaApi api, String host, int port, String version) {
        this.api = api;
        this.host = host;
        this.port = port;
        this.version = version;
    }

    /** True iff the given bind host is a loopback address. */
    private static boolean isLoopback(String host) {
        if (host == null) return false;
        if ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host)) return true;
        try {
            return InetAddress.getByName(host).isLoopbackAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }

    public SessionHandler getSessionHandler() {
        return sessionHandler;
    }

    public FindingsStore getFindingsStore() {
        return findingsStore;
    }

    public void start() throws IOException {
        // Refuse to bind on a non-loopback interface unless the operator
        // explicitly opted in. The MCP API is unauthenticated and proxies
        // arbitrary requests through Burp on behalf of the caller —
        // exposing it on the LAN would let any local-network attacker drive
        // Burp directly.
        if (!isLoopback(host) && !"true".equalsIgnoreCase(System.getProperty("swissknife.allow_non_loopback_bind"))) {
            throw new IOException(
                "Refusing to bind API on non-loopback host '" + host + "'. " +
                "The Burp Swiss Knife API is unauthenticated; binding it on " +
                "a routable interface exposes Burp to anyone on the network. " +
                "Use 127.0.0.1 / ::1 / localhost, or pass " +
                "-Dswissknife.allow_non_loopback_bind=true to override."
            );
        }
        server = HttpServer.create(new InetSocketAddress(host, port), 0);
        ExecutorService pool = Executors.newFixedThreadPool(6);
        server.setExecutor(pool);
        this.executor = pool;

        // Health
        server.createContext("/api/health", new HealthHandler(version));

        // Proxy history
        server.createContext("/api/proxy", new ProxyHandler(api));

        // Sitemap
        server.createContext("/api/sitemap", new SitemapHandler(api));

        // Scanner findings
        server.createContext("/api/scanner", new ScannerHandler(api));

        // Target scope
        server.createContext("/api/scope", new ScopeHandler(api));

        // Send HTTP through Burp
        server.createContext("/api/http", new HttpSendHandler(api));

        // Collaborator
        server.createContext("/api/collaborator", new CollaboratorHandler(api));

        // Analysis (extract params, forms, endpoints, injection points, tech stack)
        server.createContext("/api/analysis", new AnalysisHandler(api));

        // Notes / findings
        server.createContext("/api/notes", new NotesHandler(findingsStore, api));

        // Search across history
        server.createContext("/api/search", new SearchHandler(api));

        // Fuzz engine
        server.createContext("/api/fuzz", new FuzzHandler(api));

        // Cookies from cookie jar
        server.createContext("/api/cookies", new CookieHandler(api));

        // WebSocket history
        server.createContext("/api/websocket", new WebSocketHandler(api));

        // Export sitemap as JSON or OpenAPI
        server.createContext("/api/export", new SitemapExportHandler(api));

        // Static resources (JS/CSS) listing and fetching
        server.createContext("/api/resources", new ResourceHandler(api));

        // Persistent attack sessions
        sessionHandler = new SessionHandler(api, findingsStore);
        server.createContext("/api/session", sessionHandler);

        // Tracked Repeater tabs (two-way iteration)
        server.createContext("/api/repeater", new RepeaterHandler(api));

        // Attack automation (auth matrix, race condition, HPP)
        server.createContext("/api/attack", new AttackHandler(api, sessionHandler.getSessions()));

        // Intercept control
        server.createContext("/api/intercept", new InterceptHandler(api));

        // Match-and-replace rules
        server.createContext("/api/match-replace", new MatchReplaceHandler(api));

        // Proxy history annotations
        server.createContext("/api/annotations", new AnnotationHandler(api));

        // Traffic stats, live polling, and monitors
        server.createContext("/api/traffic", new TrafficMonitorHandler(api));

        // Text-pattern extraction: regex, CSS selector, links
        server.createContext("/api/extract-text", new ExtractTextHandler(api));

        // Structured-data extraction: JSON path, headers, hash
        server.createContext("/api/extract-data", new ExtractDataHandler(api));

        // Reusable request macros with variable extraction
        server.createContext("/api/macro", new MacroHandler(api));

        // WebSocket send/receive (connect, send messages, close)
        server.createContext("/api/websocket-send", new WebSocketSendHandler(api));

        // Organizer (categorize items in Burp's Organizer tab)
        server.createContext("/api/organizer", new OrganizerHandler(api));

        // Burp tools: decoder, project info, logger, intruder config
        server.createContext("/api/burp-tools", new BurpToolsHandler(api));

        server.start();
    }

    public void stop() {
        if (server != null) {
            server.stop(1);
            server = null;
        }
        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
            executor = null;
        }
    }
}
