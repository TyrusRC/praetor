package com.swissknife.server;

import burp.api.montoya.MontoyaApi;
import com.sun.net.httpserver.HttpServer;
import com.swissknife.handlers.*;
import com.swissknife.handlers.SessionHandler;
import com.swissknife.store.FindingsStore;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

public class ApiServer {

    private final MontoyaApi api;
    private final String host;
    private final int port;
    private HttpServer server;
    private final FindingsStore findingsStore = new FindingsStore();
    private SessionHandler sessionHandler;

    private final String version;

    public ApiServer(MontoyaApi api, String host, int port, String version) {
        this.api = api;
        this.host = host;
        this.port = port;
        this.version = version;
    }

    public SessionHandler getSessionHandler() {
        return sessionHandler;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(host, port), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));

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
        server.createContext("/api/notes", new NotesHandler(findingsStore));

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
        sessionHandler = new SessionHandler(api);
        server.createContext("/api/session", sessionHandler);

        // Attack automation (auth matrix, race condition, HPP)
        server.createContext("/api/attack", new AttackHandler(api, sessionHandler.getSessions()));

        server.start();
    }

    public void stop() {
        if (server != null) {
            server.stop(1);
        }
    }
}
