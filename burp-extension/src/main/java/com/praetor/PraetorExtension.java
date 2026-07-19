package com.praetor;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.praetor.server.ApiServer;
import com.praetor.ui.ConfigTab;

public class PraetorExtension implements BurpExtension {

    private static final String EXTENSION_NAME = "Praetor MCP";
    private static final int DEFAULT_PORT = 8111;
    private static final String DEFAULT_HOST = "127.0.0.1";

    private volatile ApiServer apiServer;
    private ConfigTab configTab;
    private MontoyaApi api;
    private final Object serverLifecycleLock = new Object();
    /** Long-lived FindingsStore that survives server restarts — keeps the UI dashboard pointing at the same data. */
    private final com.praetor.store.FindingsStore findingsStore = new com.praetor.store.FindingsStore();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        String version = getVersion();
        api.extension().setName(EXTENSION_NAME + " v" + version);

        checkJvm(api);

        // Read saved config or use defaults
        int port = loadInt(api, "swissknife.port", DEFAULT_PORT);
        String host = loadString(api, "swissknife.host", DEFAULT_HOST);

        // Start API server first (creates SessionHandler + FindingsStore)
        startServer(api, host, port);

        // Restore findings persisted in the Burp project so they + their status
        // survive a Burp reopen (the store is otherwise in-memory only). Load
        // BEFORE wiring the change listener so the restore itself doesn't
        // re-persist. Thereafter every add / status-change / delete rewrites
        // the project blob.
        String savedFindings = loadString(api, "praetor.findings", "");
        if (!savedFindings.isEmpty()) {
            findingsStore.loadFromJson(savedFindings);
            api.logging().logToOutput(EXTENSION_NAME + " restored "
                    + findingsStore.getAll(null).size() + " persisted findings");
        }
        findingsStore.setChangeListener(() ->
                saveString(api, "praetor.findings", findingsStore.exportJson()));

        // Register UI dashboard tab with references to live data. The
        // suppliers re-read `apiServer` on every invocation so a server
        // restart hands the UI fresh references rather than stale ones.
        configTab = new ConfigTab(api, host, port, version, this::restartServer,
                () -> {
                    ApiServer current = apiServer;
                    return (current != null && current.getSessionHandler() != null)
                        ? current.getSessionHandler().getSessionInfoList()
                        : java.util.List.of();
                },
                findingsStore);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, configTab.getPanel());

        api.extension().registerUnloadingHandler(() -> {
            synchronized (serverLifecycleLock) {
                if (configTab != null) configTab.stop();
                if (apiServer != null) apiServer.stop();
            }
            // Drop the shared Collaborator client on unload so a future
            // extension reload starts with a fresh payload-id namespace.
            com.praetor.collaborator.CollaboratorPool.reset();
            api.logging().logToOutput(EXTENSION_NAME + " stopped");
        });
    }

    private void startServer(MontoyaApi api, String host, int port) {
        synchronized (serverLifecycleLock) {
            apiServer = new ApiServer(api, host, port, getVersion(), findingsStore);
            try {
                apiServer.start();
                api.logging().logToOutput(EXTENSION_NAME + " v" + getVersion() + " started on " + host + ":" + port);
                // Surface the proxy-tunnel endpoint so hunters can spot misconfigs
                // (e.g. custom Burp proxy port not reflected in BURP_PROXY_PORT).
                api.logging().logToOutput("Proxy tunnel → "
                    + com.praetor.http.ProxyTunnel.BURP_PROXY_HOST + ":"
                    + com.praetor.http.ProxyTunnel.BURP_PROXY_PORT
                    + " (override with env BURP_PROXY_HOST/PORT or -Dswissknife.proxy.{host,port})");
            } catch (Exception e) {
                api.logging().logToError("Failed to start API server on " + host + ":" + port + ": " + e.getMessage());
                apiServer = null;
            }
        }
    }

    void restartServer(String newHost, int newPort) {
        synchronized (serverLifecycleLock) {
            if (apiServer != null) {
                apiServer.stop();
                apiServer = null;
                api.logging().logToOutput("API server stopped for reconfiguration");
            }
            saveString(api, "swissknife.host", newHost);
            saveInt(api, "swissknife.port", newPort);
            startServer(api, newHost, newPort);
        }
    }

    private String getVersion() {
        // 1. Try Package manifest (set by maven-jar-plugin Implementation-Version)
        Package pkg = getClass().getPackage();
        if (pkg != null && pkg.getImplementationVersion() != null) {
            return pkg.getImplementationVersion();
        }
        // 2. Try reading manifest directly from JAR (Burp's classloader may not populate Package)
        try {
            var resources = getClass().getClassLoader().getResources("META-INF/MANIFEST.MF");
            while (resources.hasMoreElements()) {
                try (var is = resources.nextElement().openStream()) {
                    var manifest = new java.util.jar.Manifest(is);
                    String ver = manifest.getMainAttributes().getValue("Implementation-Version");
                    String title = manifest.getMainAttributes().getValue("Implementation-Title");
                    if (ver != null && title != null && title.contains("Praetor")) {
                        return ver;
                    }
                }
            }
        } catch (Exception ignored) {}
        // 3. Fallback — should never reach here if pom.xml is configured correctly
        return "unknown";
    }

    private void checkJvm(MontoyaApi api) {
        String vendor = System.getProperty("java.vendor", "unknown");
        String jvmName = System.getProperty("java.vm.name", "unknown");
        String spec = System.getProperty("java.specification.version", "0");
        int major;
        try {
            // Handles "21", "22", "22.0.1", etc.
            major = Integer.parseInt(spec.split("\\.")[0]);
        } catch (NumberFormatException e) {
            major = 0;
        }
        api.logging().logToOutput("JVM: " + jvmName + " " + spec + " (" + vendor + ")");
        if (major < 21) {
            api.logging().logToError(
                "WARNING: Detected Java " + spec + ". Praetor MCP requires Java 21 or newer. "
                + "Launch Burp with a JDK >= 21 (e.g. https://adoptium.net/temurin/releases/?version=21). "
                + "The extension will attempt to start anyway, but class loading may fail on older JVMs."
            );
        }
    }

    // Persistence helpers using Burp's extension data
    private static int loadInt(MontoyaApi api, String key, int defaultValue) {
        try {
            String val = api.persistence().extensionData().getString(key);
            if (val != null) return Integer.parseInt(val);
        } catch (Exception ignored) {}
        return defaultValue;
    }

    private static String loadString(MontoyaApi api, String key, String defaultValue) {
        try {
            String val = api.persistence().extensionData().getString(key);
            if (val != null && !val.isEmpty()) return val;
        } catch (Exception ignored) {}
        return defaultValue;
    }

    private static void saveInt(MontoyaApi api, String key, int value) {
        try {
            api.persistence().extensionData().setString(key, String.valueOf(value));
        } catch (Exception e) {
            api.logging().logToError("[Praetor] persistence write failed for '" + key + "': " + e.getMessage());
        }
    }

    private static void saveString(MontoyaApi api, String key, String value) {
        try {
            api.persistence().extensionData().setString(key, value);
        } catch (Exception e) {
            api.logging().logToError("[Praetor] persistence write failed for '" + key + "': " + e.getMessage());
        }
    }
}
