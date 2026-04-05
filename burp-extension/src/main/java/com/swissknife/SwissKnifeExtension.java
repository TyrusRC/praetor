package com.swissknife;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.swissknife.server.ApiServer;
import com.swissknife.ui.ConfigTab;

public class SwissKnifeExtension implements BurpExtension {

    private static final String EXTENSION_NAME = "Swiss Knife MCP";
    private static final int DEFAULT_PORT = 8111;
    private static final String DEFAULT_HOST = "127.0.0.1";

    private volatile ApiServer apiServer;
    private ConfigTab configTab;
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        String version = getVersion();
        api.extension().setName(EXTENSION_NAME + " v" + version);

        // Read saved config or use defaults
        int port = loadInt(api, "swissknife.port", DEFAULT_PORT);
        String host = loadString(api, "swissknife.host", DEFAULT_HOST);

        // Start API server first (creates SessionHandler + FindingsStore)
        startServer(api, host, port);

        // Register UI dashboard tab with references to live data
        configTab = new ConfigTab(api, host, port, version, this::restartServer,
                () -> apiServer.getSessionHandler() != null ? apiServer.getSessionHandler().getSessionInfoList() : java.util.List.of(),
                apiServer.getFindingsStore());
        api.userInterface().registerSuiteTab(EXTENSION_NAME, configTab.getPanel());

        api.extension().registerUnloadingHandler(() -> {
            if (configTab != null) configTab.stop();
            if (apiServer != null) apiServer.stop();
            api.logging().logToOutput(EXTENSION_NAME + " stopped");
        });
    }

    private void startServer(MontoyaApi api, String host, int port) {
        apiServer = new ApiServer(api, host, port, getVersion());
        try {
            apiServer.start();
            api.logging().logToOutput(EXTENSION_NAME + " v" + getVersion() + " started on " + host + ":" + port);
        } catch (Exception e) {
            api.logging().logToError("Failed to start API server on " + host + ":" + port + ": " + e.getMessage());
        }
    }

    void restartServer(String newHost, int newPort) {
        // Stop current server
        if (apiServer != null) {
            apiServer.stop();
            api.logging().logToOutput("API server stopped for reconfiguration");
        }

        // Save new config
        saveString(api, "swissknife.host", newHost);
        saveInt(api, "swissknife.port", newPort);

        // Start with new config
        startServer(api, newHost, newPort);
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
                    if (ver != null && title != null && title.contains("Swiss Knife")) {
                        return ver;
                    }
                }
            }
        } catch (Exception ignored) {}
        // 3. Fallback — should never reach here if pom.xml is configured correctly
        return "unknown";
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
        try { api.persistence().extensionData().setString(key, String.valueOf(value)); } catch (Exception ignored) {}
    }

    private static void saveString(MontoyaApi api, String key, String value) {
        try { api.persistence().extensionData().setString(key, value); } catch (Exception ignored) {}
    }
}
