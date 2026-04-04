package com.swissknife;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.swissknife.server.ApiServer;

public class SwissKnifeExtension implements BurpExtension {

    private static final String EXTENSION_NAME = "Swiss Knife MCP";
    private static final int DEFAULT_PORT = 8111;

    private ApiServer apiServer;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        apiServer = new ApiServer(api, DEFAULT_PORT);

        try {
            apiServer.start();
            api.logging().logToOutput(EXTENSION_NAME + " started on port " + DEFAULT_PORT);
        } catch (Exception e) {
            api.logging().logToError("Failed to start API server: " + e.getMessage());
            return;
        }

        api.extension().registerUnloadingHandler(() -> {
            apiServer.stop();
            api.logging().logToOutput(EXTENSION_NAME + " stopped");
        });
    }
}
