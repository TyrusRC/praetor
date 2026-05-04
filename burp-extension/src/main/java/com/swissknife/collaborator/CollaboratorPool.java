package com.swissknife.collaborator;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;

/**
 * Process-wide singleton accessor for the Burp Collaborator client.
 *
 * Multiple handlers (CollaboratorHandler for direct user-driven payloads,
 * SessionHandler for auto-probe OOB matchers) all need access to the same
 * client instance — sharing the client preserves payload->interaction
 * traceability and avoids duplicate Collaborator-server allocations.
 */
public final class CollaboratorPool {

    private static volatile CollaboratorClient INSTANCE;

    private CollaboratorPool() {}

    /**
     * Returns the shared client, creating it on first call. Throws if the
     * Burp deployment cannot allocate a client (Community Edition or
     * Collaborator misconfigured) — callers should treat this as the OOB
     * feature being unavailable rather than a hard error.
     */
    public static synchronized CollaboratorClient getOrCreate(MontoyaApi api) {
        if (INSTANCE == null) {
            INSTANCE = api.collaborator().createClient();
        }
        return INSTANCE;
    }

    /** Best-effort lookup: returns null when Collaborator is unavailable. */
    public static CollaboratorClient tryGetOrCreate(MontoyaApi api) {
        try {
            return getOrCreate(api);
        } catch (Throwable t) {
            return null;
        }
    }
}
