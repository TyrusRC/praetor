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

    /**
     * Returns true if the given interaction id has been observed by the shared
     * Collaborator client. Used by NotesHandler to cross-validate
     * evidence.collaborator_interaction_id before accepting a save_finding so
     * operators can't claim an OOB hit they never received.
     *
     * Burp's getAllInteractions() drains the interaction queue, so we poll
     * once, snapshot the ids, and let the caller decide. When Collaborator is
     * unavailable (Community Edition), returns null so the caller can pick
     * between hard-reject and warn-and-allow without conflating "no Pro" with
     * "id not found".
     */
    public static Boolean hasInteraction(MontoyaApi api, String interactionId) {
        if (interactionId == null || interactionId.isEmpty()) return Boolean.FALSE;
        CollaboratorClient client = tryGetOrCreate(api);
        if (client == null) return null;  // Collaborator unavailable -> caller decides
        try {
            var interactions = client.getAllInteractions();
            if (interactions == null) return Boolean.FALSE;
            for (var i : interactions) {
                if (interactionId.equals(i.id().toString())) return Boolean.TRUE;
            }
            return Boolean.FALSE;
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * Drop the singleton so the next getOrCreate() builds a fresh client.
     * Used when the operator switches engagements via configure_scope —
     * holding interactions for a previous target's payload IDs alongside
     * the new target's pollutes payloadId namespaces. Also called from
     * extension unload paths so Burp doesn't keep a stale reference.
     */
    public static synchronized void reset() {
        INSTANCE = null;
    }
}
