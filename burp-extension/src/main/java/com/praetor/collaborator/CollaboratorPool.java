package com.praetor.collaborator;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

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

    /** Accumulated interaction IDs across all drains — read-only lookup for
     *  hasInteraction() so it never drains the queue itself. */
    private static final Set<String> OBSERVED_IDS = ConcurrentHashMap.newKeySet();

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
     * Returns true if the given interaction id has been observed by ANY prior
     * drain of the shared Collaborator client. Checks the accumulated
     * {@link #OBSERVED_IDS} set without draining the queue itself, so
     * concurrent callers never destroy each other's evidence.
     *
     * When Collaborator is unavailable (Community Edition), returns null so
     * the caller can pick between hard-reject and warn-and-allow without
     * conflating "no Pro" with "id not found".
     */
    public static Boolean hasInteraction(MontoyaApi api, String interactionId) {
        if (interactionId == null || interactionId.isEmpty()) return Boolean.FALSE;
        CollaboratorClient client = tryGetOrCreate(api);
        if (client == null) return null;  // Collaborator unavailable -> caller decides
        if (OBSERVED_IDS.contains(interactionId)) return Boolean.TRUE;
        // Drain once to pick up any interactions that arrived since the last
        // poll, then check again. The drain populates OBSERVED_IDS for all
        // future lookups.
        try {
            drainAndAccumulate(client);
        } catch (Throwable t) {
            return null;
        }
        return OBSERVED_IDS.contains(interactionId) ? Boolean.TRUE : Boolean.FALSE;
    }

    /**
     * Drain all pending interactions from Burp's buffer and record their IDs
     * in {@link #OBSERVED_IDS}. Returns the freshly drained list so callers
     * that need the full interaction objects (CollaboratorHandler) can use
     * them directly.
     */
    public static List<Interaction> drainAndAccumulate(CollaboratorClient client) {
        List<Interaction> fresh = client.getAllInteractions();
        if (fresh != null) {
            for (Interaction i : fresh) {
                OBSERVED_IDS.add(i.id().toString());
            }
        }
        return fresh != null ? fresh : List.of();
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
        OBSERVED_IDS.clear();
    }
}
