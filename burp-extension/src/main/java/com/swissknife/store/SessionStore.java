package com.swissknife.store;

import com.swissknife.handlers.Session;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Singleton thread-safe store for active attack sessions.
 *
 * Replaces SessionHandler's package-private {@code sessions} field. Singleton
 * because both SessionHandler and AttackHandler need a single shared view of
 * the session table (AttackHandler used to receive the map directly via
 * constructor injection — that wiring is preserved for source-compat, but new
 * code should call {@link #get()} instead).
 *
 * Backed by {@link ConcurrentHashMap} so list/iterate operations are
 * lock-free; individual session mutations still {@code synchronized(session)}
 * at the call site (unchanged from the pre-split behaviour).
 */
public final class SessionStore {

    private static final SessionStore INSTANCE = new SessionStore();

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    private SessionStore() { }

    public static SessionStore get() {
        return INSTANCE;
    }

    /** Returns the live backing map. Mutations on this map are visible
     *  immediately to every holder. */
    public Map<String, Session> getSessions() {
        return sessions;
    }

    public Session getSession(String name) {
        return sessions.get(name);
    }

    public Session putSession(String name, Session s) {
        return sessions.put(name, s);
    }

    public Session removeSession(String name) {
        return sessions.remove(name);
    }

    /**
     * Returns session metadata as flat string arrays for the UI table.
     * Shape: {name, baseUrl, cookieCount, variableCount, hasAuth}.
     * Preserved verbatim from SessionHandler.getSessionInfoList().
     */
    public List<String[]> getSessionInfoList() {
        List<String[]> list = new ArrayList<>();
        for (Session s : sessions.values()) {
            list.add(new String[]{
                s.name, s.baseUrl,
                String.valueOf(s.cookies.size()),
                String.valueOf(s.variables.size()),
                !s.bearerToken.isEmpty() || !s.authUser.isEmpty() ? "Yes" : "No"
            });
        }
        return list;
    }
}
