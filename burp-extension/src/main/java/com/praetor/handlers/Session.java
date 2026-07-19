package com.praetor.handlers;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Persistent attack-session state: cookie jar, headers, auth, extracted
 * variables, and the most recent HttpRequestResponse.
 *
 * Previously declared as a package-private inner class of SessionHandler.
 * Promoted to a top-level public class so the {@code session/} collaborator
 * package and {@link com.praetor.store.SessionStore} can hold and mutate
 * it without reaching back into SessionHandler. AttackHandler still references
 * it as {@code Session} via the same package.
 *
 * Field semantics are unchanged — every existing caller (SessionHandler,
 * AttackHandler, all session/* collaborators) reads/writes the same fields
 * under the same synchronization regime (callers {@code synchronized(session)}
 * before mutating).
 */
public class Session {
    public String name;
    public String baseUrl;
    public Map<String, String> cookies = new LinkedHashMap<>();
    public Map<String, String> headers = new LinkedHashMap<>();
    public Map<String, String> variables = new LinkedHashMap<>();
    public String bearerToken = "";
    public String authUser = "";
    public String authPass = "";
    public HttpRequestResponse lastResponse;
}
