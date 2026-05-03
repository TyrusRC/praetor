package com.swissknife.server;

/**
 * Shared per-response truncation limits used by every handler that ships
 * an HTTP response body back to the MCP server. Centralized so that one
 * change propagates instead of drifting across 4+ handlers.
 */
public final class ResponseLimits {

    /** Maximum characters of response body returned to the MCP server in one call. */
    public static final int MAX_RESPONSE_BODY = 50_000;

    /** Maximum characters of static resource (JS/CSS) returned in one call. */
    public static final int MAX_RESOURCE_BODY = 50_000;

    private ResponseLimits() {}
}
