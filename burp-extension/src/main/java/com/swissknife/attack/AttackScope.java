package com.swissknife.attack;

import burp.api.montoya.MontoyaApi;
import com.swissknife.http.HttpExchange;
import static com.swissknife.http.HttpResponses.sendError;

import java.io.IOException;

/**
 * Standalone scope-check helper for attack collaborator classes that live
 * outside the {@code handlers} package and therefore can't reach
 * BaseHandler's protected requireInScope() / isInScopeQuiet().
 *
 * Behaviour is preserved verbatim from BaseHandler.requireInScope:
 *   - null/blank URL or null api -> 400 validation_failed, return false
 *   - in-scope -> return true
 *   - strict mode + out-of-scope -> 403 out_of_scope, return false
 *   - operator mode + out-of-scope -> audit-log + return true (proceed)
 *   - URL parse failure -> 400 validation_failed, return false
 */
public final class AttackScope {

    private AttackScope() { }

    /**
     * Loud variant: sends a structured error response and returns false if
     * the URL is not allowed. Caller MUST bail out without further work when
     * this returns false.
     */
    public static boolean requireInScope(MontoyaApi api, HttpExchange exchange, String url) throws IOException {
        if (api == null || url == null || url.isBlank()) {
            sendError(exchange, 400,
                "Missing URL for scope check",
                "validation_failed",
                "Provide a non-empty url before sending.");
            return false;
        }
        try {
            boolean inScope = api.scope().isInScope(url);
            if (!inScope) {
                String mode = com.swissknife.handlers.ScopeHandler.currentMode;
                if ("strict".equals(mode)) {
                    sendError(exchange, 403,
                        "URL is out of scope: " + url,
                        "out_of_scope",
                        "Add the URL/host to Burp scope (configure_scope) before sending requests to it, or set mode='operator'.");
                    return false;
                }
                com.swissknife.audit.ScopeAuditLog.append(
                    exchange.getRequestURI().getPath(), url, mode
                );
            }
        } catch (Exception e) {
            sendError(exchange, 400,
                "Invalid URL for scope check: " + url + " - " + e.getMessage(),
                "validation_failed",
                "Verify the URL is well-formed before retrying.");
            return false;
        }
        return true;
    }

}
