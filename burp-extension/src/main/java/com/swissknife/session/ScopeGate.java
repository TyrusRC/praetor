package com.swissknife.session;

import burp.api.montoya.MontoyaApi;

/**
 * Standalone scope-check helper for collaborator classes that live outside
 * the {@code handlers} package and therefore can't reach BaseHandler's
 * protected isInScopeQuiet(). Logic mirrors {@code BaseHandler.isInScopeQuiet}
 * exactly so behaviour stays identical:
 *   - null/blank URL → false (drop)
 *   - in-scope → true
 *   - strict mode + out-of-scope → false (drop)
 *   - operator mode + out-of-scope → audit-log + true (proceed)
 */
public final class ScopeGate {

    private ScopeGate() { }

    public static boolean isInScopeQuiet(MontoyaApi api, String url) {
        return isInScopeQuiet(api, url, "");
    }

    public static boolean isInScopeQuiet(MontoyaApi api, String url, String tool) {
        if (api == null || url == null || url.isBlank()) return false;
        try {
            if (api.scope().isInScope(url)) return true;
            String mode = com.swissknife.handlers.ScopeHandler.currentMode;
            if ("strict".equals(mode)) return false;
            com.swissknife.audit.ScopeAuditLog.append(
                tool == null ? "" : tool, url, mode
            );
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
