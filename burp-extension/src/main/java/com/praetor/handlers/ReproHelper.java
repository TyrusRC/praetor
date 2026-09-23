package com.praetor.handlers;

import com.praetor.http.HttpExchange;
import com.praetor.http.HttpResponses;
import com.praetor.store.FindingsStore;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * reproductions[] parsing + Rule 10a validation, split out of NotesHandler so the
 * save-finding handler stays under the line ceiling. Behaviour is unchanged: the
 * endpoint-mismatch check is passed in (NotesHandler::describeEndpointMismatch,
 * which needs live Burp data) so the gate is identical to the inline version.
 */
final class ReproHelper {

    private ReproHelper() {}

    /** Coerce the raw JSON `reproductions` value into a list of maps (null when absent/non-list). */
    static List<Map<String, Object>> parse(Object reproductionsObj) {
        if (!(reproductionsObj instanceof List<?> rawList)) return null;
        List<Map<String, Object>> reproductions = new ArrayList<>();
        for (Object item : rawList) {
            if (item instanceof Map<?, ?> rawMap) {
                reproductions.add(NotesHandler.toStringObjectMap(rawMap));
            }
        }
        return reproductions;
    }

    /**
     * Rule 10a gate for timing/blind classes: >=3 reproductions, each a numeric
     * proxy_history_index that is in range and hits the finding's endpoint. Sends the
     * matching 400 and returns false on the first failure; true when the class
     * does not require reproductions or they all pass.
     */
    static boolean validate(HttpExchange exchange, List<Map<String, Object>> reproductions,
                            String vulnType, int proxyHistorySize, String findingEndpoint,
                            BiFunction<Integer, String, String> mismatchFn) throws IOException {
        if (!FindingsStore.requiresReproductions(vulnType)) return true;

        if (reproductions == null || reproductions.size() < 3) {
            HttpResponses.sendError(exchange, 400,
                "'" + vulnType + "' requires reproductions[] with >= 3 verified proxy-history entries (Rule 10a)",
                "reproductions_required",
                "Replay the timing/blind probe 2 more times so the array totals 3 entries; pass reproductions=[{proxy_history_index, elapsed_ms, status_code}, ...].");
            return false;
        }
        for (Map<String, Object> rep : reproductions) {
            Object ridx = rep.get("proxy_history_index");
            if (!(ridx instanceof Number)) {
                HttpResponses.sendError(exchange, 400, "reproductions[].proxy_history_index must be a number",
                    "reproductions_invalid",
                    "Each entry in reproductions[] must include proxy_history_index as an integer.");
                return false;
            }
            int ri = ((Number) ridx).intValue();
            if (ri < 0 || ri >= proxyHistorySize) {
                HttpResponses.sendError(exchange, 400, "reproductions[].proxy_history_index not found: " + ri,
                    "reproductions_invalid",
                    "Proxy-history index " + ri + " is out of range (history size = " + proxyHistorySize + ").");
                return false;
            }
            String repMismatch = mismatchFn.apply(ri, findingEndpoint);
            if (repMismatch != null) {
                HttpResponses.sendError(exchange, 400,
                    "reproductions[].proxy_history_index " + ri + " is a different request: " + repMismatch,
                    "reproductions_invalid",
                    "Every replay in reproductions[] must hit the endpoint the finding describes. "
                    + "A replay of unrelated traffic is not a reproduction.");
                return false;
            }
        }
        return true;
    }
}
