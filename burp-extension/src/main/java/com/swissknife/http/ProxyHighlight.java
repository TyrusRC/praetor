package com.swissknife.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.List;

/**
 * Tag recent Proxy → HTTP history entries with a highlight colour and a
 * short note so hunters can sort/filter the history panel to find notable
 * probe pairs at a glance.
 *
 * Usage pattern:
 * <pre>
 *   // After sending a probe through ProxyTunnel:
 *   ProxyHighlight.tagLatest(api, url, ProxyHighlight.Level.ANOMALY,
 *       "probe 1' -> 500 (baseline 200)");
 * </pre>
 *
 * Colour legend (matches memory/feedback_tool_traffic_in_proxy.md):
 *   RED    = confirmed-ish evidence (Collaborator callback, SQL error leak)
 *   ORANGE = anomaly worth manual review (status delta, length > 50%, 3x timing)
 *   YELLOW = baseline or probe pair in an active scored test
 *   GREEN  = clean baseline captures
 */
public final class ProxyHighlight {

    public enum Level {
        CONFIRMED(HighlightColor.RED),
        ANOMALY(HighlightColor.ORANGE),
        PROBE(HighlightColor.YELLOW),
        BASELINE(HighlightColor.GREEN);

        public final HighlightColor color;
        Level(HighlightColor c) { this.color = c; }
    }

    private ProxyHighlight() {}

    /**
     * Find the most recent Proxy history entry whose URL equals {@code url}
     * and annotate it with {@code level} and {@code note}. Silently no-ops
     * if no matching entry is found (the tunnel may not have flushed yet, or
     * the request went out via the Logger-only fallback).
     */
    public static void tagLatest(MontoyaApi api, String url, Level level, String note) {
        if (api == null || url == null || url.isEmpty()) return;
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            // Iterate from the end — latest entries land there.
            for (int i = history.size() - 1; i >= 0; i--) {
                ProxyHttpRequestResponse item = history.get(i);
                String itemUrl = item.finalRequest().url();
                if (url.equals(itemUrl)) {
                    Annotations a = item.annotations();
                    a.setHighlightColor(level.color);
                    // Don't stomp on existing notes from prior passes.
                    String existing = a.notes();
                    String merged = (existing == null || existing.isEmpty())
                        ? note : existing + " | " + note;
                    a.setNotes(merged);
                    return;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("ProxyHighlight.tagLatest failed: " + e.getMessage());
        }
    }

    /** Derive a highlight Level from baseline/probe response deltas. */
    public static Level classify(int baselineStatus, int probeStatus,
                                 int baselineLength, int probeLength,
                                 long probeTimeMs, long baselineTimeMs,
                                 boolean indicatorMatched) {
        if (indicatorMatched) return Level.CONFIRMED;
        // Any 2xx -> 5xx transition, or large length delta, counts as anomaly.
        int baseClass = baselineStatus / 100;
        int probeClass = probeStatus / 100;
        if (baseClass == 2 && probeClass == 5) return Level.ANOMALY;
        int lenDelta = Math.abs(probeLength - baselineLength);
        if (baselineLength > 0 && lenDelta > baselineLength * 0.5 && lenDelta > 1000) {
            return Level.ANOMALY;
        }
        if (baselineTimeMs > 0 && probeTimeMs > baselineTimeMs * 3 && probeTimeMs > 3000) {
            return Level.ANOMALY;
        }
        return Level.PROBE;
    }
}
