package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.ui.SuiteScreenshot;
import com.praetor.util.JsonUtil;

import java.awt.Frame;
import java.awt.image.BufferedImage;
import java.util.Map;

/**
 * GET /api/ui/screenshot — full-window PNG of the Burp Suite frame, base64 in
 * JSON. With {@code ?tab=<name>} it first brings that top-level Burp tab to front
 * (Proxy, Repeater, Intruder, Organizer, Logger, ...); otherwise it captures
 * whatever tab is selected. For report evidence.
 */
public class ScreenshotHandler extends BaseHandler {

    private final MontoyaApi api;

    public ScreenshotHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Use GET.");
            return;
        }
        if (!SuiteScreenshot.displayAvailable()) {
            sendError(exchange, 409,
                "Burp is running headless (no GUI) — nothing to screenshot.",
                "headless",
                "Start Burp with its UI to capture the window.");
            return;
        }
        Frame frame = api.userInterface().swingUtils().suiteFrame();
        if (frame == null) {
            sendError(exchange, 409, "Burp suite frame unavailable.", "no_frame", null);
            return;
        }
        Map<String, String> params = queryParams(exchange);
        String requestedTab = params.getOrDefault("tab", "");
        String requestedSubtab = params.getOrDefault("subtab", "");
        // Best-effort: bring the requested top-level tab (and nested sub-tab, e.g.
        // Proxy > HTTP history) to front. A null entry => that level didn't match;
        // the caller sees selected_tab / selected_subtab.
        String[] selected = SuiteScreenshot.selectTab(frame, requestedTab, requestedSubtab);
        String selectedTab = selected[0];
        String selectedSubtab = selected[1];

        double scale = parseDouble(params.get("scale"), 2.0);   // 2× for readability
        // Optional footer strip (opt-in) — appended below the shot, hides nothing.
        String label = params.getOrDefault("label", "");        // PoC-step caption
        String trademark = params.getOrDefault("trademark", ""); // right-aligned brand

        BufferedImage img = SuiteScreenshot.captureFrame(frame, scale, label, trademark);
        sendJson(exchange, JsonUtil.object(
            "png_base64", SuiteScreenshot.pngBase64(img),
            "width", img.getWidth(),
            "height", img.getHeight(),
            "title", frame.getTitle(),
            "requested_tab", requestedTab,
            // The tab actually brought to front (null if not matched — the shot is
            // then the previously-selected tab).
            "selected_tab", selectedTab == null ? "" : selectedTab,
            "requested_subtab", requestedSubtab,
            "selected_subtab", selectedSubtab == null ? "" : selectedSubtab,
            "label", label,
            "trademark", trademark,
            // Identifies the capture engine so a caller can VERIFY which build is
            // loaded (printAll = occlusion-immune component render, not a screen
            // grab). Absent/other value => a stale jar is still loaded.
            "engine", "printall"
        ));
    }

    private static double parseDouble(String s, double fallback) {
        if (s == null || s.isBlank()) {
            return fallback;
        }
        try {
            double v = Double.parseDouble(s.trim());
            return Double.isFinite(v) ? v : fallback;   // reject NaN/Infinity
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
