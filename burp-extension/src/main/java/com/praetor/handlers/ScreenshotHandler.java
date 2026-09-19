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

        // Snapshot the operator's current view (tab / sub-tab / row / layout) so we
        // can restore it after capturing — a screenshot must NOT leave a human's
        // Burp on a different tab/selection than they had it (don't disrupt someone
        // using the mouse). Default on; ?restore=false leaves the navigation.
        boolean restore = !"false".equalsIgnoreCase(params.getOrDefault("restore", "true"));
        SuiteScreenshot.UiSnapshot snapshot = restore ? SuiteScreenshot.snapshotUi(frame) : null;

        String requestedTab = params.getOrDefault("tab", "");
        String requestedSubtab = params.getOrDefault("subtab", "");
        // Best-effort: bring the requested top-level tab (and nested sub-tab, e.g.
        // Proxy > HTTP history) to front. A null entry => that level didn't match;
        // the caller sees selected_tab / selected_subtab.
        String[] selected = SuiteScreenshot.selectTab(frame, requestedTab, requestedSubtab);
        String selectedTab = selected[0];
        String selectedSubtab = selected[1];

        // Optionally click a real Burp button (by text/tooltip/accessible-name)
        // in the selected tab so the action runs THROUGH the UI and its result
        // renders — an API call leaves the UI unchanged. Works for standard Swing
        // buttons (Collaborator "Poll now"/"Copy to clipboard", Settings, ...).
        // NOTE: Repeater's "Send" is a custom-painted control, not a Swing button,
        // so it is NOT clickable here — fire Repeater via repeater_resend instead.
        // The action is async, so wait before capturing.
        String clickButton = params.getOrDefault("click_button", "");
        // Select a specific row in the selected tab's main table (Proxy HTTP
        // history, Logger, ...) and scroll it into view, so the row's req/resp
        // detail renders and the shot shows a SPECIFIC request. Value: a "#"
        // entry number, or "last"/"newest" for the most recent row.
        String selectRow = params.getOrDefault("select_row", "");
        int selectedRow = -1;
        if (!selectRow.isBlank()) {
            int want = -1;   // <0 = last/newest
            if (!selectRow.equalsIgnoreCase("last") && !selectRow.equalsIgnoreCase("newest")) {
                try {
                    want = Integer.parseInt(selectRow.trim());
                } catch (NumberFormatException ignore) {
                    want = -1;
                }
            }
            selectedRow = SuiteScreenshot.selectTableRow(frame, want);
            try {
                Thread.sleep(400);   // let the req/resp detail pane render
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }

        boolean clickedButton = false;
        // Diagnostic: what clickable buttons the selected tab actually exposes —
        // helps when a label doesn't match (Burp's custom UI may not use standard
        // AbstractButtons). Only computed when a click was requested.
        java.util.List<String> availableButtons = java.util.List.of();
        if (!clickButton.isBlank()) {
            availableButtons = SuiteScreenshot.listButtons(frame);
            clickedButton = SuiteScreenshot.clickButton(frame, clickButton);
            if (clickedButton) {
                try {
                    Thread.sleep(2500);   // let the action round-trip + the pane render
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        double scale = parseDouble(params.get("scale"), 2.0);   // 2× for readability
        // Optional footer strip (opt-in) — appended below the shot, hides nothing.
        String label = params.getOrDefault("label", "");        // PoC-step caption
        String trademark = params.getOrDefault("trademark", ""); // right-aligned brand

        BufferedImage img = SuiteScreenshot.captureFrame(frame, scale, label, trademark);
        // Put the operator's view back exactly as it was (the PNG already holds the
        // navigated state). A button CLICK is a real action and is not undone.
        SuiteScreenshot.restoreUi(snapshot);
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
            "clicked_button", clickedButton ? clickButton : "",
            "available_buttons", availableButtons,
            "selected_row", selectedRow,
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
