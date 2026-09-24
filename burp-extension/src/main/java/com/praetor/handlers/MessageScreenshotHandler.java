package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.ui.MessageEditorShot;
import com.praetor.ui.SuiteScreenshot;
import com.praetor.util.JsonUtil;

import java.awt.Frame;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.util.List;
import java.util.Map;

/**
 * POST /api/ui/message-screenshot — screenshot ONE proxy-history request or
 * response, auto-scrolled to and highlighting a keyword, for when the message is
 * too long to fit a single viewport.
 *
 * <p>Body: {@code {proxy_index:int, which:"request"|"response", search:"<expr>",
 * width:int, height:int, scale:double}}. Renders the message in our own read-only
 * Burp editor, applies the native search (highlight + scroll to first match), and
 * returns the PNG as base64 — see {@link MessageEditorShot}. The operator's live
 * Burp UI is not navigated or touched.
 */
public class MessageScreenshotHandler extends BaseHandler {

    private final MontoyaApi api;

    public MessageScreenshotHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Use POST.");
            return;
        }
        if (!SuiteScreenshot.displayAvailable()) {
            sendError(exchange, 409,
                "Burp is running headless (no GUI) — nothing to render.",
                "headless",
                "Start Burp with its UI to capture a message editor.");
            return;
        }
        Map<String, Object> body = readJsonBody(exchange);

        int index = intOf(body.get("proxy_index"), -1);
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index < 0 || index >= history.size()) {
            sendError(exchange, 404,
                "proxy_index out of range (have 0.." + (history.size() - 1) + ")");
            return;
        }
        ProxyHttpRequestResponse item = history.get(index);

        // 'both' (default) stacks request over response — real proxy-history
        // evidence. 'request'/'response' render just one.
        String which = strOf(body.get("which"), "both").toLowerCase();
        if (!which.equals("request") && !which.equals("response")) {
            which = "both";
        }
        HttpRequest req = item.finalRequest();
        HttpResponse resp = item.originalResponse();
        // No response captured for this entry — fall back to the request alone
        // rather than render an empty response pane.
        if (resp == null) {
            if (which.equals("response")) {
                sendError(exchange, 409,
                    "history entry " + index + " has no response to render — "
                    + "capture the request instead (which='request').");
                return;
            }
            which = "request";
        }

        String layout = strOf(body.get("layout"), "side").toLowerCase();
        if (!layout.equals("stacked")) {
            layout = "side";
        }
        String search = strOf(body.get("search"), "");
        // Side-by-side halves each pane's width, so default wider there for readable
        // HTTP lines (the report standard: don't shrink text past legibility).
        int defW = which.equals("both") && layout.equals("side") ? 1600 : 1000;
        int width = MessageEditorShot.clampDim(intOf(body.get("width"), defW), 300, 2600);
        int height = MessageEditorShot.clampDim(intOf(body.get("height"), 760), 200, 4000);
        double scale = parseScale(body.get("scale"));

        BufferedImage img = MessageEditorShot.capture(
            api, which, layout, req, resp, search, width, height, scale);

        // Real Burp window title (with version/project/licence) and window icon,
        // so a composite header can render the exact chrome instead of guessing.
        String burpTitle = "";
        String burpIconB64 = "";
        try {
            Frame frame = api.userInterface().swingUtils().suiteFrame();
            if (frame != null) {
                burpTitle = frame.getTitle() != null ? frame.getTitle() : "";
                burpIconB64 = iconBase64(frame);
            }
        } catch (RuntimeException ignored) {
            // best-effort — the shot still returns without the chrome extras
        }

        sendJson(exchange, JsonUtil.object(
            "png_base64", SuiteScreenshot.pngBase64(img),
            "width", img.getWidth(),
            "height", img.getHeight(),
            "burp_title", burpTitle,
            "burp_icon_b64", burpIconB64,
            "which", which,
            "layout", layout,
            // Echo the search expression actually applied — empty => captured from
            // the top of the message (no keyword given / matched).
            "search", search,
            "proxy_index", index,
            // Capture engine, so a caller can verify this build is loaded (native
            // editor search + printAll, not a full-window grab).
            "engine", "editor-search"
        ));
    }

    /** The frame's largest window icon as a PNG base64 (Burp's logo), or "". */
    private static String iconBase64(Frame frame) throws Exception {
        java.util.List<Image> icons = frame.getIconImages();
        if (icons == null || icons.isEmpty()) {
            return "";
        }
        Image best = null;
        int bestW = -1;
        for (Image im : icons) {
            int w = im.getWidth(null);
            if (w > bestW) {
                bestW = w;
                best = im;
            }
        }
        if (best == null || bestW <= 0) {
            return "";
        }
        int h = Math.max(1, best.getHeight(null));
        BufferedImage bi = new BufferedImage(bestW, h, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = bi.createGraphics();
        try {
            g.drawImage(best, 0, 0, null);
        } finally {
            g.dispose();
        }
        return SuiteScreenshot.pngBase64(bi);
    }

    private static int intOf(Object o, int fallback) {
        if (o instanceof Number n) {
            return n.intValue();
        }
        try {
            return (int) Math.round(Double.parseDouble(String.valueOf(o)));
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    private static String strOf(Object o, String fallback) {
        return o instanceof String s && !s.isBlank() ? s : fallback;
    }

    private static double parseScale(Object o) {
        double s = 2.0;
        if (o instanceof Number n) {
            s = n.doubleValue();
        } else if (o != null) {
            try {
                s = Double.parseDouble(String.valueOf(o));
            } catch (NumberFormatException ignore) {
                s = 2.0;
            }
        }
        if (!Double.isFinite(s)) {
            return 2.0;
        }
        return Math.max(1.0, Math.min(s, 4.0));
    }
}
