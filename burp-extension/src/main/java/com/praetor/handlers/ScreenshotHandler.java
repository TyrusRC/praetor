package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.ui.SuiteScreenshot;
import com.praetor.util.JsonUtil;

import java.awt.Frame;
import java.awt.image.BufferedImage;

/**
 * GET /api/ui/screenshot — full-window PNG of the Burp Suite frame, base64 in
 * JSON. Captures whatever tab the operator has on screen (history, Repeater,
 * Intruder, Organizer, ...) for report evidence.
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
        BufferedImage img = SuiteScreenshot.captureFrame(frame);
        sendJson(exchange, JsonUtil.object(
            "png_base64", SuiteScreenshot.pngBase64(img),
            "width", img.getWidth(),
            "height", img.getHeight(),
            "title", frame.getTitle()
        ));
    }
}
