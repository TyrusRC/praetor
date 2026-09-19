package com.praetor.handlers;

import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.ui.SuiteScreenshot;
import com.praetor.util.JsonUtil;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * POST /api/ui/redact — draw opaque redaction boxes over an existing screenshot
 * (no re-capture, no re-render). Body: {png_base64, boxes:[[x,y,w,h], ...],
 * style:"pixel"|"solid"} in the image's own pixel coordinates ("pixel" = coarse
 * mosaic, default "solid"). Returns the redacted PNG as base64.
 */
public class RedactHandler extends BaseHandler {

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Use POST.");
            return;
        }
        Map<String, Object> body = readJsonBody(exchange);
        Object pngObj = body.get("png_base64");
        if (!(pngObj instanceof String s) || s.isEmpty()) {
            sendError(exchange, 400, "Missing 'png_base64'.");
            return;
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode((String) pngObj);
        } catch (IllegalArgumentException e) {
            sendError(exchange, 400, "Bad base64 image.");
            return;
        }
        BufferedImage src = ImageIO.read(new ByteArrayInputStream(raw));
        if (src == null) {
            sendError(exchange, 400, "Not a decodable image.");
            return;
        }

        List<int[]> boxes = new ArrayList<>();
        if (body.get("boxes") instanceof List<?> list) {
            for (Object o : list) {
                if (o instanceof List<?> b && b.size() >= 4) {
                    boxes.add(new int[]{toInt(b.get(0)), toInt(b.get(1)),
                                        toInt(b.get(2)), toInt(b.get(3))});
                }
            }
        }
        if (boxes.isEmpty()) {
            sendError(exchange, 400, "No valid boxes — each must be [x, y, w, h].");
            return;
        }

        String style = body.get("style") instanceof String st && !st.isBlank()
                     ? st : "solid";
        BufferedImage redacted = SuiteScreenshot.applyRedactions(src, boxes, style);
        sendJson(exchange, JsonUtil.object(
            "png_base64", SuiteScreenshot.pngBase64(redacted),
            "width", redacted.getWidth(),
            "height", redacted.getHeight(),
            "boxes_applied", boxes.size(),
            "style", style
        ));
    }

    private static int toInt(Object o) {
        if (o instanceof Number n) {
            return n.intValue();
        }
        try {
            return (int) Math.round(Double.parseDouble(String.valueOf(o)));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
