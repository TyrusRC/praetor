package com.praetor.ui;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.util.List;

/**
 * Censor sensitive regions of an already-captured screenshot — cookies, session
 * tokens, keys, PII — before it goes into a report. Pure image work; no capture,
 * no re-render.
 */
public final class ScreenshotRedactor {

    private ScreenshotRedactor() {}

    private static int clamp(int v, int lo, int hi) {
        return v < lo ? lo : (v > hi ? hi : v);
    }

    /** Solid-fill overload (kept for callers that don't pass a style). */
    public static BufferedImage applyRedactions(BufferedImage src, List<int[]> boxes) {
        return applyRedactions(src, boxes, "solid");
    }

    /**
     * Draw redaction boxes OVER an existing image (no re-render) to hide
     * sensitive data — cookies, session tokens, keys, PII. Each box is
     * {@code [x, y, w, h]} in the image's own pixel coordinates; caller sizes it
     * to cover only the sensitive span (redact half a value, leave a prefix).
     *
     * <p>{@code style="pixel"} (or "mosaic") averages the box into COARSE blocks
     * — block size ~= the text height, so each block spans more than one glyph and
     * per-character information is destroyed (not a fine, reversible blur). Any
     * other style paints a solid opaque fill. Returns a new image; the original is
     * untouched.
     */
    public static BufferedImage applyRedactions(BufferedImage src, List<int[]> boxes,
                                                String style) {
        boolean pixel = "pixel".equalsIgnoreCase(style)
                     || "pixelate".equalsIgnoreCase(style)
                     || "mosaic".equalsIgnoreCase(style);
        BufferedImage out = new BufferedImage(src.getWidth(), src.getHeight(),
                                              BufferedImage.TYPE_INT_RGB);
        Graphics2D g = out.createGraphics();
        try {
            g.drawImage(src, 0, 0, null);
            for (int[] b : boxes) {
                if (b == null || b.length < 4) {
                    continue;
                }
                int x = clamp(b[0], 0, out.getWidth());
                int y = clamp(b[1], 0, out.getHeight());
                int w = clamp(b[2], 0, out.getWidth() - x);
                int h = clamp(b[3], 0, out.getHeight() - y);
                if (w <= 0 || h <= 0) {
                    continue;
                }
                if (pixel) {
                    mosaic(out, x, y, w, h);
                } else {
                    g.setColor(new Color(18, 18, 18));   // opaque, irreversible
                    g.fillRect(x, y, w, h);
                }
            }
        } finally {
            g.dispose();
        }
        return out;
    }

    /**
     * Pixel-mosaic a region in place: average each COARSE block to one colour.
     * Block ~= text height so a block spans &gt;1 character — collapsing distinct
     * glyphs to the same average makes the censoring non-invertible, unlike a
     * fine-grained blur that Depix-style tools can undo.
     */
    private static void mosaic(BufferedImage img, int x, int y, int w, int h) {
        int block = clamp((int) Math.round(h * 0.9), 10, 24);
        for (int by = y; by < y + h; by += block) {
            int bh = Math.min(block, y + h - by);
            for (int bx = x; bx < x + w; bx += block) {
                int bw = Math.min(block, x + w - bx);
                long r = 0, gr = 0, bl = 0;
                int n = 0;
                for (int j = by; j < by + bh; j++) {
                    for (int i = bx; i < bx + bw; i++) {
                        int p = img.getRGB(i, j);
                        r += (p >> 16) & 0xFF;
                        gr += (p >> 8) & 0xFF;
                        bl += p & 0xFF;
                        n++;
                    }
                }
                if (n == 0) {
                    continue;
                }
                int avg = (0xFF << 24) | ((int) (r / n) << 16)
                        | ((int) (gr / n) << 8) | (int) (bl / n);
                for (int j = by; j < by + bh; j++) {
                    for (int i = bx; i < bx + bw; i++) {
                        img.setRGB(i, j, avg);
                    }
                }
            }
        }
    }
}
