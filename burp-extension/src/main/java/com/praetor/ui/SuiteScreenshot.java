package com.praetor.ui;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Frame;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

/**
 * Full-window screenshot of the Burp Suite frame, for evidence capture.
 *
 * <p>Capture renders the component tree OFFSCREEN via {@link Component#printAll}
 * — NOT a screen-region grab. A {@code Robot} screen capture of the frame's
 * bounds returns whatever pixels are composited there, so an overlapping window
 * gets captured instead of Burp. {@code printAll} paints Burp's own Swing
 * hierarchy: always Burp regardless of z-order, never another window's content.
 *
 * <p>Tab/row/button navigation before a capture lives in {@link BurpNavigator};
 * redaction of a captured shot in {@link ScreenshotRedactor}; generic Swing-tree
 * helpers in {@link SwingUi}.
 */
public final class SuiteScreenshot {

    private SuiteScreenshot() {}

    /** True when a display is available to render (false in headless Burp). */
    public static boolean displayAvailable() {
        return SwingUi.displayAvailable();
    }

    /** PNG-encode an image and base64 it for JSON transport (the testable seam). */
    public static String pngBase64(BufferedImage img) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, "png", out);
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    public static BufferedImage captureComponent(Component c, int width, int height) {
        return captureComponent(c, width, height, 1.0);
    }

    /**
     * Render at {@code scale}× for readability (Burp windows are small; a 1×
     * grab pixelates when viewed larger). Supersampling draws the vector Swing
     * UI at higher resolution so text stays crisp on FHD/2K. Output is
     * {@code TYPE_INT_RGB} (no alpha) to keep the PNG small.
     */
    public static BufferedImage captureComponent(Component c, int width, int height, double scale) {
        int w = Math.max(1, (int) Math.round(width * scale));
        int h = Math.max(1, (int) Math.round(height * scale));
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        SwingUi.runOnEdt(() -> {
            Graphics2D g = img.createGraphics();
            try {
                g.setColor(Color.WHITE);
                g.fillRect(0, 0, w, h);
                g.setRenderingHint(RenderingHints.KEY_RENDERING,
                                   RenderingHints.VALUE_RENDER_QUALITY);
                g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                                   RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                g.scale(scale, scale);
                c.printAll(g);
            } finally {
                g.dispose();
            }
        });
        return img;
    }

    /**
     * Effective scale: honour the request but cap the long side at {@code
     * maxLongSide} (≈2K) so the PNG stays optimised, and never downscale below 1×.
     */
    public static double effectiveScale(int width, int height, double requested, int maxLongSide) {
        if (!Double.isFinite(requested)) {
            requested = 1.0;   // NaN/Infinity -> safe default (no 1px degenerate image)
        }
        double s = Math.max(1.0, Math.min(requested, 4.0));
        int longSide = Math.max(width, height);
        if (longSide > 0 && longSide * s > maxLongSide) {
            s = (double) maxLongSide / longSide;
        }
        return Math.max(1.0, s);
    }

    /**
     * Append a footer strip BELOW the screenshot (extends the canvas — hides no
     * content, like a phone-screenshot caption bar) carrying the caption (left)
     * and an optional trademark (right). Returns a new, taller image.
     */
    static BufferedImage addFooter(BufferedImage src, String caption,
                                   String trademark, double scale) {
        int fs = Math.max(13, (int) Math.round(14 * scale));
        int pad = Math.max(6, (int) Math.round(7 * scale));
        Font font = new Font(Font.SANS_SERIF, Font.BOLD, fs);

        BufferedImage probe = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
        Graphics2D pg = probe.createGraphics();
        pg.setFont(font);
        FontMetrics fm = pg.getFontMetrics();
        int footerH = fm.getHeight() + pad * 2;
        pg.dispose();

        int w = src.getWidth();
        BufferedImage out = new BufferedImage(w, src.getHeight() + footerH,
                                              BufferedImage.TYPE_INT_RGB);
        Graphics2D g = out.createGraphics();
        try {
            g.drawImage(src, 0, 0, null);
            g.setColor(new Color(24, 24, 28));
            g.fillRect(0, src.getHeight(), w, footerH);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                               RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g.setFont(font);
            int baseline = src.getHeight() + pad + fm.getAscent();
            if (caption != null && !caption.isBlank()) {
                g.setColor(new Color(255, 214, 0));
                g.drawString(caption, pad, baseline);
            }
            if (trademark != null && !trademark.isBlank()) {
                g.setColor(new Color(200, 200, 200));
                g.drawString(trademark, w - fm.stringWidth(trademark) - pad, baseline);
            }
        } finally {
            g.dispose();
        }
        return out;
    }

    /**
     * Capture the Burp suite frame. De-iconifies it first (a minimized window
     * paints blank) but does NOT need to raise it — {@code printAll} is immune to
     * occlusion. Renders at an effective scale capped at ~2K and, when {@code
     * caption} or {@code trademark} is non-blank, appends a footer strip below
     * the shot (no content hidden).
     */
    public static BufferedImage captureFrame(Frame frame, double scale,
                                             String caption, String trademark) {
        // De-iconify and read component state on the EDT (AWT state reads off the
        // EDT are not guaranteed consistent). Clear ONLY the ICONIFIED bit so a
        // maximized-then-minimized window isn't shrunk to "normal".
        Dimension[] dim = {null};
        double[] deviceScale = {1.0};
        SwingUi.runOnEdt(() -> {
            if ((frame.getExtendedState() & Frame.ICONIFIED) != 0) {
                frame.setExtendedState(frame.getExtendedState() & ~Frame.ICONIFIED);
            }
            dim[0] = frame.getSize();
            try {
                if (frame.getGraphicsConfiguration() != null) {
                    deviceScale[0] = frame.getGraphicsConfiguration()
                        .getDefaultTransform().getScaleX();
                }
            } catch (Exception ignored) {
                // No GC (edge) — stay at 1×.
            }
        });
        // frame.getSize() is in LOGICAL points; on a HiDPI/Retina display the
        // backing store is deviceScale× denser. Render at least at that density so
        // a Mac Retina capture is pixel-perfect, not a soft 1× logical grab.
        Dimension d = dim[0] != null ? dim[0] : new Dimension(1, 1);
        double eff = effectiveScale(d.width, d.height, Math.max(scale, deviceScale[0]), 2560);
        BufferedImage img = captureComponent(frame, d.width, d.height, eff);
        boolean wantFooter = (caption != null && !caption.isBlank())
                          || (trademark != null && !trademark.isBlank());
        if (wantFooter) {
            img = addFooter(img, caption, trademark, eff);
        }
        return img;
    }

    /** Back-compat: 1×, no footer. */
    public static BufferedImage captureFrame(Frame frame) {
        return captureFrame(frame, 1.0, null, null);
    }
}
