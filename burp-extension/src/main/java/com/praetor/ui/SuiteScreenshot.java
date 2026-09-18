package com.praetor.ui;

import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

/**
 * Full-window screenshot of the Burp Suite frame, for evidence capture.
 *
 * <p>The operator selects the tab they want visible (Proxy &gt; HTTP history,
 * Repeater, Intruder, Organizer, ...) and the capture grabs whatever the suite
 * frame is currently showing. Montoya exposes the top-level frame but not the
 * individual tool tabs, so "which tab" is the operator's on-screen selection,
 * not a parameter.
 *
 * <p>Capture renders the component tree OFFSCREEN via {@link Component#printAll}
 * — NOT a screen-region grab. That matters: a {@code Robot} screen capture of
 * the frame's bounds returns whatever pixels are composited there, so an
 * overlapping window (another terminal, an editor) gets captured instead of
 * Burp, and the frame does not even need to be in front. {@code printAll} paints
 * Burp's own Swing hierarchy, so the result is always Burp regardless of z-order
 * and never leaks another window's content.
 */
public final class SuiteScreenshot {

    private SuiteScreenshot() {}

    /** PNG-encode an image and base64 it for JSON transport (the testable seam). */
    public static String pngBase64(BufferedImage img) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, "png", out);
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    /** True when a display is available to render (false in headless Burp). */
    public static boolean displayAvailable() {
        return !GraphicsEnvironment.isHeadless();
    }

    /**
     * Render a component to an image via {@code printAll}, on the EDT. Works for
     * any lightweight Swing component regardless of what overlaps it on screen.
     *
     * <p>NOTE: renders the Swing hierarchy. Standard Burp panels (HTTP editors,
     * tables, tabs) are Swing and paint correctly; a rare heavyweight/native peer
     * could come out blank. Upgrade path if that ever bites: composite a Robot
     * grab of just that sub-region.
     */
    public static BufferedImage captureComponent(Component c, int width, int height) {
        BufferedImage img = new BufferedImage(Math.max(1, width), Math.max(1, height),
                                              BufferedImage.TYPE_INT_ARGB);
        Runnable paint = () -> {
            Graphics2D g = img.createGraphics();
            try {
                c.printAll(g);
            } finally {
                g.dispose();
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            paint.run();
        } else {
            try {
                SwingUtilities.invokeAndWait(paint);
            } catch (Exception ignored) {
                // Best-effort — return whatever was painted (possibly blank).
            }
        }
        return img;
    }

    /**
     * Capture the Burp suite frame. De-iconifies it first (a minimized window
     * paints blank) but does NOT need to raise it — {@code printAll} is immune to
     * occlusion.
     */
    public static BufferedImage captureFrame(Frame frame) {
        try {
            SwingUtilities.invokeAndWait(() -> {
                if ((frame.getExtendedState() & Frame.ICONIFIED) != 0) {
                    frame.setExtendedState(Frame.NORMAL);
                }
            });
        } catch (Exception ignored) {
            // De-iconify is best-effort; capture proceeds regardless.
        }
        Dimension d = frame.getSize();
        return captureComponent(frame, d.width, d.height);
    }
}
