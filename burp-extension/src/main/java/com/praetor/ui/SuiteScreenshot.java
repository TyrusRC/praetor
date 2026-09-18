package com.praetor.ui;

import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;
import java.awt.AWTException;
import java.awt.Frame;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.awt.Robot;
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
 */
public final class SuiteScreenshot {

    private SuiteScreenshot() {}

    /** PNG-encode an image and base64 it for JSON transport (the testable seam). */
    public static String pngBase64(BufferedImage img) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, "png", out);
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    /** True when a display is available to capture (false in headless Burp). */
    public static boolean displayAvailable() {
        return !GraphicsEnvironment.isHeadless();
    }

    /**
     * Capture the given frame as it currently appears on screen. Brings it to
     * front on the EDT first (best-effort) so an overlapping window doesn't
     * occlude it, then grabs its screen bounds.
     *
     * <p>NOTE: single-screen capture via the default Robot over the virtual
     * coordinate space — covers the common single-monitor case. A frame dragged
     * onto a secondary display with a different origin may clip; upgrade path is
     * a per-device Robot from {@code frame.getGraphicsConfiguration()}.
     */
    public static BufferedImage captureFrame(Frame frame) throws AWTException {
        try {
            SwingUtilities.invokeAndWait(() -> {
                frame.toFront();
                frame.requestFocus();
            });
        } catch (Exception ignored) {
            // toFront is best-effort; capture proceeds regardless.
        }
        Rectangle bounds = frame.getBounds();
        return new Robot().createScreenCapture(bounds);
    }
}
