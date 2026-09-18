package com.praetor.ui;

import javax.imageio.ImageIO;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Frame;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 * Full-window screenshot of the Burp Suite frame, for evidence capture.
 *
 * <p>Optionally brings a named top-level Burp tab (Proxy, Repeater, Intruder,
 * Organizer, Logger, ...) to front before capturing, so the caller gets the tab
 * they asked for instead of whatever happened to be selected. Montoya has no
 * tab-select API, so this walks the Swing tree to the main tab strip — a bounded,
 * tested best-effort that degrades gracefully (unknown name -> current tab).
 *
 * <p>Capture renders the component tree OFFSCREEN via {@link Component#printAll}
 * — NOT a screen-region grab. A {@code Robot} screen capture of the frame's
 * bounds returns whatever pixels are composited there, so an overlapping window
 * gets captured instead of Burp. {@code printAll} paints Burp's own Swing
 * hierarchy: always Burp regardless of z-order, never another window's content.
 */
public final class SuiteScreenshot {

    private SuiteScreenshot() {}

    // Top-level Burp tab titles — used to identify the MAIN tab strip among the
    // several JTabbedPanes in the frame (sub-tabs like Proxy>HTTP-history score 0).
    private static final Set<String> TOP_LEVEL_TABS = Set.of(
        "dashboard", "target", "proxy", "intruder", "repeater", "collaborator",
        "sequencer", "decoder", "comparer", "logger", "organizer", "extensions",
        "learn");

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

    private static void runOnEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            try {
                SwingUtilities.invokeAndWait(r);
            } catch (Exception ignored) {
                // Best-effort — proceed with whatever state exists.
            }
        }
    }

    /** The main Burp tab strip: the JTabbedPane whose tab titles include the most
     *  known top-level names. Null if none looks like the Burp strip. */
    static JTabbedPane findMainTabbedPane(Component root) {
        List<JTabbedPane> panes = new ArrayList<>();
        collectTabbedPanes(root, panes);
        JTabbedPane best = null;
        int bestScore = 0;
        for (JTabbedPane p : panes) {
            int score = 0;
            for (int i = 0; i < p.getTabCount(); i++) {
                String t = p.getTitleAt(i);
                if (t != null && TOP_LEVEL_TABS.contains(t.trim().toLowerCase())) {
                    score++;
                }
            }
            if (score > bestScore) {
                bestScore = score;
                best = p;
            }
        }
        return best;
    }

    private static void collectTabbedPanes(Component c, List<JTabbedPane> out) {
        if (c instanceof JTabbedPane tp) {
            out.add(tp);
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                collectTabbedPanes(child, out);
            }
        }
    }

    /**
     * Select the top-level Burp tab whose title contains {@code tabName}
     * (case-insensitive), on the EDT. Returns the title actually selected, or
     * null if no match / no tab strip found (caller then captures the current
     * tab). Blank {@code tabName} is a no-op.
     */
    public static String selectTab(Frame frame, String tabName) {
        return selectTabIn(frame, tabName);
    }

    /** Selection core, over any component root (so it is testable without a
     *  heavyweight Frame, which cannot be built headless). */
    static String selectTabIn(Component root, String tabName) {
        if (tabName == null || tabName.isBlank()) {
            return null;
        }
        String needle = tabName.trim().toLowerCase();
        String[] selected = {null};
        runOnEdt(() -> {
            JTabbedPane tp = findMainTabbedPane(root);
            if (tp == null) {
                return;
            }
            for (int i = 0; i < tp.getTabCount(); i++) {
                String t = tp.getTitleAt(i);
                if (t != null && t.toLowerCase().contains(needle)) {
                    tp.setSelectedIndex(i);
                    selected[0] = t;
                    return;
                }
            }
        });
        return selected[0];
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
        runOnEdt(() -> {
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
        double s = Math.max(1.0, Math.min(requested, 4.0));
        int longSide = Math.max(width, height);
        if (longSide > 0 && longSide * s > maxLongSide) {
            s = (double) maxLongSide / longSide;
        }
        return Math.max(1.0, s);
    }

    /** Draw an amber call-out banner (the PoC step / caption) across the top. */
    static void drawCaption(BufferedImage img, String text, double scale) {
        Graphics2D g = img.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                               RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            int fs = Math.max(13, (int) Math.round(15 * scale));
            int pad = Math.max(6, (int) Math.round(6 * scale));
            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, fs));
            FontMetrics fm = g.getFontMetrics();
            int barH = fm.getHeight() + pad * 2;
            g.setColor(new Color(0, 0, 0, 205));
            g.fillRect(0, 0, img.getWidth(), barH);
            g.setColor(new Color(255, 214, 0));
            g.drawString(text, pad, pad + fm.getAscent());
        } finally {
            g.dispose();
        }
    }

    /**
     * Capture the Burp suite frame. De-iconifies it first (a minimized window
     * paints blank) but does NOT need to raise it — {@code printAll} is immune to
     * occlusion. Renders at an effective scale capped at ~2K and, when {@code
     * label} is non-blank, stamps it as a call-out banner (the PoC step).
     */
    public static BufferedImage captureFrame(Frame frame, double scale, String label) {
        runOnEdt(() -> {
            if ((frame.getExtendedState() & Frame.ICONIFIED) != 0) {
                frame.setExtendedState(Frame.NORMAL);
            }
        });
        Dimension d = frame.getSize();
        // frame.getSize() is in LOGICAL points; on a HiDPI/Retina display the
        // backing store is deviceScale× denser. Render at least at that density so
        // a Mac Retina capture is pixel-perfect, not a soft 1× logical grab.
        double deviceScale = 1.0;
        try {
            if (frame.getGraphicsConfiguration() != null) {
                deviceScale = frame.getGraphicsConfiguration()
                    .getDefaultTransform().getScaleX();
            }
        } catch (Exception ignored) {
            // No GC (headless/edge) — stay at 1×.
        }
        double eff = effectiveScale(d.width, d.height, Math.max(scale, deviceScale), 2560);
        BufferedImage img = captureComponent(frame, d.width, d.height, eff);
        if (label != null && !label.isBlank()) {
            drawCaption(img, label, eff);
        }
        return img;
    }

    /** Back-compat: 1×, no caption. */
    public static BufferedImage captureFrame(Frame frame) {
        return captureFrame(frame, 1.0, null);
    }
}
