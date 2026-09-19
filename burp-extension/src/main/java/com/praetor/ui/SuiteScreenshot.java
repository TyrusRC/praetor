package com.praetor.ui;

import javax.imageio.ImageIO;
import javax.swing.AbstractButton;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
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
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
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

    /**
     * Run on the EDT and PROPAGATE failures — a render that throws must surface
     * as an error, not a silent blank-but-valid PNG returned as success.
     */
    private static void runOnEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
            return;
        }
        try {
            SwingUtilities.invokeAndWait(r);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();          // restore the flag
            throw new RuntimeException("interrupted during EDT operation", e);
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw new RuntimeException("EDT operation failed: " + cause, cause);
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
        return selectTabAndSubIn(frame, tabName, null)[0];
    }

    /** Select a top-level tab AND, if given, a nested sub-tab within it (e.g.
     *  Proxy > HTTP history). Returns {topTitle, subTitle}; either may be null. */
    public static String[] selectTab(Frame frame, String tabName, String subTabName) {
        return selectTabAndSubIn(frame, tabName, subTabName);
    }

    /** Index of the tab whose title best matches {@code needle} (lowercased):
     *  EXACT, then prefix, then substring — so an abbreviated name doesn't grab
     *  the wrong tab when a better match exists later. -1 if none. */
    static int matchTab(JTabbedPane tp, String needle) {
        int exact = -1, prefix = -1, contains = -1;
        for (int i = 0; i < tp.getTabCount(); i++) {
            String t = tp.getTitleAt(i);
            if (t == null) {
                continue;
            }
            String lt = t.toLowerCase();
            if (lt.equals(needle) && exact < 0) {
                exact = i;
            } else if (lt.startsWith(needle) && prefix < 0) {
                prefix = i;
            } else if (lt.contains(needle) && contains < 0) {
                contains = i;
            }
        }
        return exact >= 0 ? exact : (prefix >= 0 ? prefix : contains);
    }

    /** The nested JTabbedPane under {@code root} that HAS a tab matching
     *  {@code needle} — so a sub-tab name finds the tool's own sub-strip, not a
     *  deep editor's Pretty/Raw/Hex strip. DFS pre-order = shallowest first. */
    static JTabbedPane findSubTabbedPaneWith(Component root, String needle) {
        List<JTabbedPane> panes = new ArrayList<>();
        collectTabbedPanes(root, panes);
        for (JTabbedPane p : panes) {
            if (matchTab(p, needle) >= 0) {
                return p;
            }
        }
        return null;
    }

    /** Back-compat single-tab selector (over any component root — testable
     *  without a heavyweight Frame). */
    static String selectTabIn(Component root, String tabName) {
        return selectTabAndSubIn(root, tabName, null)[0];
    }

    /**
     * Selection core over any component root. Selects the top-level tab, then (if
     * {@code subTabName} is given) descends into that tool's component to select a
     * nested sub-tab. Best-effort — a failure never aborts the capture. Returns
     * {topTitle, subTitle}; a null entry means that level didn't match.
     */
    static String[] selectTabAndSubIn(Component root, String tabName, String subTabName) {
        String[] out = {null, null};
        if (tabName == null || tabName.isBlank()) {
            return out;
        }
        String topNeedle = tabName.trim().toLowerCase();
        String subNeedle = (subTabName == null || subTabName.isBlank())
            ? null : subTabName.trim().toLowerCase();
        try {
            runOnEdt(() -> {
                JTabbedPane main = findMainTabbedPane(root);
                if (main == null) {
                    return;
                }
                int idx = matchTab(main, topNeedle);
                if (idx < 0) {
                    return;
                }
                main.setSelectedIndex(idx);
                out[0] = main.getTitleAt(idx);
                if (subNeedle != null) {
                    JTabbedPane sub = findSubTabbedPaneWith(main.getComponentAt(idx), subNeedle);
                    if (sub != null) {
                        int sidx = matchTab(sub, subNeedle);
                        if (sidx >= 0) {
                            sub.setSelectedIndex(sidx);
                            out[1] = sub.getTitleAt(sidx);
                        }
                    }
                }
            });
        } catch (RuntimeException e) {
            // Best-effort — never abort the capture over tab selection.
            return out;
        }
        return out;
    }

    /** The first enabled {@link AbstractButton} under {@code root} whose text
     *  equals {@code label} (case-insensitive, trimmed). Null if none. */
    static AbstractButton findButton(Component root, String label) {
        if (root instanceof AbstractButton b) {
            String t = b.getText();
            if (t != null && t.trim().equalsIgnoreCase(label)) {
                return b;
            }
        }
        if (root instanceof Container c) {
            for (Component child : c.getComponents()) {
                AbstractButton found = findButton(child, label);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    static void collectButtons(Component c, List<AbstractButton> out) {
        if (c instanceof AbstractButton b) {
            out.add(b);
        }
        if (c instanceof Container ct) {
            for (Component child : ct.getComponents()) {
                collectButtons(child, out);
            }
        }
    }

    /** A button's identifying label: its text, else its tooltip, else its
     *  accessible name — so a custom-painted, text-less button (Burp's "Send") is
     *  still matchable. */
    static String buttonLabel(AbstractButton b) {
        String t = b.getText();
        if (t != null && !t.isBlank()) {
            return t.trim();
        }
        t = b.getToolTipText();
        if (t != null && !t.isBlank()) {
            return t.trim();
        }
        try {
            String a = b.getAccessibleContext().getAccessibleName();
            if (a != null && !a.isBlank()) {
                return a.trim();
            }
        } catch (Exception ignored) {
            // no accessible context
        }
        return "";
    }

    /** Best {@link AbstractButton} match under {@code root}: exact label, then a
     *  prefix, then a substring (matched on text/tooltip/accessible-name so a
     *  text-less custom button is still found), preferring an enabled one. */
    static AbstractButton findButtonFuzzy(Component root, String wantLower) {
        List<AbstractButton> all = new ArrayList<>();
        collectButtons(root, all);
        AbstractButton exact = null, prefix = null, contains = null;
        for (AbstractButton b : all) {
            String label = buttonLabel(b);
            if (label.isEmpty()) {
                continue;
            }
            String lt = label.toLowerCase();
            if (lt.equals(wantLower) && (exact == null || b.isEnabled())) {
                exact = b;
            } else if (lt.startsWith(wantLower) && prefix == null) {
                prefix = b;
            } else if (lt.contains(wantLower) && contains == null) {
                contains = b;
            }
        }
        return exact != null ? exact : (prefix != null ? prefix : contains);
    }

    /** Enabled-button labels under the currently-selected top tab — a diagnostic
     *  so a caller can see what's clickable (Burp's custom UI may not expose a
     *  given control as a standard AbstractButton). */
    public static List<String> listButtons(Frame frame) {
        List<String> out = new ArrayList<>();
        try {
            runOnEdt(() -> {
                Component scope = selectedTopComponent(frame);
                List<AbstractButton> all = new ArrayList<>();
                collectButtons(scope, all);
                for (AbstractButton b : all) {
                    String label = buttonLabel(b);   // text, else tooltip/accessible-name
                    if (!label.isEmpty()) {
                        out.add(label + (b.isEnabled() ? "" : " (disabled)"));
                    }
                }
            });
        } catch (RuntimeException e) {
            // diagnostic only
        }
        return out;
    }

    static void collectTables(Component c, List<JTable> out) {
        if (c instanceof JTable t) {
            out.add(t);
        }
        if (c instanceof Container ct) {
            for (Component child : ct.getComponents()) {
                collectTables(child, out);
            }
        }
    }

    static void collectSplitPanes(Component c, List<JSplitPane> out) {
        if (c instanceof JSplitPane sp) {
            out.add(sp);
        }
        if (c instanceof Container ct) {
            for (Component child : ct.getComponents()) {
                collectSplitPanes(child, out);
            }
        }
    }

    static boolean containsTable(Component c) {
        List<JTable> t = new ArrayList<>();
        collectTables(c, t);
        return !t.isEmpty();
    }

    /**
     * If the table/detail VERTICAL split (table on top, request/response below)
     * is collapsed to a table-only view, open it to ~55% so a selected row's
     * request/response detail is visible. Best-effort, on the EDT.
     */
    static void ensureDetailPaneVisible(Component root) {
        List<JSplitPane> splits = new ArrayList<>();
        collectSplitPanes(root, splits);
        for (JSplitPane sp : splits) {
            if (sp.getOrientation() != JSplitPane.VERTICAL_SPLIT) {
                continue;
            }
            Component top = sp.getTopComponent();
            if (top == null || !containsTable(top)) {
                continue;   // want the split whose TOP holds the history table
            }
            int h = sp.getHeight();
            if (h <= 0) {
                return;
            }
            int div = sp.getDividerLocation();
            int max = sp.getMaximumDividerLocation();
            if (div >= max - 5 || div >= h - 60) {   // detail collapsed
                sp.setDividerLocation(0.55);
            }
            return;
        }
    }

    /** View-row for a table's first ("#") column value {@code wantNumber}; the
     *  last row when {@code wantNumber < 0} or no match (empty table -> -1). */
    static int rowForNumber(JTable table, int wantNumber) {
        if (table.getRowCount() == 0) {
            return -1;
        }
        if (wantNumber >= 0) {
            String want = String.valueOf(wantNumber);
            for (int r = 0; r < table.getRowCount(); r++) {
                Object v = table.getValueAt(r, 0);
                if (v != null && v.toString().trim().equals(want)) {
                    return r;
                }
            }
        }
        return table.getRowCount() - 1;
    }

    /** The JTable with the most rows under {@code root} — the history/results
     *  table rather than a small side table. Null if none. */
    static JTable findLargestTable(Component root) {
        List<JTable> tables = new ArrayList<>();
        collectTables(root, tables);
        JTable best = null;
        for (JTable t : tables) {
            if (best == null || t.getRowCount() > best.getRowCount()) {
                best = t;
            }
        }
        return best;
    }

    /**
     * Select a row in the selected tab's main table (Proxy HTTP history, Logger,
     * Intruder results, ...) and scroll it into view, on the EDT — so the row's
     * request/response detail renders below and a screenshot shows a SPECIFIC
     * request. {@code wantNumber} is the value in the table's first ("#") column
     * (Burp's 1-based entry number); pass < 0 for the last (newest) row. Returns
     * the selected view-row index (0-based), or -1 if no table/row.
     */
    public static int selectTableRow(Frame frame, int wantNumber) {
        int[] result = {-1};
        try {
            runOnEdt(() -> {
                JTable table = findLargestTable(selectedTopComponent(frame));
                if (table == null || table.getRowCount() == 0) {
                    return;
                }
                int viewRow = rowForNumber(table, wantNumber);
                table.setRowSelectionInterval(viewRow, viewRow);
                table.scrollRectToVisible(table.getCellRect(viewRow, 0, true));
                // The selected row's request/response detail lives in a bottom
                // split-pane that is often collapsed (table-only view) — open it
                // so the shot shows the request + response, not just the row.
                ensureDetailPaneVisible(selectedTopComponent(frame));
                result[0] = viewRow;
            });
        } catch (RuntimeException e) {
            return -1;
        }
        return result[0];
    }

    /**
     * A snapshot of the operator's navigational UI state (every tab strip's
     * selection, every table's selected rows, every split's divider). Taken
     * BEFORE the capture navigates, restored AFTER — so a screenshot never leaves
     * a human's Burp on a different tab/row/layout than they had it (don't disrupt
     * someone using Burp with the mouse). Button CLICKS are real actions and are
     * NOT undone.
     */
    public static final class UiSnapshot {
        private final Map<JTabbedPane, Integer> tabs = new IdentityHashMap<>();
        private final Map<JTable, int[]> tableRows = new IdentityHashMap<>();
        private final Map<JSplitPane, Integer> splits = new IdentityHashMap<>();
    }

    public static UiSnapshot snapshotUi(Component root) {
        UiSnapshot s = new UiSnapshot();
        runOnEdt(() -> {
            List<JTabbedPane> tps = new ArrayList<>();
            collectTabbedPanes(root, tps);
            for (JTabbedPane tp : tps) {
                s.tabs.put(tp, tp.getSelectedIndex());
            }
            List<JTable> ts = new ArrayList<>();
            collectTables(root, ts);
            for (JTable t : ts) {
                s.tableRows.put(t, t.getSelectedRows());
            }
            List<JSplitPane> sps = new ArrayList<>();
            collectSplitPanes(root, sps);
            for (JSplitPane sp : sps) {
                s.splits.put(sp, sp.getDividerLocation());
            }
        });
        return s;
    }

    /** Restore a {@link #snapshotUi} — puts the operator's tab / row / layout back. */
    public static void restoreUi(UiSnapshot s) {
        if (s == null) {
            return;
        }
        runOnEdt(() -> {
            s.tabs.forEach((tp, i) -> {
                try {
                    if (i >= 0 && i < tp.getTabCount()) {
                        tp.setSelectedIndex(i);
                    }
                } catch (Exception ignored) {
                    // best-effort
                }
            });
            s.tableRows.forEach((t, rows) -> {
                try {
                    t.clearSelection();
                    for (int r : rows) {
                        if (r >= 0 && r < t.getRowCount()) {
                            t.addRowSelectionInterval(r, r);
                        }
                    }
                } catch (Exception ignored) {
                    // best-effort
                }
            });
            s.splits.forEach((sp, d) -> {
                try {
                    sp.setDividerLocation(d);
                } catch (Exception ignored) {
                    // best-effort
                }
            });
        });
    }

    /** The component of the currently-selected top-level tab, or the frame. */
    private static Component selectedTopComponent(Frame frame) {
        JTabbedPane main = findMainTabbedPane(frame);
        if (main != null) {
            int idx = main.getSelectedIndex();
            if (idx >= 0) {
                return main.getComponentAt(idx);
            }
        }
        return frame;
    }

    /**
     * Click a real Burp button (by exact label) in the currently-selected
     * top-level tab, on the EDT — so the action runs THROUGH the UI and its
     * result renders in the pane (an API call does not update the UI). Generic
     * over features: "Send" (Repeater), "Poll now" (Collaborator), "Start attack"
     * (Intruder), "Decode"/"Encode" (Decoder), etc. Returns true if an enabled
     * button with that label was found and clicked. Any async result arrives
     * after; the caller waits before capturing.
     */
    public static boolean clickButton(Frame frame, String label) {
        if (label == null || label.isBlank()) {
            return false;
        }
        String want = label.trim().toLowerCase();
        boolean[] clicked = {false};
        try {
            runOnEdt(() -> {
                // Search the selected tool's component first, then the whole frame
                // as a fallback (some controls live in a shared toolbar).
                AbstractButton btn = findButtonFuzzy(selectedTopComponent(frame), want);
                if (btn == null) {
                    btn = findButtonFuzzy(frame, want);
                }
                if (btn != null && btn.isEnabled()) {
                    btn.doClick();
                    clicked[0] = true;
                }
            });
        } catch (RuntimeException e) {
            return false;
        }
        return clicked[0];
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
        runOnEdt(() -> {
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
