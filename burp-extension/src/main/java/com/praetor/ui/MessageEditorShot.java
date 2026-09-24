package com.praetor.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.JFrame;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.List;

/**
 * Screenshot a proxy-history entry — request AND response, on the Raw view,
 * auto-scrolled to and highlighting a keyword — for evidence when the message is
 * too long to fit one viewport.
 *
 * <p>Renders the message in OUR OWN read-only Burp editors (Montoya {@code
 * createHttpRequestEditor}/{@code createHttpResponseEditor}), switches each to its
 * <b>Raw</b> tab (the on-the-wire bytes a triager wants, not the reformatted
 * Pretty view), applies the editor's NATIVE search ({@link
 * burp.api.montoya.ui.editor.Editor#setSearchExpression} — highlights every match
 * and scrolls the first into view), then {@link SuiteScreenshot#captureComponent}
 * paints them stacked in one image. Request + response together mirror Burp's own
 * proxy-history detail. Because these are our own editor instances, the operator's
 * live Burp UI is never touched.
 *
 * <p>An editor's scroll pane only lays out (and only scrolls to a match) once
 * realised, so the pane(s) are parented to a tiny undecorated off-screen {@link
 * JFrame} for the capture, then disposed.
 */
public final class MessageEditorShot {

    private MessageEditorShot() {}

    public static boolean displayAvailable() {
        return SuiteScreenshot.displayAvailable();
    }

    /** Clamp a requested viewport dimension into a sane pixel range. */
    public static int clampDim(int requested, int lo, int hi) {
        if (requested < lo) return lo;
        return Math.min(requested, hi);
    }

    /**
     * Render the request and/or response (per {@code which}: "request",
     * "response", or "both"), each on its Raw tab, apply {@code searchExpr} (blank
     * = none), and return the PNG-ready capture at {@code scale}×. When both are
     * shown they are stacked request-over-response in a split pane. The off-screen
     * host is disposed before returning.
     */
    public static BufferedImage capture(MontoyaApi api, String which,
                                        HttpRequest req, HttpResponse resp,
                                        String searchExpr, int width, int height,
                                        double scale) {
        boolean wantReq = !"response".equalsIgnoreCase(which);
        boolean wantResp = !"request".equalsIgnoreCase(which);
        // [0] = the Component to paint (a pane or the split), [1] = its host JFrame.
        Object[] holder = {null, null};
        SwingUi.runOnEdt(() -> {
            List<Component> panes = new ArrayList<>();
            List<Runnable> setup = new ArrayList<>();   // select Raw + search, after realise

            if (wantReq) {
                HttpRequestEditor ed =
                    api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
                ed.setRequest(req != null ? req : HttpRequest.httpRequest(""));
                Component c = ed.uiComponent();
                panes.add(c);
                setup.add(() -> {
                    selectRawTab(c);
                    applySearch(ed::setSearchExpression, searchExpr);
                });
            }
            if (wantResp) {
                HttpResponseEditor ed =
                    api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
                ed.setResponse(resp != null ? resp : HttpResponse.httpResponse(""));
                Component c = ed.uiComponent();
                panes.add(c);
                setup.add(() -> {
                    selectRawTab(c);
                    applySearch(ed::setSearchExpression, searchExpr);
                });
            }

            Component root;
            if (panes.size() == 2) {
                JSplitPane split = new JSplitPane(
                    JSplitPane.VERTICAL_SPLIT, panes.get(0), panes.get(1));
                split.setResizeWeight(0.35);            // request smaller, response fills
                split.setDividerLocation((int) (height * 0.35));
                root = split;
            } else {
                root = panes.get(0);
            }

            JFrame host = hostOffscreen(root, width, height);
            for (Runnable r : setup) {
                r.run();
            }
            host.validate();
            holder[0] = root;
            holder[1] = host;
        });
        // Let the Raw-tab switch + native search scroll/highlight settle on the EDT
        // before the paint — they queue a revalidate that must run first, or
        // printAll captures the pre-scroll (top-of-message) view.
        sleepQuietly(350);
        BufferedImage img = SuiteScreenshot.captureComponent(
            (Component) holder[0], width, height, scale);
        SwingUi.runOnEdt(() -> {
            if (holder[1] != null) {
                ((JFrame) holder[1]).dispose();
            }
        });
        return img;
    }

    /** Select the editor's "Raw" tab (the wire bytes) instead of the default
     *  "Pretty" reformatted view — walks the editor component's own tab strip. */
    private static void selectRawTab(Component root) {
        List<JTabbedPane> tps = new ArrayList<>();
        SwingUi.collectTabbedPanes(root, tps);
        for (JTabbedPane tp : tps) {
            for (int i = 0; i < tp.getTabCount(); i++) {
                String t = tp.getTitleAt(i);
                if (t != null && t.trim().equalsIgnoreCase("Raw")) {
                    tp.setSelectedIndex(i);
                    return;
                }
            }
        }
    }

    /** Parent {@code comp} to a realised, off-screen, undecorated frame sized to
     *  the requested viewport, so the editor lays out and can scroll. */
    private static JFrame hostOffscreen(Component comp, int width, int height) {
        JFrame f = new JFrame();
        f.setUndecorated(true);
        f.setLocation(-20000, -20000);   // realised but never visible to the operator
        f.getContentPane().add(comp);
        f.getContentPane().setPreferredSize(new Dimension(width, height));
        f.pack();
        f.setVisible(true);
        comp.setSize(width, height);
        f.validate();
        return f;
    }

    private static void applySearch(java.util.function.Consumer<String> search, String expr) {
        if (expr != null && !expr.isBlank()) {
            search.accept(expr);
        }
    }

    /** Sleep {@code ms}, restoring the interrupt flag if interrupted. */
    static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
}
