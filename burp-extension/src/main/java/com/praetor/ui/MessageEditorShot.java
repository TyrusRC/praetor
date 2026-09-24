package com.praetor.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.JFrame;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.image.BufferedImage;

/**
 * Screenshot a single request/response, auto-scrolled to and highlighting a
 * keyword — for evidence when the message is too long to fit one viewport.
 *
 * <p>Renders the message in OUR OWN read-only Burp editor (Montoya {@code
 * createHttpRequestEditor}/{@code createHttpResponseEditor}), applies the editor's
 * NATIVE search ({@link burp.api.montoya.ui.editor.Editor#setSearchExpression})
 * — which highlights every match and scrolls the first into view exactly like
 * typing into Burp's search box — then {@link SuiteScreenshot#captureComponent}
 * paints it at a fixed viewport. Because it is our own editor instance, the
 * operator's live Burp UI is never touched.
 *
 * <p>The editor's scroll pane only lays out (and only scrolls to a match) once
 * its component is realised, so the component is parented to a tiny undecorated
 * off-screen {@link JFrame} for the duration of the capture, then disposed.
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
     * Render {@code req} or {@code resp} (per {@code isResponse}) in a read-only
     * editor, apply {@code searchExpr} (blank = none), and return the PNG-ready
     * capture at {@code scale}×. The editor is hosted off-screen and disposed
     * before returning.
     */
    public static BufferedImage capture(MontoyaApi api, boolean isResponse,
                                        HttpRequest req, HttpResponse resp,
                                        String searchExpr, int width, int height,
                                        double scale) {
        // [0] = the editor Component to paint, [1] = its off-screen host JFrame.
        Object[] holder = {null, null};
        SwingUi.runOnEdt(() -> {
            Component comp;
            if (isResponse) {
                HttpResponseEditor ed =
                    api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
                ed.setResponse(resp != null ? resp : HttpResponse.httpResponse(""));
                comp = ed.uiComponent();
                JFrame host = hostOffscreen(comp, width, height);
                applySearch(ed::setSearchExpression, searchExpr);
                host.validate();
                holder[0] = comp;
                holder[1] = host;
            } else {
                HttpRequestEditor ed =
                    api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
                ed.setRequest(req != null ? req : HttpRequest.httpRequest(""));
                comp = ed.uiComponent();
                JFrame host = hostOffscreen(comp, width, height);
                applySearch(ed::setSearchExpression, searchExpr);
                host.validate();
                holder[0] = comp;
                holder[1] = host;
            }
        });
        // Let the native search's scroll/highlight settle on the EDT before the
        // paint — setSearchExpression queues a revalidate that must run first, or
        // printAll captures the pre-scroll (top-of-message) view.
        sleepQuietly(300);
        BufferedImage img = SuiteScreenshot.captureComponent(
            (Component) holder[0], width, height, scale);
        SwingUi.runOnEdt(() -> {
            if (holder[1] != null) {
                ((JFrame) holder[1]).dispose();
            }
        });
        return img;
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
