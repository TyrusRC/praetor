package com.praetor.ui;

import javax.swing.AbstractButton;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;
import java.util.ArrayList;
import java.util.List;

/**
 * Generic Swing tree helpers — walking a component hierarchy, matching buttons,
 * and running work on the EDT. Nothing here is Burp-specific; the Burp-aware
 * navigation (tab strip, HTTP-history table, ...) lives in {@link BurpNavigator}.
 */
final class SwingUi {

    private SwingUi() {}

    /** True when a display is available to render (false in headless Burp). */
    static boolean displayAvailable() {
        return !GraphicsEnvironment.isHeadless();
    }

    /**
     * Run on the EDT and PROPAGATE failures — a render that throws must surface
     * as an error, not a silent blank-but-valid PNG returned as success.
     */
    static void runOnEdt(Runnable r) {
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

    static void collectTabbedPanes(Component c, List<JTabbedPane> out) {
        if (c instanceof JTabbedPane tp) {
            out.add(tp);
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                collectTabbedPanes(child, out);
            }
        }
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
}
