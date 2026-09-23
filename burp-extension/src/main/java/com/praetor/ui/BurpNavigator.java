package com.praetor.ui;

import javax.swing.AbstractButton;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import java.awt.Component;
import java.awt.Frame;
import java.awt.Rectangle;
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Drives and reads Burp's own Swing UI: brings a named top-level tab (and nested
 * sub-tab) to front, selects a row in the tool's main table so its request/response
 * detail renders, clicks a real Burp button, and snapshots/restores the operator's
 * view so a capture never leaves their Burp on a different tab. Montoya exposes no
 * such API, so this walks the Swing tree via {@link SwingUi} — a bounded, tested
 * best-effort that degrades gracefully (unknown name -> current tab).
 */
public final class BurpNavigator {

    private BurpNavigator() {}

    // Top-level Burp tab titles — used to identify the MAIN tab strip among the
    // several JTabbedPanes in the frame (sub-tabs like Proxy>HTTP-history score 0).
    private static final Set<String> TOP_LEVEL_TABS = Set.of(
        "dashboard", "target", "proxy", "intruder", "repeater", "collaborator",
        "sequencer", "decoder", "comparer", "logger", "organizer", "extensions",
        "learn");

    /** The main Burp tab strip: the JTabbedPane whose tab titles include the most
     *  known top-level names. Null if none looks like the Burp strip. */
    static JTabbedPane findMainTabbedPane(Component root) {
        List<JTabbedPane> panes = new ArrayList<>();
        SwingUi.collectTabbedPanes(root, panes);
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
        SwingUi.collectTabbedPanes(root, panes);
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
            SwingUi.runOnEdt(() -> {
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

    /**
     * Top-level tab titles actually present in Burp's main tab strip right now —
     * a diagnostic so a caller can tell a mismatched {@code tab} name apart from
     * a tab the operator has HIDDEN (right-click the tab bar -> Hide). Montoya
     * has no API to detect or un-hide a hidden tool tab, so a hidden tab simply
     * never appears in this list and {@link #selectTab} can never select it —
     * this surfaces that situation instead of silently screenshotting/selecting
     * whatever tab happened to be in front. Empty list if no tab strip found.
     */
    public static List<String> listTopLevelTabs(Frame frame) {
        return listTopLevelTabsIn(frame);
    }

    /** Core of {@link #listTopLevelTabs} over any component root — testable
     *  without a heavyweight Frame, same pattern as {@link #selectTabIn}. */
    static List<String> listTopLevelTabsIn(Component root) {
        List<String> out = new ArrayList<>();
        try {
            SwingUi.runOnEdt(() -> {
                JTabbedPane main = findMainTabbedPane(root);
                if (main == null) {
                    return;
                }
                for (int i = 0; i < main.getTabCount(); i++) {
                    String t = main.getTitleAt(i);
                    if (t != null && !t.isBlank()) {
                        out.add(t);
                    }
                }
            });
        } catch (RuntimeException e) {
            // diagnostic only
        }
        return out;
    }

    /** Enabled-button labels under the currently-selected top tab — a diagnostic
     *  so a caller can see what's clickable (Burp's custom UI may not expose a
     *  given control as a standard AbstractButton). */
    public static List<String> listButtons(Frame frame) {
        List<String> out = new ArrayList<>();
        try {
            SwingUi.runOnEdt(() -> {
                Component scope = selectedTopComponent(frame);
                List<AbstractButton> all = new ArrayList<>();
                SwingUi.collectButtons(scope, all);
                for (AbstractButton b : all) {
                    String label = SwingUi.buttonLabel(b);   // text, else tooltip/accessible-name
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

    /**
     * If the table/detail VERTICAL split (table on top, request/response below)
     * is collapsed to a table-only view, open it to ~55% so a selected row's
     * request/response detail is visible. Best-effort, on the EDT.
     */
    static void ensureDetailPaneVisible(Component root) {
        List<JSplitPane> splits = new ArrayList<>();
        SwingUi.collectSplitPanes(root, splits);
        for (JSplitPane sp : splits) {
            if (sp.getOrientation() != JSplitPane.VERTICAL_SPLIT || !sp.isShowing()) {
                continue;   // ignore splits in off-screen sub-tabs (see findLargestTable)
            }
            Component top = sp.getTopComponent();
            if (top == null || !SwingUi.containsTable(top)) {
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

    /** View-row where EVERY whitespace-separated token of {@code needle} appears
     *  in some column (case-insensitive AND); the LAST (newest) such row, or -1 if
     *  none / empty table / blank needle.
     *
     *  <p>This is the translator the numeric {@link #rowForNumber} can't be: a
     *  Praetor evidence index (proxy-history list ordinal, {@code proxy_history_index})
     *  is NOT the value Burp prints in the "#" column, so a caller that only has
     *  an evidence index cannot address the right row by number. Matching on the
     *  request text Burp actually shows (host / method / URL columns) sidesteps
     *  both numbering spaces — the programmatic equivalent of typing into Burp's
     *  search box. A single token is a plain substring match; multiple tokens
     *  (e.g. "host /path") AND across columns, so a caller can disambiguate a
     *  path that repeats across hosts or a bare "/" root. Last match wins so a
     *  repeated request lands on the newest. */
    static int rowForText(JTable table, String needle) {
        if (table.getRowCount() == 0 || needle == null || needle.isBlank()) {
            return -1;
        }
        String[] tokens = needle.trim().toLowerCase(Locale.ROOT).split("\\s+");
        int hit = -1;
        for (int r = 0; r < table.getRowCount(); r++) {
            if (rowHasAllTokens(table, r, tokens)) {
                hit = r;   // keep scanning: last (newest) match wins
            }
        }
        return hit;
    }

    /** True when every token appears in at least one column of view-row {@code r}. */
    private static boolean rowHasAllTokens(JTable table, int r, String[] tokens) {
        for (String tok : tokens) {
            boolean found = false;
            for (int c = 0; c < table.getColumnCount(); c++) {
                Object v = table.getValueAt(r, c);
                if (v != null && v.toString().toLowerCase(Locale.ROOT).contains(tok)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }

    /** The JTable with the most rows under {@code root} — the history/results
     *  table rather than a small side table. Null if none.
     *
     *  <p>Prefers tables that are actually SHOWING on screen: a tool panel keeps
     *  every sub-tab's component instantiated (Proxy holds HTTP-history,
     *  WebSockets-history and Match-and-replace tables at once), so an off-screen
     *  sub-tab's larger table would otherwise win and the row select would land on
     *  a table the operator can't see. Only if no table is showing (headless /
     *  odd layout) does it fall back to the largest overall. */
    static JTable findLargestTable(Component root) {
        List<JTable> tables = new ArrayList<>();
        SwingUi.collectTables(root, tables);
        JTable best = null, bestShowing = null;
        for (JTable t : tables) {
            if (best == null || t.getRowCount() > best.getRowCount()) {
                best = t;
            }
            if (t.isShowing()
                    && (bestShowing == null || t.getRowCount() > bestShowing.getRowCount())) {
                bestShowing = t;
            }
        }
        return bestShowing != null ? bestShowing : best;
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
            SwingUi.runOnEdt(() -> {
                JTable table = findLargestTable(selectedTopComponent(frame));
                if (table == null || table.getRowCount() == 0) {
                    return;
                }
                int viewRow = rowForNumber(table, wantNumber);
                // The selected row's request/response detail lives in a bottom
                // split-pane that is often collapsed (table-only view) — open it
                // FIRST so the editors are laid out, then drive the row so Burp
                // loads its request/response into them.
                ensureDetailPaneVisible(selectedTopComponent(frame));
                result[0] = driveRowSelection(table, viewRow);
            });
        } catch (RuntimeException e) {
            return -1;
        }
        return result[0];
    }

    /**
     * Select the row whose text matches {@code needle} in the selected tab's main
     * table (Proxy HTTP history, Logger, ...) and load its request/response into
     * the editors — the programmatic equivalent of typing {@code needle} into
     * Burp's search box. Use this to reach a SPECIFIC request the caller can only
     * identify by URL/host/method (e.g. a browser-origin OAuth callback), since a
     * Praetor evidence index is not Burp's "#" column value. Returns the selected
     * 0-based view row, or -1 if no table / no match.
     */
    public static int selectRowByText(Frame frame, String needle) {
        int[] result = {-1};
        try {
            SwingUi.runOnEdt(() -> {
                Component top = selectedTopComponent(frame);
                JTable table = findLargestTable(top);
                if (table == null || table.getRowCount() == 0) {
                    return;
                }
                int viewRow = rowForText(table, needle);
                if (viewRow < 0) {
                    return;   // no match -> leave the operator's selection alone
                }
                ensureDetailPaneVisible(top);
                result[0] = driveRowSelection(table, viewRow);
            });
        } catch (RuntimeException e) {
            return -1;
        }
        return result[0];
    }

    /**
     * Select {@code viewRow} in {@code table} AND load the row into the tool's
     * request/response editors, scrolling it into view. Returns {@code viewRow}.
     *
     * <p>Burp fills those editors from a MOUSE-driven selection handler, not a
     * plain {@code ListSelectionListener}, so a bare
     * {@link JTable#setRowSelectionInterval} moves the highlight but leaves the
     * editors showing the previously mouse-clicked row — the "highlight moves,
     * detail stays" bug. Dispatching a synthetic left-click on the row's own cell
     * fires that handler through the normal path. Coordinates are component-local
     * ({@link JTable#getCellRect}), so this needs no Retina/HiDPI conversion and
     * behaves identically on macOS, Linux and Windows (unlike {@code java.awt.Robot},
     * which uses screen coordinates). Must run on the EDT.
     */
    static int driveRowSelection(JTable table, int viewRow) {
        table.setRowSelectionInterval(viewRow, viewRow);
        Rectangle cell = table.getCellRect(viewRow, 0, true);
        table.scrollRectToVisible(cell);
        int px = cell.x + Math.min(Math.max(cell.width / 2, 1), 12);
        int py = cell.y + cell.height / 2;
        long when = System.currentTimeMillis();
        table.dispatchEvent(new MouseEvent(table, MouseEvent.MOUSE_PRESSED, when,
                InputEvent.BUTTON1_DOWN_MASK, px, py, 1, false, MouseEvent.BUTTON1));
        table.dispatchEvent(new MouseEvent(table, MouseEvent.MOUSE_RELEASED, when,
                0, px, py, 1, false, MouseEvent.BUTTON1));
        table.dispatchEvent(new MouseEvent(table, MouseEvent.MOUSE_CLICKED, when,
                0, px, py, 1, false, MouseEvent.BUTTON1));
        return viewRow;
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
        SwingUi.runOnEdt(() -> {
            List<JTabbedPane> tps = new ArrayList<>();
            SwingUi.collectTabbedPanes(root, tps);
            for (JTabbedPane tp : tps) {
                s.tabs.put(tp, tp.getSelectedIndex());
            }
            List<JTable> ts = new ArrayList<>();
            SwingUi.collectTables(root, ts);
            for (JTable t : ts) {
                s.tableRows.put(t, t.getSelectedRows());
            }
            List<JSplitPane> sps = new ArrayList<>();
            SwingUi.collectSplitPanes(root, sps);
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
        SwingUi.runOnEdt(() -> {
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
    static Component selectedTopComponent(Frame frame) {
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
            SwingUi.runOnEdt(() -> {
                // Search the selected tool's component first, then the whole frame
                // as a fallback (some controls live in a shared toolbar).
                AbstractButton btn = SwingUi.findButtonFuzzy(selectedTopComponent(frame), want);
                if (btn == null) {
                    btn = SwingUi.findButtonFuzzy(frame, want);
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
}
