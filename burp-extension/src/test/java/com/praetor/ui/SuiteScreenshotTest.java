package com.praetor.ui;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.util.Base64;

class SuiteScreenshotTest {

    /** A JTabbedPane that looks like Burp's main strip, wrapped so the finder has
     *  to walk into it (mirrors the real nested layout). */
    private static JTabbedPane burpLikeStrip() {
        JTabbedPane tp = new JTabbedPane();
        for (String t : new String[]{"Dashboard", "Target", "Proxy", "Intruder",
                "Repeater", "Collaborator", "Decoder", "Comparer", "Logger",
                "Organizer", "Extensions"}) {
            tp.addTab(t, new JLabel(t));
        }
        return tp;
    }

    @Test
    void findMainTabbedPaneIgnoresUnrelatedTabStrips() {
        JPanel root = new JPanel();
        JTabbedPane subTabs = new JTabbedPane();     // e.g. Proxy sub-tabs — must NOT win
        subTabs.addTab("HTTP history", new JLabel());
        subTabs.addTab("WebSockets history", new JLabel());
        root.add(subTabs);
        JTabbedPane main = burpLikeStrip();
        root.add(main);

        assertSame(main, BurpNavigator.findMainTabbedPane(root));
    }

    @Test
    void selectTabBringsNamedTopLevelTabToFront() {
        JPanel root = new JPanel();
        JTabbedPane main = burpLikeStrip();
        root.add(main);
        // The tabs the operator called out explicitly, plus a couple more.
        for (String name : new String[]{"logger", "organizer", "collaborator",
                "comparer", "decoder", "repeater", "proxy"}) {
            String sel = BurpNavigator.selectTabIn(root, name);
            assertNotNull(sel, name + " should match a top-level tab");
            assertEquals(name, sel.toLowerCase());
            assertEquals(name, main.getTitleAt(main.getSelectedIndex()).toLowerCase());
        }
    }

    @Test
    void selectTabPrefersExactAndPrefixOverSubstring() {
        JTabbedPane tp = new JTabbedPane();
        for (String t : new String[]{"Dashboard", "Proxy", "Decoder", "Comparer",
                "Collaborator", "Logger"}) {
            tp.addTab(t, new JLabel(t));
        }
        JPanel root = new JPanel();
        root.add(tp);
        // "co": Decoder CONTAINS it (earlier index) but Comparer/Collaborator
        // START with it -> a prefix beats a substring, so NOT Decoder.
        String co = BurpNavigator.selectTabIn(root, "co");
        assertNotEquals("Decoder", co);
        assertTrue(co.toLowerCase().startsWith("co"));
        // Exact title wins over any partial match.
        assertEquals("Decoder", BurpNavigator.selectTabIn(root, "decoder"));
        assertEquals("Comparer", BurpNavigator.selectTabIn(root, "comparer"));
    }

    @Test
    void effectiveScaleRejectsNonFinite() {
        // ?scale=NaN / Infinity must not produce a 1x1 degenerate or NaN scale.
        assertEquals(1.0, SuiteScreenshot.effectiveScale(1000, 700, Double.NaN, 2560), 0.01);
        assertEquals(1.0, SuiteScreenshot.effectiveScale(1000, 700,
                     Double.POSITIVE_INFINITY, 2560), 0.01);
    }

    @Test
    void selectsNestedSubTabWithinAToolTab() {
        JTabbedPane sub = new JTabbedPane();
        sub.addTab("Intercept", new JLabel());
        sub.addTab("HTTP history", new JLabel());
        sub.addTab("WebSockets history", new JLabel());
        JPanel proxyTool = new JPanel();
        proxyTool.add(sub);
        JTabbedPane main = new JTabbedPane();
        main.addTab("Dashboard", new JLabel());
        main.addTab("Proxy", proxyTool);          // Proxy's content holds the sub-strip
        main.addTab("Logger", new JLabel());
        JPanel root = new JPanel();
        root.add(main);

        String[] r = BurpNavigator.selectTabAndSubIn(root, "proxy", "http history");
        assertEquals("Proxy", r[0]);
        assertEquals("HTTP history", r[1]);
        assertEquals("Proxy", main.getTitleAt(main.getSelectedIndex()));
        assertEquals("HTTP history", sub.getTitleAt(sub.getSelectedIndex()));
    }

    @Test
    void unmatchedSubTabStillSelectsTheTopTab() {
        JTabbedPane sub = new JTabbedPane();
        sub.addTab("Intercept", new JLabel());
        sub.addTab("HTTP history", new JLabel());
        JPanel proxyTool = new JPanel();
        proxyTool.add(sub);
        JTabbedPane main = new JTabbedPane();
        main.addTab("Proxy", proxyTool);
        main.addTab("Logger", new JLabel());
        JPanel root = new JPanel();
        root.add(main);

        String[] r = BurpNavigator.selectTabAndSubIn(root, "proxy", "no-such-subtab");
        assertEquals("Proxy", r[0]);
        assertNull(r[1]);   // sub-tab not found -> top tab still selected
    }

    @Test
    void selectTabReturnsNullForUnknownNameOrBlank() {
        JPanel root = new JPanel();
        root.add(burpLikeStrip());
        assertNull(BurpNavigator.selectTabIn(root, "no-such-tab"));
        assertNull(BurpNavigator.selectTabIn(root, ""));
    }

    /** available_tabs (ScreenshotHandler) must reflect the REAL tab strip, so a
     *  caller can tell "operator hid this tab" apart from "I misspelled it". */
    @Test
    void listTopLevelTabsReturnsEveryTabInTheMainStrip() {
        JPanel root = new JPanel();
        JTabbedPane main = burpLikeStrip();
        root.add(main);

        java.util.List<String> tabs = BurpNavigator.listTopLevelTabsIn(root);

        assertEquals(11, tabs.size());
        assertTrue(tabs.contains("Logger"));
        assertTrue(tabs.contains("Proxy"));
    }

    /** A tab the operator right-click-Hides in Burp never appears in the
     *  JTabbedPane at all — Montoya has no API to see or undo that — so a
     *  "hidden" tab is simply absent here, same as it would be live. */
    @Test
    void listTopLevelTabsOmitsAHiddenTab() {
        JTabbedPane main = new JTabbedPane();
        main.addTab("Dashboard", new JLabel());
        main.addTab("Proxy", new JLabel());
        main.addTab("Repeater", new JLabel());
        // "Logger" intentionally not added -> simulates the operator hiding it.
        JPanel root = new JPanel();
        root.add(main);

        java.util.List<String> tabs = BurpNavigator.listTopLevelTabsIn(root);

        assertFalse(tabs.contains("Logger"));
        assertEquals(java.util.List.of("Dashboard", "Proxy", "Repeater"), tabs);
    }

    @Test
    void listTopLevelTabsEmptyWhenNoTabStripFound() {
        assertTrue(BurpNavigator.listTopLevelTabsIn(new JPanel()).isEmpty());
    }

    @Test
    void captureComponentRendersTheComponentNotAScreenRegion() {
        // printAll paints the component's own pixels — proving the capture is the
        // Swing hierarchy (occlusion-immune), not a Robot grab of the screen.
        JPanel panel = new JPanel();
        panel.setOpaque(true);
        panel.setBackground(Color.RED);
        panel.setSize(8, 8);

        BufferedImage img = SuiteScreenshot.captureComponent(panel, 8, 8);
        assertEquals(8, img.getWidth());
        assertEquals(8, img.getHeight());
        assertEquals(new Color(Color.RED.getRGB()).getRGB(), img.getRGB(4, 4),
            "center pixel should be the panel's own background");
    }

    @Test
    void effectiveScaleHonoursRequestButCapsAt2K() {
        // small window, 2x requested, fits under 2560 (1000*2=2000) -> 2x honoured
        assertEquals(2.0, SuiteScreenshot.effectiveScale(1000, 700, 2.0, 2560), 0.01);
        // 2x would exceed 2560 on the long side -> capped so long side == 2560
        double s = SuiteScreenshot.effectiveScale(1600, 900, 2.0, 2560);
        assertEquals(2560.0 / 1600.0, s, 0.01);
        assertTrue(1600 * s <= 2560.5);
        // the real Burp window (1291 wide) at 2x -> capped just under 2x
        assertEquals(2560.0 / 1291.0, SuiteScreenshot.effectiveScale(1291, 699, 2.0, 2560), 0.01);
        // never downscale below 1x, even for a window already wider than the cap
        assertEquals(1.0, SuiteScreenshot.effectiveScale(3000, 1600, 2.0, 2560), 0.01);
        // requested scale clamped to 4x max
        assertEquals(2560.0 / 800.0, SuiteScreenshot.effectiveScale(800, 600, 9.0, 2560), 0.01);
    }

    @Test
    void addFooterExtendsCanvasBelowAndPreservesContent() {
        BufferedImage src = new BufferedImage(20, 10, BufferedImage.TYPE_INT_RGB);
        for (int x = 0; x < 20; x++) {
            for (int y = 0; y < 10; y++) {
                src.setRGB(x, y, 0x0000FF);   // solid blue
            }
        }
        BufferedImage out = SuiteScreenshot.addFooter(src, "Step 1", "ACME Security", 1.0);

        assertEquals(20, out.getWidth(), "width unchanged");
        assertTrue(out.getHeight() > src.getHeight(), "footer appended below");
        // Every original pixel is preserved (nothing overlaid/hidden).
        assertEquals(0x0000FF, out.getRGB(5, 5) & 0xFFFFFF);
        assertEquals(0x0000FF, out.getRGB(19, 9) & 0xFFFFFF);
        // The footer strip lives strictly below the original image.
        assertNotEquals(0x0000FF, out.getRGB(5, src.getHeight() + 2) & 0xFFFFFF);
    }

    @Test
    void findButtonLocatesSendAndDoClickFires() {
        JButton send = new JButton("Send");
        int[] clicks = {0};
        send.addActionListener(e -> clicks[0]++);
        JPanel toolbar = new JPanel();
        toolbar.add(new JButton("Cancel"));
        toolbar.add(send);
        JPanel root = new JPanel();
        root.add(toolbar);

        AbstractButton found = SwingUi.findButton(root, "Send");
        assertSame(send, found);
        assertNull(SwingUi.findButton(root, "no-such-button"));
        // clickSendButton's core: doClick() actually fires the action.
        found.doClick();
        assertEquals(1, clicks[0]);
    }

    @Test
    void tableRowFinderMatchesNumberOrLast() {
        javax.swing.table.DefaultTableModel model =
            new javax.swing.table.DefaultTableModel(new Object[]{"#", "URL"}, 0);
        model.addRow(new Object[]{"1", "/a"});
        model.addRow(new Object[]{"2", "/b"});
        model.addRow(new Object[]{"15", "/sqli"});
        javax.swing.JTable table = new javax.swing.JTable(model);
        // findLargestTable locates it under a container
        JPanel root = new JPanel();
        root.add(table);
        assertSame(table, BurpNavigator.findLargestTable(root));
        // by "#" number
        assertEquals(2, BurpNavigator.rowForNumber(table, 15));
        assertEquals(0, BurpNavigator.rowForNumber(table, 1));
        // last row for <0 or no match
        assertEquals(2, BurpNavigator.rowForNumber(table, -1));
        assertEquals(2, BurpNavigator.rowForNumber(table, 999));
    }

    @Test
    void snapshotRestorePutsTabAndRowBack() {
        JTabbedPane tp = new JTabbedPane();
        tp.addTab("A", new JLabel());
        tp.addTab("B", new JLabel());
        tp.addTab("C", new JLabel());
        tp.setSelectedIndex(1);                         // operator on tab B
        javax.swing.table.DefaultTableModel model =
            new javax.swing.table.DefaultTableModel(new Object[]{"#"}, 0);
        model.addRow(new Object[]{"1"});
        model.addRow(new Object[]{"2"});
        model.addRow(new Object[]{"3"});
        javax.swing.JTable table = new javax.swing.JTable(model);
        table.setRowSelectionInterval(0, 0);            // operator had row 0 selected
        JPanel root = new JPanel();
        root.add(tp);
        root.add(table);

        BurpNavigator.UiSnapshot snap = BurpNavigator.snapshotUi(root);
        // simulate the capture navigating away
        tp.setSelectedIndex(2);
        table.setRowSelectionInterval(2, 2);
        // restore puts the operator's view back
        BurpNavigator.restoreUi(snap);
        assertEquals(1, tp.getSelectedIndex());
        assertEquals(0, table.getSelectedRow());
    }

    @Test
    void applyRedactionsBlacksOutOnlyTheBox() {
        BufferedImage src = new BufferedImage(20, 20, BufferedImage.TYPE_INT_RGB);
        for (int x = 0; x < 20; x++) {
            for (int y = 0; y < 20; y++) {
                src.setRGB(x, y, 0xFFFFFF);   // white
            }
        }
        BufferedImage out = ScreenshotRedactor.applyRedactions(src, java.util.List.of(new int[]{5, 5, 6, 6}));
        assertTrue((out.getRGB(7, 7) & 0xFFFFFF) < 0x303030, "inside the box must be dark");
        assertEquals(0xFFFFFF, out.getRGB(0, 0) & 0xFFFFFF, "outside unchanged");
        assertEquals(0xFFFFFF, out.getRGB(19, 19) & 0xFFFFFF, "outside unchanged");
        // out-of-bounds box is clamped, no crash
        assertNotNull(ScreenshotRedactor.applyRedactions(src, java.util.List.of(new int[]{15, 15, 999, 999})));
    }

    @Test
    void pixelStyleMosaicsInsideBoxAndLeavesOutsideUntouched() {
        // half black / half white checkerboard inside the box -> a coarse mosaic
        // averages neighbouring cells to grey, so the exact pattern can't be read back.
        BufferedImage src = new BufferedImage(40, 20, BufferedImage.TYPE_INT_RGB);
        for (int x = 0; x < 40; x++) {
            for (int y = 0; y < 20; y++) {
                src.setRGB(x, y, ((x + y) % 2 == 0) ? 0x000000 : 0xFFFFFF);
            }
        }
        BufferedImage out = ScreenshotRedactor.applyRedactions(
            src, java.util.List.of(new int[]{4, 2, 20, 16}), "pixel");
        int c = out.getRGB(12, 8) & 0xFF;              // a blue channel inside the box
        assertTrue(c > 0x20 && c < 0xE0, "inside must be an averaged mid-tone, not pure b/w");
        assertEquals(src.getRGB(0, 0), out.getRGB(0, 0), "outside the box unchanged");
        assertEquals(src.getRGB(39, 19), out.getRGB(39, 19), "outside the box unchanged");
    }

    @Test
    void pngBase64EncodesADecodablePng() throws Exception {
        BufferedImage img = new BufferedImage(3, 2, BufferedImage.TYPE_INT_RGB);
        img.setRGB(0, 0, 0xFF0000);
        img.setRGB(2, 1, 0x00FF00);

        String b64 = SuiteScreenshot.pngBase64(img);
        assertFalse(b64.isEmpty());

        byte[] raw = Base64.getDecoder().decode(b64);
        // PNG magic number: 0x89 'P' 'N' 'G'.
        assertEquals((byte) 0x89, raw[0]);
        assertEquals('P', raw[1]);
        assertEquals('N', raw[2]);
        assertEquals('G', raw[3]);

        BufferedImage back = ImageIO.read(new ByteArrayInputStream(raw));
        assertNotNull(back);
        assertEquals(3, back.getWidth());
        assertEquals(2, back.getHeight());
    }

    /** driveRowSelection must both SELECT the row and dispatch a real mouse click
     *  on it — Burp loads the row's request/response from a mouse handler, so a
     *  bare setRowSelectionInterval (highlight only) leaves the editors stale. */
    @Test
    void driveRowSelectionSelectsAndFiresMouseClick() {
        javax.swing.table.DefaultTableModel model =
            new javax.swing.table.DefaultTableModel(new Object[]{"#", "URL"}, 0);
        model.addRow(new Object[]{"1", "/a"});
        model.addRow(new Object[]{"2", "/b"});
        model.addRow(new Object[]{"3", "/c"});
        javax.swing.JTable table = new javax.swing.JTable(model);
        table.setSize(200, 60);       // give cells a non-zero rect
        table.doLayout();

        int[] clickedRow = {-1};
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                clickedRow[0] = table.rowAtPoint(e.getPoint());
            }
        });

        int r = BurpNavigator.driveRowSelection(table, 2);

        assertEquals(2, r);
        assertEquals(2, table.getSelectedRow());        // highlight moved
        assertEquals(2, clickedRow[0]);                 // AND a real click fired on that row
    }
}
