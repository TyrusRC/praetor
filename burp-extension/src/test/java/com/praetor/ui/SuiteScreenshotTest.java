package com.praetor.ui;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
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

        assertSame(main, SuiteScreenshot.findMainTabbedPane(root));
    }

    @Test
    void selectTabBringsNamedTopLevelTabToFront() {
        JPanel root = new JPanel();
        JTabbedPane main = burpLikeStrip();
        root.add(main);
        // The tabs the operator called out explicitly, plus a couple more.
        for (String name : new String[]{"logger", "organizer", "collaborator",
                "comparer", "decoder", "repeater", "proxy"}) {
            String sel = SuiteScreenshot.selectTabIn(root, name);
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
        String co = SuiteScreenshot.selectTabIn(root, "co");
        assertNotEquals("Decoder", co);
        assertTrue(co.toLowerCase().startsWith("co"));
        // Exact title wins over any partial match.
        assertEquals("Decoder", SuiteScreenshot.selectTabIn(root, "decoder"));
        assertEquals("Comparer", SuiteScreenshot.selectTabIn(root, "comparer"));
    }

    @Test
    void effectiveScaleRejectsNonFinite() {
        // ?scale=NaN / Infinity must not produce a 1x1 degenerate or NaN scale.
        assertEquals(1.0, SuiteScreenshot.effectiveScale(1000, 700, Double.NaN, 2560), 0.01);
        assertEquals(1.0, SuiteScreenshot.effectiveScale(1000, 700,
                     Double.POSITIVE_INFINITY, 2560), 0.01);
    }

    @Test
    void selectTabReturnsNullForUnknownNameOrBlank() {
        JPanel root = new JPanel();
        root.add(burpLikeStrip());
        assertNull(SuiteScreenshot.selectTabIn(root, "no-such-tab"));
        assertNull(SuiteScreenshot.selectTabIn(root, ""));
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
}
