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
