package com.praetor.ui;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.util.Base64;

class SuiteScreenshotTest {

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
