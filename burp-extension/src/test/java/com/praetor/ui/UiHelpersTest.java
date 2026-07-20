package com.praetor.ui;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class UiHelpersTest {

    @Test
    void literalNewlineEscapesBecomeRealNewlines() {
        // Content that arrived JSON double-encoded carries the two chars \ n.
        String in = "line one\\nline two\\ttabbed";
        String out = UiHelpers.toReadableText(in, false);
        assertEquals("line one\nline two\ttabbed", out);
    }

    @Test
    void descriptionStripsHtmlTagsAndRendersBreaks() {
        String in = "<html><b>SQL injection</b><br>in login form</html>";
        String out = UiHelpers.toReadableText(in, true);
        // <html>/<br> -> newlines, <b> stripped, no raw tags remain.
        assertFalse(out.contains("<"), "no raw tags should remain: " + out);
        assertTrue(out.contains("SQL injection"));
        assertTrue(out.contains("in login form"));
        assertTrue(out.contains("\n"), "break tags should produce a newline: " + out);
    }

    @Test
    void evidenceKeepsPayloadTagsByteFaithful() {
        // The whole point of evidence: an XSS payload must stay visible.
        String in = "reflected: <script>alert(1)</script>";
        String out = UiHelpers.toReadableText(in, false);
        assertTrue(out.contains("<script>alert(1)</script>"),
            "evidence must preserve payload markup: " + out);
    }

    @Test
    void descriptionUnescapesEntities() {
        String out = UiHelpers.toReadableText("price &lt; 100 &amp;&amp; qty &gt; 0", true);
        assertEquals("price < 100 && qty > 0", out);
    }

    @Test
    void nullAndEmptyAreSafe() {
        assertEquals("", UiHelpers.toReadableText(null, true));
        assertEquals("", UiHelpers.toReadableText("", false));
    }
}
