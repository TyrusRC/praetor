package com.praetor.handlers;

import org.junit.jupiter.api.Test;

import static com.praetor.handlers.ScannerHandler.issueMatches;
import static com.praetor.handlers.ScannerHandler.tryGet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Calibration for the scanner-findings host filter (added because Burp's
 * issues() are project-wide — one target's findings were buried among every
 * other scanned host) and the tryGet isolation helper (added because some Burp
 * builds throw "Currently unsupported" on individual Audit calls).
 */
class ScannerFindingsFilterTest {

    private static final String URL = "https://lab-abc.web-security-academy.net/product/stock";

    @Test
    void emptyFiltersMatchEverything() {
        assertTrue(issueMatches("", "", "", "High", "Certain", URL));
    }

    @Test
    void hostFilterIsSubstringOfBaseUrl() {
        assertTrue(issueMatches("", "", "lab-abc.web-security-academy.net", "High", "Certain", URL));
        assertFalse(issueMatches("", "", "other-host.net", "High", "Certain", URL));
    }

    @Test
    void nullBaseUrlNeverMatchesNonEmptyHost() {
        assertFalse(issueMatches("", "", "lab-abc", "High", "Certain", null));
        // ...but an empty host filter still matches a null base URL.
        assertTrue(issueMatches("", "", "", "High", "Certain", null));
    }

    @Test
    void severityAndConfidenceAreCaseInsensitive() {
        assertTrue(issueMatches("HIGH", "CERTAIN", "", "High", "Certain", URL));
        assertFalse(issueMatches("HIGH", "", "", "Low", "Certain", URL));
        assertFalse(issueMatches("", "FIRM", "", "High", "Certain", URL));
    }

    @Test
    void allThreeFiltersMustHold() {
        assertTrue(issueMatches("HIGH", "CERTAIN", "lab-abc", "High", "Certain", URL));
        assertFalse(issueMatches("HIGH", "CERTAIN", "wrong-host", "High", "Certain", URL));
    }

    @Test
    void tryGetReturnsValueOrNullOnThrow() {
        assertEquals(42, tryGet(() -> 42));
        assertNull(tryGet(() -> { throw new RuntimeException("Currently unsupported."); }));
    }
}
