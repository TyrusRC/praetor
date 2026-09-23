package com.praetor.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import static com.praetor.ui.BurpNavigator.rowForText;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The row-by-text matcher is the translator between a Praetor evidence index and
 * the Burp table row it can't address by number (proxy-history ordinal /
 * logger_index != Burp's "#" column). It matches on the request text Burp shows.
 */
class BurpNavigatorRowTextTest {

    /** Mimics Burp's Proxy HTTP-history columns: #, Host, Method, URL. */
    private static JTable history() {
        DefaultTableModel m = new DefaultTableModel(
                new Object[]{"#", "Host", "Method", "URL"}, 0);
        m.addRow(new Object[]{"1", "www.google.com", "GET", "/gtm.js"});
        m.addRow(new Object[]{"2", "accounts.example.com", "GET", "/oidc/callback"});
        m.addRow(new Object[]{"3", "optimizationguide-pa.googleapis.com", "POST", "/v1/hint"});
        m.addRow(new Object[]{"4", "accounts.example.com", "GET", "/oidc/callback"});
        return new JTable(m);
    }

    @Test
    void matchesRowByUrlSubstring() {
        // "#" numbering is noise; a unique URL substring finds the exact row
        assertEquals(0, rowForText(history(), "/gtm.js"));
    }

    @Test
    void lastMatchWinsForRepeatedRequest() {
        // two rows share the path -> newest (highest view row) is selected
        assertEquals(3, rowForText(history(), "oidc/callback"));
    }

    @Test
    void caseInsensitiveAcrossColumns() {
        assertEquals(2, rowForText(history(), "GOOGLEAPIS.COM"));
    }

    @Test
    void noMatchReturnsMinusOne() {
        assertEquals(-1, rowForText(history(), "/does/not/exist"));
    }

    @Test
    void blankNeedleReturnsMinusOne() {
        assertEquals(-1, rowForText(history(), "   "));
    }

    @Test
    void emptyTableReturnsMinusOne() {
        JTable empty = new JTable(new DefaultTableModel(new Object[]{"#", "URL"}, 0));
        assertEquals(-1, rowForText(empty, "anything"));
    }
}
