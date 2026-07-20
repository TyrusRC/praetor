package com.praetor.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Shared styling + small Swing helpers reused across the dashboard panels.
 * Package-private — internal to {@code com.praetor.ui}.
 */
final class UiHelpers {

    private UiHelpers() {}

    // Theme colors
    static final Color ACCENT = new Color(64, 128, 64);
    static final Color BG_SUCCESS = new Color(230, 250, 230);
    static final Color BG_ERROR = new Color(255, 230, 230);
    static final Color BG_INFO = new Color(230, 240, 255);
    static final Color BORDER_COLOR = new Color(200, 200, 200);
    static final Color SECTION_BG = new Color(248, 248, 248);

    // Severity colors
    static final Color SEV_CRITICAL = new Color(220, 38, 38);
    static final Color SEV_HIGH = new Color(234, 88, 12);
    static final Color SEV_MEDIUM = new Color(180, 130, 0);
    static final Color SEV_LOW = new Color(22, 163, 74);

    static JLabel sectionTitle(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 14f));
        l.setBorder(BorderFactory.createEmptyBorder(4, 0, 6, 0));
        return l;
    }

    static JLabel hint(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.ITALIC, 11f));
        l.setForeground(Color.GRAY);
        l.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        return l;
    }

    static JLabel label(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 12f));
        return l;
    }

    static void styleTable(JTable table, int[] widths) {
        table.setFillsViewportHeight(true);
        table.setRowHeight(24);
        table.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        table.getTableHeader().setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        table.getTableHeader().setBackground(SECTION_BG);
        table.setGridColor(BORDER_COLOR);
        table.setShowGrid(true);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        for (int i = 0; i < widths.length && i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
    }

    static void applySeverityRenderer(JTable table, int colIndex) {
        table.getColumnModel().getColumn(colIndex).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value, boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
                if (!sel && value != null) {
                    switch (value.toString()) {
                        case "CRITICAL" -> { c.setBackground(new Color(255, 200, 200)); c.setForeground(new Color(180, 0, 0)); }
                        case "HIGH" -> { c.setBackground(new Color(255, 220, 200)); c.setForeground(new Color(200, 80, 0)); }
                        case "MEDIUM" -> { c.setBackground(new Color(255, 245, 200)); c.setForeground(new Color(180, 130, 0)); }
                        case "LOW" -> { c.setBackground(new Color(230, 255, 230)); c.setForeground(new Color(0, 128, 0)); }
                        default -> { c.setBackground(Color.WHITE); c.setForeground(Color.DARK_GRAY); }
                    }
                }
                return c;
            }
        });
    }

    static String formatTimestamp(String iso) {
        if (iso == null || iso.isEmpty() || "null".equals(iso)) return "";
        try {
            if (iso.length() >= 19) {
                return iso.substring(5, 10) + " " + iso.substring(11, 19);
            }
        } catch (Exception ignored) {}
        return iso;
    }

    static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /**
     * Make stored finding text readable in a plain {@link JTextArea}.
     *
     * <p>Two things break readability of saved findings: content that arrived
     * JSON double-encoded carries literal {@code \n}/{@code \t} sequences
     * instead of real whitespace, and presentation fields sometimes carry HTML
     * markup ({@code <html><b>…}) that a JTextArea shows as raw tags.
     *
     * <p>Always converts literal escape sequences to real whitespace. When
     * {@code stripTags} is true (description / remediation — author-controlled
     * presentation), HTML line-break/block tags become newlines, remaining tags
     * are removed, and basic entities are unescaped. When false (EVIDENCE), all
     * markup is preserved byte-faithfully so attack payloads (e.g.
     * {@code <script>alert(1)</script>}) stay visible as proof — only the literal
     * escape sequences are normalised.
     */
    static String toReadableText(String s, boolean stripTags) {
        if (s == null || s.isEmpty()) return "";
        // Literal escape sequences that survived JSON double-encoding.
        String out = s.replace("\\r\\n", "\n").replace("\\n", "\n")
                      .replace("\\r", "\n").replace("\\t", "\t");
        if (stripTags) {
            out = out.replaceAll("(?i)<\\s*br\\s*/?\\s*>", "\n")
                     .replaceAll("(?i)</?\\s*(p|div|li|tr|h[1-6]|html|head|body|ul|ol|table)\\s*>", "\n")
                     .replaceAll("<[^>]+>", "")
                     .replaceAll("\n{3,}", "\n\n");
            out = unescapeEntities(out);
        }
        return out.strip();
    }

    /** Unescape the handful of HTML entities that show up in finding text. */
    private static String unescapeEntities(String s) {
        return s.replace("&lt;", "<").replace("&gt;", ">")
                .replace("&quot;", "\"").replace("&#39;", "'")
                .replace("&nbsp;", " ").replace("&amp;", "&"); // &amp; last
    }
}
