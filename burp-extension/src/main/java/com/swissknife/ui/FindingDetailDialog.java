package com.swissknife.ui;

import javax.swing.*;
import java.awt.*;
import java.util.Map;

/**
 * Modal dialog showing a single finding's full detail: severity badge, title,
 * endpoint, CWE, timestamp, description, evidence block, remediation guidance.
 * Owns its own widget helpers (label / text-area / CWE inference) so the
 * dashboard panel doesn't carry rendering code.
 */
final class FindingDetailDialog {

    private FindingDetailDialog() {}

    /**
     * Build and display the dialog for {@code finding}. Blocks until closed
     * (APPLICATION_MODAL).
     *
     * @param parent       UI component used to anchor the dialog
     * @param findingId    numeric id, shown in the window title
     * @param finding      raw finding map from FindingsStore
     * @param remediation  CWE -> remediation text map (FindingsStore.REMEDIATION)
     */
    static void show(Component parent, int findingId, Map<String, Object> finding,
                     Map<String, String> remediation) {
        String titleText = String.valueOf(finding.getOrDefault("title", ""));
        String severity = String.valueOf(finding.getOrDefault("severity", "INFO"));
        String endpoint = String.valueOf(finding.getOrDefault("endpoint", ""));
        String description = String.valueOf(finding.getOrDefault("description", ""));
        String evidence = String.valueOf(finding.getOrDefault("evidence", ""));
        String timestamp = String.valueOf(finding.getOrDefault("timestamp", ""));
        String cwe = inferCwe(finding, remediation);

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(parent),
            "Finding #" + findingId, Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout());
        dialog.setSize(700, 550);
        dialog.setLocationRelativeTo(parent);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));

        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        headerPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel sevLabel = new JLabel(" " + severity + " ");
        sevLabel.setOpaque(true);
        sevLabel.setFont(sevLabel.getFont().deriveFont(Font.BOLD, 12f));
        Color sevColor = switch (severity) {
            case "CRITICAL" -> UiHelpers.SEV_CRITICAL;
            case "HIGH" -> UiHelpers.SEV_HIGH;
            case "MEDIUM" -> UiHelpers.SEV_MEDIUM;
            case "LOW" -> UiHelpers.SEV_LOW;
            default -> Color.GRAY;
        };
        sevLabel.setForeground(Color.WHITE);
        sevLabel.setBackground(sevColor);
        sevLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        headerPanel.add(sevLabel);
        JLabel titleLabel = new JLabel(titleText);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
        headerPanel.add(titleLabel);
        content.add(headerPanel);
        content.add(Box.createVerticalStrut(8));

        if (!endpoint.isEmpty()) content.add(makeField("Endpoint", endpoint));
        if (!cwe.isEmpty()) content.add(makeField("CWE", cwe));
        if (!timestamp.isEmpty()) content.add(makeField("Timestamp", UiHelpers.formatTimestamp(timestamp)));
        content.add(Box.createVerticalStrut(8));

        if (!description.isEmpty()) {
            content.add(makeSectionLabel("Description"));
            JTextArea descArea = makeTextArea(description);
            JScrollPane descScroll = new JScrollPane(descArea);
            descScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
            descScroll.setPreferredSize(new Dimension(650, 100));
            descScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 150));
            content.add(descScroll);
            content.add(Box.createVerticalStrut(8));
        }

        if (!evidence.isEmpty()) {
            content.add(makeSectionLabel("Evidence"));
            JTextArea evidenceArea = makeTextArea(evidence);
            evidenceArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            evidenceArea.setBackground(new Color(245, 245, 245));
            JScrollPane evidenceScroll = new JScrollPane(evidenceArea);
            evidenceScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
            evidenceScroll.setPreferredSize(new Dimension(650, 120));
            evidenceScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 200));
            content.add(evidenceScroll);
            content.add(Box.createVerticalStrut(8));
        }

        String remediationText = remediation.getOrDefault(cwe, "");
        if (!remediationText.isEmpty()) {
            content.add(makeSectionLabel("Remediation"));
            JTextArea remArea = makeTextArea(remediationText);
            remArea.setBackground(UiHelpers.BG_INFO);
            JScrollPane remScroll = new JScrollPane(remArea);
            remScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
            remScroll.setPreferredSize(new Dimension(650, 60));
            remScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));
            content.add(remScroll);
        }

        JScrollPane mainScroll = new JScrollPane(content);
        mainScroll.setBorder(null);
        dialog.add(mainScroll, BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        btnPanel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, UiHelpers.BORDER_COLOR));
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        btnPanel.add(closeBtn);
        dialog.add(btnPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    private static JLabel makeField(String name, String value) {
        JLabel l = new JLabel("<html><b>" + UiHelpers.escapeHtml(name) + ":</b> " + UiHelpers.escapeHtml(value) + "</html>");
        l.setFont(l.getFont().deriveFont(12f));
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(1, 0, 1, 0));
        return l;
    }

    private static JLabel makeSectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 13f));
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
        return l;
    }

    private static JTextArea makeTextArea(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(area.getFont().deriveFont(12f));
        area.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        return area;
    }

    /** Infer CWE from finding fields — same logic as FindingsStore. */
    private static String inferCwe(Map<String, Object> finding, Map<String, String> remediation) {
        String titleVal = String.valueOf(finding.getOrDefault("title", "")).toLowerCase();
        String evidenceVal = String.valueOf(finding.getOrDefault("evidence", "")).toLowerCase();
        String combined = titleVal + " " + evidenceVal;

        for (String cwe : remediation.keySet()) {
            if (combined.contains(cwe.toLowerCase())) return cwe;
        }

        if (combined.contains("sqli") || combined.contains("sql")) return "CWE-89";
        if (combined.contains("xss") || combined.contains("cross-site scripting")) return "CWE-79";
        if (combined.contains("path_traversal") || combined.contains("traversal") || combined.contains("lfi")) return "CWE-22";
        if (combined.contains("ssti") || combined.contains("template")) return "CWE-1336";
        if (combined.contains("command_injection") || combined.contains("rce") || combined.contains("os command")) return "CWE-78";
        if (combined.contains("ssrf")) return "CWE-918";
        if (combined.contains("xxe") || combined.contains("xml external")) return "CWE-611";
        if (combined.contains("idor") || combined.contains("insecure direct")) return "CWE-639";
        if (combined.contains("info_disclosure") || combined.contains("information disclosure")) return "CWE-200";

        return "";
    }
}
