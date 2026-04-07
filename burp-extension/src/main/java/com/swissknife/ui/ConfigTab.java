package com.swissknife.ui;

import burp.api.montoya.MontoyaApi;
import com.swissknife.store.FindingsStore;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Supplier;

/**
 * Multi-panel dashboard for Swiss Knife MCP extension.
 * Tabs: Dashboard | Sessions | Activity Log
 */
public class ConfigTab {

    private final JPanel panel;
    private JTextField hostField;
    private JTextField portField;
    private JLabel statusLabel;
    private final MontoyaApi api;

    // Activity log
    private final DefaultListModel<String> logModel = new DefaultListModel<>();
    private static volatile ConfigTab instance;

    // Tables
    private final DefaultTableModel sessionsModel;
    private final DefaultTableModel findingsModel;

    // Data sources
    private final Supplier<List<String[]>> sessionSupplier;
    private final FindingsStore findingsStore;

    // Dashboard badges
    private JLabel badgeTotal;
    private JLabel badgeCritical;
    private JLabel badgeHigh;
    private JLabel badgeMedium;
    private JLabel badgeLow;
    private JLabel badgeSessions;

    // Auto-refresh timer
    private final javax.swing.Timer refreshTimer;

    // Server config (for export API calls)
    private String serverHost;
    private int serverPort;

    // Colors
    private static final Color ACCENT = new Color(64, 128, 64);
    private static final Color BG_SUCCESS = new Color(230, 250, 230);
    private static final Color BG_ERROR = new Color(255, 230, 230);
    private static final Color BG_INFO = new Color(230, 240, 255);
    private static final Color BORDER_COLOR = new Color(200, 200, 200);
    private static final Color SECTION_BG = new Color(248, 248, 248);

    // Severity colors
    private static final Color SEV_CRITICAL = new Color(220, 38, 38);
    private static final Color SEV_HIGH = new Color(234, 88, 12);
    private static final Color SEV_MEDIUM = new Color(180, 130, 0);
    private static final Color SEV_LOW = new Color(22, 163, 74);

    // CWE remediation (mirrors FindingsStore for UI display)
    private static final Map<String, String> REMEDIATION = Map.ofEntries(
        Map.entry("CWE-89", "Use parameterized queries or prepared statements. Never concatenate user input into SQL."),
        Map.entry("CWE-79", "Encode output according to context (HTML, JS, URL). Use Content-Security-Policy header."),
        Map.entry("CWE-22", "Validate and sanitize file paths. Use allowlists for permitted files."),
        Map.entry("CWE-78", "Avoid system commands with user input. Use safe APIs instead of shell execution."),
        Map.entry("CWE-918", "Validate and restrict URLs. Block internal/private IP ranges."),
        Map.entry("CWE-611", "Disable external entity processing in XML parsers."),
        Map.entry("CWE-639", "Implement proper authorization checks. Verify object ownership on every request."),
        Map.entry("CWE-200", "Disable debug mode and verbose error messages in production."),
        Map.entry("CWE-1336", "Never pass user input directly to template engines. Use sandboxed rendering.")
    );

    public ConfigTab(MontoyaApi api, String currentHost, int currentPort, String version,
                     BiConsumer<String, Integer> restartCallback,
                     Supplier<List<String[]>> sessionSupplier, FindingsStore findingsStore) {
        this.api = api;
        this.sessionSupplier = sessionSupplier;
        this.findingsStore = findingsStore;
        this.serverHost = currentHost;
        this.serverPort = currentPort;
        instance = this;

        panel = new JPanel(new BorderLayout());

        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(tabs.getFont().deriveFont(Font.BOLD, 12f));

        sessionsModel = new DefaultTableModel(new String[]{"Session", "Base URL", "Cookies", "Variables", "Auth"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        findingsModel = new DefaultTableModel(new String[]{"ID", "Severity", "Title", "Endpoint", "Timestamp"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        tabs.addTab(" Dashboard ", buildDashboardPanel(currentHost, currentPort, version, restartCallback));
        tabs.addTab(" Sessions ", buildSessionsPanel());
        tabs.addTab(" Activity Log ", buildLogPanel());

        panel.add(tabs, BorderLayout.CENTER);

        // Auto-refresh dashboard every 5 seconds
        refreshTimer = new javax.swing.Timer(5000, e -> refreshDashboardStats());
        refreshTimer.start();
    }

    // ── Dashboard Panel ──

    private JPanel buildDashboardPanel(String host, int port, String version,
                                        BiConsumer<String, Integer> restartCallback) {
        JPanel p = new JPanel(new BorderLayout(0, 10));
        p.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // ── Top: header + status bar ──
        JPanel top = new JPanel(new BorderLayout(0, 8));

        JPanel header = new JPanel(new BorderLayout());
        header.setBorder(new CompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 2, 0, ACCENT),
            BorderFactory.createEmptyBorder(0, 0, 6, 0)
        ));
        JLabel title = new JLabel("Swiss Knife MCP");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 20f));
        title.setForeground(ACCENT);
        header.add(title, BorderLayout.WEST);
        JLabel ver = new JLabel("v" + version);
        ver.setFont(ver.getFont().deriveFont(Font.PLAIN, 13f));
        ver.setForeground(Color.GRAY);
        header.add(ver, BorderLayout.EAST);
        top.add(header, BorderLayout.NORTH);

        // Status bar: badges
        JPanel statusBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        statusBar.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
        badgeSessions = makeBadge("Sessions: 0", new Color(124, 58, 237));
        badgeTotal = makeBadge("Findings: 0", Color.DARK_GRAY);
        badgeCritical = makeBadge("Critical: 0", SEV_CRITICAL);
        badgeHigh = makeBadge("High: 0", SEV_HIGH);
        badgeMedium = makeBadge("Medium: 0", SEV_MEDIUM);
        badgeLow = makeBadge("Low: 0", SEV_LOW);
        statusBar.add(badgeSessions);
        statusBar.add(Box.createHorizontalStrut(6));
        statusBar.add(badgeTotal);
        statusBar.add(badgeCritical);
        statusBar.add(badgeHigh);
        statusBar.add(badgeMedium);
        statusBar.add(badgeLow);
        top.add(statusBar, BorderLayout.SOUTH);
        p.add(top, BorderLayout.NORTH);

        // ── Center: findings table ──
        JPanel centerSection = new JPanel(new BorderLayout(0, 4));
        centerSection.setBorder(new CompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_COLOR), "  Findings (double-click to view details)  ",
                TitledBorder.LEFT, TitledBorder.TOP,
                centerSection.getFont().deriveFont(Font.BOLD, 12f)
            ),
            BorderFactory.createEmptyBorder(4, 4, 4, 4)
        ));

        JTable findingsTable = new JTable(findingsModel);
        styleTable(findingsTable, new int[]{35, 70, 250, 200, 110});
        applySeverityRenderer(findingsTable, 1);

        // Double-click to open finding detail
        findingsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = findingsTable.getSelectedRow();
                    if (row >= 0) showFindingDetail(row);
                }
            }
        });

        centerSection.add(new JScrollPane(findingsTable), BorderLayout.CENTER);
        p.add(centerSection, BorderLayout.CENTER);

        // ── Bottom: config + export buttons ──
        JPanel bottom = new JPanel(new BorderLayout(0, 0));

        // Export buttons
        JPanel exportRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        exportRow.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));

        JButton exportOpenApi = new JButton("Export OpenAPI");
        exportOpenApi.setToolTipText("Export sitemap as OpenAPI 3.0 YAML");
        exportOpenApi.addActionListener(e -> exportOpenApiToFile());
        exportRow.add(exportOpenApi);

        JButton exportReport = new JButton("Export Report");
        exportReport.setToolTipText("Export findings as Markdown report");
        exportReport.addActionListener(e -> exportFindingsReport());
        exportRow.add(exportReport);

        bottom.add(exportRow, BorderLayout.NORTH);

        // Server config
        JPanel configRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        configRow.setBorder(new CompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_COLOR), "  API Server  ",
                TitledBorder.LEFT, TitledBorder.TOP,
                configRow.getFont().deriveFont(Font.BOLD, 12f)
            ),
            BorderFactory.createEmptyBorder(4, 6, 4, 6)
        ));

        configRow.add(label("Host:"));
        hostField = new JTextField(host, 12);
        hostField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_COLOR),
            BorderFactory.createEmptyBorder(3, 5, 3, 5)));
        configRow.add(hostField);

        configRow.add(label("Port:"));
        portField = new JTextField(String.valueOf(port), 5);
        portField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_COLOR),
            BorderFactory.createEmptyBorder(3, 5, 3, 5)));
        configRow.add(portField);

        JButton applyBtn = new JButton("Apply & Restart");
        applyBtn.setFont(applyBtn.getFont().deriveFont(Font.BOLD));
        applyBtn.addActionListener(e -> {
            String newHost = hostField.getText().trim();
            int newPort;
            try {
                newPort = Integer.parseInt(portField.getText().trim());
                if (newPort < 1 || newPort > 65535) throw new NumberFormatException();
            } catch (NumberFormatException ex) {
                setStatus("Invalid port (1-65535)", BG_ERROR, Color.RED);
                return;
            }
            setStatus("Restarting...", BG_INFO, Color.BLUE);
            new SwingWorker<Void, Void>() {
                @Override protected Void doInBackground() { restartCallback.accept(newHost, newPort); return null; }
                @Override protected void done() {
                    serverHost = newHost;
                    serverPort = newPort;
                    setStatus(" Running on " + newHost + ":" + newPort + " ", BG_SUCCESS, ACCENT);
                    log("Server restarted on " + newHost + ":" + newPort);
                }
            }.execute();
        });
        configRow.add(applyBtn);

        statusLabel = new JLabel(" Running on " + host + ":" + port + " ");
        statusLabel.setOpaque(true);
        statusLabel.setBackground(BG_SUCCESS);
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 11f));
        statusLabel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ACCENT),
            BorderFactory.createEmptyBorder(3, 6, 3, 6)));
        configRow.add(statusLabel);

        bottom.add(configRow, BorderLayout.SOUTH);
        p.add(bottom, BorderLayout.SOUTH);
        return p;
    }

    // ── Finding Detail Dialog ──

    private void showFindingDetail(int tableRow) {
        // Get finding ID from table, look up full data from store
        Object idObj = findingsModel.getValueAt(tableRow, 0);
        if (!(idObj instanceof Number)) return;
        int findingId = ((Number) idObj).intValue();

        Map<String, Object> finding = null;
        for (Map<String, Object> f : findingsStore.getAll("")) {
            if (findingId == ((Number) f.get("id")).intValue()) {
                finding = f;
                break;
            }
        }
        if (finding == null) return;

        String titleText = String.valueOf(finding.getOrDefault("title", ""));
        String severity = String.valueOf(finding.getOrDefault("severity", "INFO"));
        String endpoint = String.valueOf(finding.getOrDefault("endpoint", ""));
        String description = String.valueOf(finding.getOrDefault("description", ""));
        String evidence = String.valueOf(finding.getOrDefault("evidence", ""));
        String timestamp = String.valueOf(finding.getOrDefault("timestamp", ""));
        String cwe = inferCwe(finding);

        // Build dialog
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(panel), "Finding #" + findingId, Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout());
        dialog.setSize(700, 550);
        dialog.setLocationRelativeTo(panel);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));

        // Severity + Title header
        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        headerPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel sevLabel = new JLabel(" " + severity + " ");
        sevLabel.setOpaque(true);
        sevLabel.setFont(sevLabel.getFont().deriveFont(Font.BOLD, 12f));
        Color sevColor = switch (severity) {
            case "CRITICAL" -> SEV_CRITICAL;
            case "HIGH" -> SEV_HIGH;
            case "MEDIUM" -> SEV_MEDIUM;
            case "LOW" -> SEV_LOW;
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

        // Metadata
        if (!endpoint.isEmpty()) {
            content.add(makeField("Endpoint", endpoint));
        }
        if (!cwe.isEmpty()) {
            content.add(makeField("CWE", cwe));
        }
        if (!timestamp.isEmpty()) {
            content.add(makeField("Timestamp", formatTimestamp(timestamp)));
        }
        content.add(Box.createVerticalStrut(8));

        // Description
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

        // Evidence
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

        // Remediation
        String remediation = REMEDIATION.getOrDefault(cwe, "");
        if (!remediation.isEmpty()) {
            content.add(makeSectionLabel("Remediation"));
            JTextArea remArea = makeTextArea(remediation);
            remArea.setBackground(BG_INFO);
            JScrollPane remScroll = new JScrollPane(remArea);
            remScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
            remScroll.setPreferredSize(new Dimension(650, 60));
            remScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));
            content.add(remScroll);
        }

        JScrollPane mainScroll = new JScrollPane(content);
        mainScroll.setBorder(null);
        dialog.add(mainScroll, BorderLayout.CENTER);

        // Close button
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        btnPanel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER_COLOR));
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        btnPanel.add(closeBtn);
        dialog.add(btnPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    private JLabel makeField(String name, String value) {
        JLabel l = new JLabel("<html><b>" + escapeHtml(name) + ":</b> " + escapeHtml(value) + "</html>");
        l.setFont(l.getFont().deriveFont(12f));
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(1, 0, 1, 0));
        return l;
    }

    private JLabel makeSectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 13f));
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
        return l;
    }

    private JTextArea makeTextArea(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(area.getFont().deriveFont(12f));
        area.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        return area;
    }

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Infer CWE from finding fields — same logic as FindingsStore. */
    private String inferCwe(Map<String, Object> finding) {
        String titleVal = String.valueOf(finding.getOrDefault("title", "")).toLowerCase();
        String evidenceVal = String.valueOf(finding.getOrDefault("evidence", "")).toLowerCase();
        String combined = titleVal + " " + evidenceVal;

        for (String cwe : REMEDIATION.keySet()) {
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

    // ── Export Actions ──

    private void exportOpenApiToFile() {
        String prefix = JOptionPane.showInputDialog(panel,
            "Enter the target base URL (e.g. https://example.com):",
            "Export OpenAPI", JOptionPane.QUESTION_MESSAGE);
        if (prefix == null || prefix.isBlank()) return;

        JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
        fc.setSelectedFile(new File("openapi-export.yaml"));
        if (fc.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        File outFile = fc.getSelectedFile();

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                String url = "http://" + serverHost + ":" + serverPort
                    + "/api/export/sitemap?format=openapi&prefix="
                    + java.net.URLEncoder.encode(prefix, java.nio.charset.StandardCharsets.UTF_8);
                try (HttpClient client = HttpClient.newHttpClient()) {
                    HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).GET().build();
                    HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
                    if (resp.statusCode() != 200) {
                        throw new IOException("API returned " + resp.statusCode() + ": " + resp.body());
                    }
                    return resp.body();
                }
            }

            @Override
            protected void done() {
                try {
                    String yaml = get();
                    try (FileWriter fw = new FileWriter(outFile)) {
                        fw.write(yaml);
                    }
                    JOptionPane.showMessageDialog(panel,
                        "Exported " + outFile.getName() + " (" + yaml.length() + " bytes)",
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
                    log("Exported OpenAPI to " + outFile.getAbsolutePath());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(panel,
                        "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void exportFindingsReport() {
        if (findingsStore == null || findingsStore.getAll("").isEmpty()) {
            JOptionPane.showMessageDialog(panel, "No findings to export.", "Export Report", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
        fc.setSelectedFile(new File("pentest-report.md"));
        if (fc.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        File outFile = fc.getSelectedFile();

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                try (FileWriter fw = new FileWriter(outFile)) {
                    fw.write(findingsStore.exportMarkdown());
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    get(); // propagate exceptions
                    JOptionPane.showMessageDialog(panel,
                        "Exported " + outFile.getName(),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
                    log("Exported report to " + outFile.getAbsolutePath());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(panel,
                        "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    // ── Dashboard Stats Refresh ──

    private JLabel makeBadge(String text, Color color) {
        JLabel badge = new JLabel(text);
        badge.setFont(badge.getFont().deriveFont(Font.BOLD, 11f));
        badge.setForeground(color);
        badge.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(color, 1),
            BorderFactory.createEmptyBorder(2, 6, 2, 6)
        ));
        return badge;
    }

    private void refreshDashboardStats() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshDashboardStats);
            return;
        }
        int sessionCount = 0;
        if (sessionSupplier != null) {
            try { sessionCount = sessionSupplier.get().size(); } catch (Exception ignored) {}
        }
        badgeSessions.setText("Sessions: " + sessionCount);

        if (findingsStore == null) return;
        List<Map<String, Object>> all = findingsStore.getAll("");
        int crit = 0, high = 0, med = 0, low = 0;
        for (Map<String, Object> f : all) {
            String sev = String.valueOf(f.getOrDefault("severity", ""));
            switch (sev) {
                case "CRITICAL" -> crit++;
                case "HIGH" -> high++;
                case "MEDIUM" -> med++;
                case "LOW" -> low++;
            }
        }
        badgeTotal.setText("Findings: " + all.size());
        badgeCritical.setText("Critical: " + crit);
        badgeHigh.setText("High: " + high);
        badgeMedium.setText("Medium: " + med);
        badgeLow.setText("Low: " + low);

        badgeCritical.setVisible(crit > 0);
        badgeHigh.setVisible(high > 0);
        badgeMedium.setVisible(med > 0);
        badgeLow.setVisible(low > 0);

        // Refresh findings table (newest first)
        findingsModel.setRowCount(0);
        for (int i = all.size() - 1; i >= 0; i--) {
            Map<String, Object> f = all.get(i);
            findingsModel.addRow(new Object[]{
                f.get("id"), f.get("severity"), f.get("title"), f.get("endpoint"),
                formatTimestamp(String.valueOf(f.getOrDefault("timestamp", ""))),
            });
        }
    }

    // ── Sessions Panel ──

    private JPanel buildSessionsPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout());
        top.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER_COLOR));
        JLabel title = sectionTitle("Active Attack Sessions");
        JLabel hint = hint("Persistent session state created by Claude — cookies, auth tokens, extracted variables.");
        top.add(title, BorderLayout.WEST);
        top.add(hint, BorderLayout.SOUTH);
        p.add(top, BorderLayout.NORTH);

        JTable table = new JTable(sessionsModel);
        styleTable(table, new int[]{120, 250, 60, 70, 50});
        p.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        btns.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER_COLOR));
        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refreshSessions());
        btns.add(refresh);
        p.add(btns, BorderLayout.SOUTH);

        return p;
    }

    private void refreshSessions() {
        sessionsModel.setRowCount(0);
        if (sessionSupplier == null) return;
        for (String[] row : sessionSupplier.get()) {
            sessionsModel.addRow(row);
        }
    }

    // ── Activity Log Panel ──

    private JPanel buildLogPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout());
        top.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER_COLOR));
        JLabel title = sectionTitle("MCP Activity Log");
        JLabel hint3 = hint("Real-time stream of API calls from Claude via the MCP server.");
        top.add(title, BorderLayout.WEST);
        top.add(hint3, BorderLayout.SOUTH);
        p.add(top, BorderLayout.NORTH);

        JList<String> logList = new JList<>(logModel);
        logList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logList.setBackground(new Color(252, 252, 252));
        logList.setSelectionBackground(BG_INFO);
        p.add(new JScrollPane(logList), BorderLayout.CENTER);

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        btns.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER_COLOR));
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> logModel.clear());
        btns.add(clearBtn);
        p.add(btns, BorderLayout.SOUTH);

        return p;
    }

    // ── Helpers ──

    private String formatTimestamp(String iso) {
        if (iso == null || iso.isEmpty() || "null".equals(iso)) return "";
        try {
            if (iso.length() >= 19) {
                return iso.substring(5, 10) + " " + iso.substring(11, 19);
            }
        } catch (Exception ignored) {}
        return iso;
    }

    private static void applySeverityRenderer(JTable table, int colIndex) {
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

    private void setStatus(String text, Color bg, Color border) {
        statusLabel.setText(" " + text + " ");
        statusLabel.setBackground(bg);
        statusLabel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(border),
            BorderFactory.createEmptyBorder(3, 6, 3, 6)));
    }

    private static void styleTable(JTable table, int[] widths) {
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

    private static JLabel sectionTitle(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 14f));
        l.setBorder(BorderFactory.createEmptyBorder(4, 0, 6, 0));
        return l;
    }

    private static JLabel hint(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.ITALIC, 11f));
        l.setForeground(Color.GRAY);
        l.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        return l;
    }

    private static JLabel label(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 12f));
        return l;
    }

    public JPanel getPanel() { return panel; }

    /** Stop auto-refresh timer. Call on extension unload to prevent leaks. */
    public void stop() {
        refreshTimer.stop();
    }

    /** Thread-safe activity log entry. */
    public static void log(String message) {
        ConfigTab current = instance; // read volatile once
        if (current == null) return;
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String entry = "[" + ts + "] " + message;
        SwingUtilities.invokeLater(() -> {
            current.logModel.addElement(entry);
            while (current.logModel.size() > 500) current.logModel.remove(0);
        });
    }
}
