package com.swissknife.ui;

import com.swissknife.store.FindingsStore;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
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
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Dashboard tab — badges + findings table + server config + export buttons.
 * Owns the auto-refresh entry point ({@link #refreshStats()}) but does NOT
 * own the timer; the composer drives it.
 */
public class DashboardPanel extends JPanel {

    // Pulled from FindingsStore so the table and store stay in lockstep.
    private static final Map<String, String> REMEDIATION = FindingsStore.REMEDIATION;

    private final FindingsStore findingsStore;
    private final Supplier<List<String[]>> sessionSupplier;
    private final Consumer<String> logSink;

    private final DefaultTableModel findingsModel;

    // Badges
    private JLabel badgeTotal;
    private JLabel badgeCritical;
    private JLabel badgeHigh;
    private JLabel badgeMedium;
    private JLabel badgeLow;
    private JLabel badgeSessions;

    // Server config
    private JTextField hostField;
    private JTextField portField;
    private JLabel statusLabel;
    private String serverHost;
    private int serverPort;

    public DashboardPanel(String host, int port, String version,
                          BiConsumer<String, Integer> restartCallback,
                          Supplier<List<String[]>> sessionSupplier,
                          FindingsStore findingsStore,
                          Consumer<String> logSink) {
        super(new BorderLayout(0, 10));
        this.findingsStore = findingsStore;
        this.sessionSupplier = sessionSupplier;
        this.logSink = logSink;
        this.serverHost = host;
        this.serverPort = port;

        this.findingsModel = new DefaultTableModel(
            new String[]{"ID", "Severity", "Title", "Endpoint", "Timestamp"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        buildUi(host, port, version, restartCallback);
    }

    private void buildUi(String host, int port, String version,
                         BiConsumer<String, Integer> restartCallback) {
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // Top: header + status bar
        JPanel top = new JPanel(new BorderLayout(0, 8));

        JPanel header = new JPanel(new BorderLayout());
        header.setBorder(new CompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 2, 0, UiHelpers.ACCENT),
            BorderFactory.createEmptyBorder(0, 0, 6, 0)
        ));
        JLabel title = new JLabel("Swiss Knife MCP");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 20f));
        title.setForeground(UiHelpers.ACCENT);
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
        badgeCritical = makeBadge("Critical: 0", UiHelpers.SEV_CRITICAL);
        badgeHigh = makeBadge("High: 0", UiHelpers.SEV_HIGH);
        badgeMedium = makeBadge("Medium: 0", UiHelpers.SEV_MEDIUM);
        badgeLow = makeBadge("Low: 0", UiHelpers.SEV_LOW);
        statusBar.add(badgeSessions);
        statusBar.add(Box.createHorizontalStrut(6));
        statusBar.add(badgeTotal);
        statusBar.add(badgeCritical);
        statusBar.add(badgeHigh);
        statusBar.add(badgeMedium);
        statusBar.add(badgeLow);
        top.add(statusBar, BorderLayout.SOUTH);
        add(top, BorderLayout.NORTH);

        // Center: findings table
        JPanel centerSection = new JPanel(new BorderLayout(0, 4));
        centerSection.setBorder(new CompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(UiHelpers.BORDER_COLOR),
                "  Findings (double-click to view details)  ",
                TitledBorder.LEFT, TitledBorder.TOP,
                centerSection.getFont().deriveFont(Font.BOLD, 12f)
            ),
            BorderFactory.createEmptyBorder(4, 4, 4, 4)
        ));

        JTable findingsTable = new JTable(findingsModel);
        UiHelpers.styleTable(findingsTable, new int[]{35, 70, 250, 200, 110});
        UiHelpers.applySeverityRenderer(findingsTable, 1);

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
        add(centerSection, BorderLayout.CENTER);

        // Bottom: export buttons + server config
        JPanel bottom = new JPanel(new BorderLayout(0, 0));

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

        JPanel configRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        configRow.setBorder(new CompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(UiHelpers.BORDER_COLOR), "  API Server  ",
                TitledBorder.LEFT, TitledBorder.TOP,
                configRow.getFont().deriveFont(Font.BOLD, 12f)
            ),
            BorderFactory.createEmptyBorder(4, 6, 4, 6)
        ));

        configRow.add(UiHelpers.label("Host:"));
        hostField = new JTextField(host, 12);
        hostField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(UiHelpers.BORDER_COLOR),
            BorderFactory.createEmptyBorder(3, 5, 3, 5)));
        configRow.add(hostField);

        configRow.add(UiHelpers.label("Port:"));
        portField = new JTextField(String.valueOf(port), 5);
        portField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(UiHelpers.BORDER_COLOR),
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
                setStatus("Invalid port (1-65535)", UiHelpers.BG_ERROR, Color.RED);
                return;
            }
            setStatus("Restarting...", UiHelpers.BG_INFO, Color.BLUE);
            new SwingWorker<Void, Void>() {
                @Override protected Void doInBackground() { restartCallback.accept(newHost, newPort); return null; }
                @Override protected void done() {
                    serverHost = newHost;
                    serverPort = newPort;
                    setStatus(" Running on " + newHost + ":" + newPort + " ", UiHelpers.BG_SUCCESS, UiHelpers.ACCENT);
                    log("Server restarted on " + newHost + ":" + newPort);
                }
            }.execute();
        });
        configRow.add(applyBtn);

        statusLabel = new JLabel(" Running on " + host + ":" + port + " ");
        statusLabel.setOpaque(true);
        statusLabel.setBackground(UiHelpers.BG_SUCCESS);
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 11f));
        statusLabel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(UiHelpers.ACCENT),
            BorderFactory.createEmptyBorder(3, 6, 3, 6)));
        configRow.add(statusLabel);

        bottom.add(configRow, BorderLayout.SOUTH);
        add(bottom, BorderLayout.SOUTH);
    }

    // ── Refresh ──

    /** Called by the composer's auto-refresh timer. EDT-safe. */
    public void refreshStats() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refreshStats);
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

        findingsModel.setRowCount(0);
        for (int i = all.size() - 1; i >= 0; i--) {
            Map<String, Object> f = all.get(i);
            findingsModel.addRow(new Object[]{
                f.get("id"), f.get("severity"), f.get("title"), f.get("endpoint"),
                UiHelpers.formatTimestamp(String.valueOf(f.getOrDefault("timestamp", ""))),
            });
        }
    }

    // ── Finding detail dialog ──

    private void showFindingDetail(int tableRow) {
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

        FindingDetailDialog.show(this, findingId, finding, REMEDIATION);
    }

    // ── Exports ──

    private void exportOpenApiToFile() {
        String prefix = JOptionPane.showInputDialog(this,
            "Enter the target base URL (e.g. https://example.com):",
            "Export OpenAPI", JOptionPane.QUESTION_MESSAGE);
        if (prefix == null || prefix.isBlank()) return;

        JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
        fc.setSelectedFile(new File("openapi-export.yaml"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
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
                    JOptionPane.showMessageDialog(DashboardPanel.this,
                        "Exported " + outFile.getName() + " (" + yaml.length() + " bytes)",
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
                    log("Exported OpenAPI to " + outFile.getAbsolutePath());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(DashboardPanel.this,
                        "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void exportFindingsReport() {
        if (findingsStore == null || findingsStore.getAll("").isEmpty()) {
            JOptionPane.showMessageDialog(this, "No findings to export.", "Export Report", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
        fc.setSelectedFile(new File("pentest-report.md"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
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
                    get();
                    JOptionPane.showMessageDialog(DashboardPanel.this,
                        "Exported " + outFile.getName(),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
                    log("Exported report to " + outFile.getAbsolutePath());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(DashboardPanel.this,
                        "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    // ── Helpers ──

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

    private void setStatus(String text, Color bg, Color border) {
        statusLabel.setText(" " + text + " ");
        statusLabel.setBackground(bg);
        statusLabel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(border),
            BorderFactory.createEmptyBorder(3, 6, 3, 6)));
    }

    private void log(String message) {
        if (logSink != null) logSink.accept(message);
    }
}
