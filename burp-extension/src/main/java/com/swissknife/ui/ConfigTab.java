package com.swissknife.ui;

import burp.api.montoya.MontoyaApi;
// Uses Map<String, ?> for session data to avoid package-private access issues
import com.swissknife.store.FindingsStore;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Multi-panel dashboard for Swiss Knife MCP extension.
 * Panels: Config | Sessions | Findings | Activity Log
 * Shows unique info NOT already in Burp's native tabs.
 */
public class ConfigTab {

    private final JPanel panel;
    private JTextField hostField;
    private JTextField portField;
    private JLabel statusLabel;
    private final MontoyaApi api;

    // Activity log
    private final DefaultListModel<String> logModel = new DefaultListModel<>();
    private static ConfigTab instance;

    // Sessions table
    private final DefaultTableModel sessionsModel;

    // Findings table
    private final DefaultTableModel findingsModel;

    // Suppliers for refresh — avoid direct access to package-private types
    private final java.util.function.Supplier<List<String[]>> sessionSupplier;
    private final FindingsStore findingsStore;

    public ConfigTab(MontoyaApi api, String currentHost, int currentPort, String version,
                     BiConsumer<String, Integer> restartCallback,
                     java.util.function.Supplier<List<String[]>> sessionSupplier, FindingsStore findingsStore) {
        this.api = api;
        this.sessionSupplier = sessionSupplier;
        this.findingsStore = findingsStore;
        instance = this;

        panel = new JPanel(new BorderLayout());

        // Create tabbed pane inside our main panel
        JTabbedPane tabs = new JTabbedPane();

        // ── Tab 1: Dashboard Overview ──
        tabs.addTab("Dashboard", buildDashboardPanel(currentHost, currentPort, version, restartCallback));

        // ── Tab 2: Active Sessions ──
        sessionsModel = new DefaultTableModel(new String[]{"Session", "Base URL", "Cookies", "Variables", "Auth"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        tabs.addTab("Sessions", buildSessionsPanel());

        // ── Tab 3: Findings ──
        findingsModel = new DefaultTableModel(new String[]{"ID", "Severity", "Title", "Endpoint"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        tabs.addTab("Findings", buildFindingsPanel());

        // ── Tab 4: Activity Log ──
        tabs.addTab("Activity Log", buildLogPanel());

        panel.add(tabs, BorderLayout.CENTER);
    }

    // ── Dashboard Panel ──

    private JPanel buildDashboardPanel(String currentHost, int currentPort, String version,
                                        BiConsumer<String, Integer> restartCallback) {
        JPanel p = new JPanel(new BorderLayout(10, 10));
        p.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Header
        JPanel header = new JPanel(new BorderLayout());
        JLabel title = new JLabel("Swiss Knife MCP");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        header.add(title, BorderLayout.WEST);
        JLabel ver = new JLabel("v" + version);
        ver.setFont(ver.getFont().deriveFont(Font.ITALIC, 12f));
        ver.setForeground(Color.GRAY);
        header.add(ver, BorderLayout.EAST);
        p.add(header, BorderLayout.NORTH);

        // Config form
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0; gbc.gridy = 0;
        form.add(new JLabel("API Host:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        hostField = new JTextField(currentHost, 20);
        form.add(hostField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        form.add(new JLabel("API Port:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        portField = new JTextField(String.valueOf(currentPort), 10);
        form.add(portField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        JLabel help = new JLabel("Default: 127.0.0.1:8111. Python MCP server must match (BURP_API_HOST/BURP_API_PORT env vars).");
        help.setFont(help.getFont().deriveFont(Font.ITALIC, 11f));
        help.setForeground(Color.GRAY);
        form.add(help, gbc);

        // Status (init before button captures it)
        statusLabel = new JLabel("Server running on " + currentHost + ":" + currentPort);
        statusLabel.setForeground(new Color(0, 128, 0));

        gbc.gridy = 3; gbc.gridwidth = 1;
        JButton applyBtn = new JButton("Apply & Restart");
        applyBtn.addActionListener(e -> {
            String newHost = hostField.getText().trim();
            int newPort;
            try {
                newPort = Integer.parseInt(portField.getText().trim());
                if (newPort < 1 || newPort > 65535) throw new NumberFormatException();
            } catch (NumberFormatException ex) {
                statusLabel.setText("Invalid port (1-65535)");
                statusLabel.setForeground(Color.RED);
                return;
            }
            statusLabel.setText("Restarting...");
            statusLabel.setForeground(Color.BLUE);
            new SwingWorker<Void, Void>() {
                @Override protected Void doInBackground() { restartCallback.accept(newHost, newPort); return null; }
                @Override protected void done() {
                    statusLabel.setText("Running on " + newHost + ":" + newPort);
                    statusLabel.setForeground(new Color(0, 128, 0));
                    log("Server restarted on " + newHost + ":" + newPort);
                }
            }.execute();
        });
        form.add(applyBtn, gbc);

        gbc.gridx = 1;
        form.add(statusLabel, gbc);

        p.add(form, BorderLayout.CENTER);

        // Info
        JTextArea info = new JTextArea(
            "Architecture: Claude Code -> Python MCP Server (stdio) -> This Extension (REST API) -> Burp Suite\n\n" +
            "This tab shows sessions, findings, and activity unique to the MCP integration.\n" +
            "Burp's native tabs (Scanner, Sitemap, Proxy History) show their own data — no duplication here."
        );
        info.setEditable(false);
        info.setBackground(p.getBackground());
        info.setFont(info.getFont().deriveFont(11f));
        info.setForeground(Color.DARK_GRAY);
        p.add(info, BorderLayout.SOUTH);

        return p;
    }

    // ── Sessions Panel ──

    private JPanel buildSessionsPanel() {
        JPanel p = new JPanel(new BorderLayout(5, 5));
        p.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        JTable table = new JTable(sessionsModel);
        table.setFillsViewportHeight(true);
        p.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refreshSessions());
        buttons.add(refresh);

        JLabel hint = new JLabel("Sessions are created by Claude via MCP — shows active attack contexts.");
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 11f));
        hint.setForeground(Color.GRAY);
        buttons.add(hint);

        p.add(buttons, BorderLayout.SOUTH);
        return p;
    }

    private void refreshSessions() {
        sessionsModel.setRowCount(0);
        if (sessionSupplier == null) return;
        for (String[] row : sessionSupplier.get()) {
            sessionsModel.addRow(row);
        }
    }

    // ── Findings Panel ──

    private JPanel buildFindingsPanel() {
        JPanel p = new JPanel(new BorderLayout(5, 5));
        p.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        JTable table = new JTable(findingsModel);
        table.setFillsViewportHeight(true);
        p.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refreshFindings());
        buttons.add(refresh);

        JLabel hint = new JLabel("Manual findings saved by Claude — not duplicating Burp Scanner issues.");
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 11f));
        hint.setForeground(Color.GRAY);
        buttons.add(hint);

        p.add(buttons, BorderLayout.SOUTH);
        return p;
    }

    private void refreshFindings() {
        findingsModel.setRowCount(0);
        if (findingsStore == null) return;
        for (Map<String, Object> f : findingsStore.getAll("")) {
            findingsModel.addRow(new Object[]{
                f.get("id"),
                f.get("severity"),
                f.get("title"),
                f.get("endpoint"),
            });
        }
    }

    // ── Activity Log Panel ──

    private JPanel buildLogPanel() {
        JPanel p = new JPanel(new BorderLayout(5, 5));
        p.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        JList<String> logList = new JList<>(logModel);
        logList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        p.add(new JScrollPane(logList), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearBtn = new JButton("Clear Log");
        clearBtn.addActionListener(e -> logModel.clear());
        buttons.add(clearBtn);

        JLabel hint = new JLabel("MCP tool activity — shows what Claude is doing via the extension.");
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 11f));
        hint.setForeground(Color.GRAY);
        buttons.add(hint);

        p.add(buttons, BorderLayout.SOUTH);
        return p;
    }

    // ── Public API ──

    public JPanel getPanel() {
        return panel;
    }

    /**
     * Add entry to activity log. Thread-safe.
     */
    public static void log(String message) {
        if (instance == null) return;
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        SwingUtilities.invokeLater(() -> {
            instance.logModel.addElement("[" + timestamp + "] " + message);
            // Keep last 500 entries
            while (instance.logModel.size() > 500) {
                instance.logModel.remove(0);
            }
        });
    }
}
