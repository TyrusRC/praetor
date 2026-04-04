package com.swissknife.ui;

import burp.api.montoya.MontoyaApi;
import com.swissknife.store.FindingsStore;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Supplier;

/**
 * Multi-panel dashboard for Swiss Knife MCP extension.
 * Tabs: Dashboard | Sessions | Findings | Activity Log
 * Shows unique info NOT in Burp's native tabs.
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

    // Tables
    private final DefaultTableModel sessionsModel;
    private final DefaultTableModel findingsModel;

    // Data sources
    private final Supplier<List<String[]>> sessionSupplier;
    private final FindingsStore findingsStore;

    // Colors
    private static final Color ACCENT = new Color(64, 128, 64);
    private static final Color BG_SUCCESS = new Color(230, 250, 230);
    private static final Color BG_ERROR = new Color(255, 230, 230);
    private static final Color BG_INFO = new Color(230, 240, 255);
    private static final Color BORDER_COLOR = new Color(200, 200, 200);
    private static final Color SECTION_BG = new Color(248, 248, 248);

    public ConfigTab(MontoyaApi api, String currentHost, int currentPort, String version,
                     BiConsumer<String, Integer> restartCallback,
                     Supplier<List<String[]>> sessionSupplier, FindingsStore findingsStore) {
        this.api = api;
        this.sessionSupplier = sessionSupplier;
        this.findingsStore = findingsStore;
        instance = this;

        panel = new JPanel(new BorderLayout());

        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(tabs.getFont().deriveFont(Font.BOLD, 12f));

        sessionsModel = new DefaultTableModel(new String[]{"Session", "Base URL", "Cookies", "Variables", "Auth"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        findingsModel = new DefaultTableModel(new String[]{"ID", "Severity", "Title", "Endpoint"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        tabs.addTab(" Dashboard ", buildDashboardPanel(currentHost, currentPort, version, restartCallback));
        tabs.addTab(" Sessions ", buildSessionsPanel());
        tabs.addTab(" Findings ", buildFindingsPanel());
        tabs.addTab(" Activity Log ", buildLogPanel());

        panel.add(tabs, BorderLayout.CENTER);
    }

    // ── Dashboard Panel ──

    private JPanel buildDashboardPanel(String host, int port, String version,
                                        BiConsumer<String, Integer> restartCallback) {
        JPanel p = new JPanel(new BorderLayout(0, 10));
        p.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // Header bar
        JPanel header = new JPanel(new BorderLayout());
        header.setBorder(new CompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 2, 0, ACCENT),
            BorderFactory.createEmptyBorder(0, 0, 8, 0)
        ));
        JLabel title = new JLabel("Swiss Knife MCP");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 20f));
        title.setForeground(ACCENT);
        header.add(title, BorderLayout.WEST);

        JLabel ver = new JLabel("v" + version);
        ver.setFont(ver.getFont().deriveFont(Font.PLAIN, 13f));
        ver.setForeground(Color.GRAY);
        header.add(ver, BorderLayout.EAST);
        p.add(header, BorderLayout.NORTH);

        // Config section
        JPanel configSection = new JPanel(new BorderLayout(0, 8));

        JPanel formWrapper = new JPanel(new BorderLayout());
        formWrapper.setBorder(new CompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_COLOR), "  API Server Configuration  ",
                TitledBorder.LEFT, TitledBorder.TOP,
                formWrapper.getFont().deriveFont(Font.BOLD, 12f)
            ),
            BorderFactory.createEmptyBorder(8, 8, 8, 8)
        ));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0; gbc.gridy = 0;
        form.add(label("Host:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        hostField = new JTextField(host, 20);
        hostField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_COLOR),
            BorderFactory.createEmptyBorder(4, 6, 4, 6)));
        form.add(hostField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        form.add(label("Port:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        portField = new JTextField(String.valueOf(port), 10);
        portField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER_COLOR),
            BorderFactory.createEmptyBorder(4, 6, 4, 6)));
        form.add(portField, gbc);

        // Status + Apply button row
        statusLabel = new JLabel(" Running on " + host + ":" + port + " ");
        statusLabel.setOpaque(true);
        statusLabel.setBackground(BG_SUCCESS);
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 12f));
        statusLabel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ACCENT),
            BorderFactory.createEmptyBorder(4, 8, 4, 8)));

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
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
                    setStatus(" Running on " + newHost + ":" + newPort + " ", BG_SUCCESS, ACCENT);
                    log("Server restarted on " + newHost + ":" + newPort);
                }
            }.execute();
        });
        btnRow.add(applyBtn);
        btnRow.add(statusLabel);
        form.add(btnRow, gbc);

        formWrapper.add(form, BorderLayout.CENTER);
        configSection.add(formWrapper, BorderLayout.CENTER);

        // Hint section
        JPanel hintPanel = new JPanel(new BorderLayout());
        hintPanel.setBorder(new CompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDER_COLOR), "  Notes  ",
                TitledBorder.LEFT, TitledBorder.TOP,
                hintPanel.getFont().deriveFont(Font.BOLD, 12f)
            ),
            BorderFactory.createEmptyBorder(6, 8, 6, 8)
        ));
        JTextArea notes = new JTextArea(
            "Architecture: Claude Code  ->  Python MCP Server (stdio)  ->  This Extension (REST API)  ->  Burp Suite\n\n" +
            "Python MCP server config: set BURP_API_HOST and BURP_API_PORT environment variables to match.\n" +
            "Sessions, Findings, and Activity Log tabs show data unique to MCP integration (not duplicating Burp native tabs)."
        );
        notes.setEditable(false);
        notes.setBackground(SECTION_BG);
        notes.setFont(notes.getFont().deriveFont(11.5f));
        notes.setForeground(Color.DARK_GRAY);
        notes.setLineWrap(true);
        notes.setWrapStyleWord(true);
        notes.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        hintPanel.add(notes);
        configSection.add(hintPanel, BorderLayout.SOUTH);

        p.add(configSection, BorderLayout.CENTER);
        return p;
    }

    // ── Sessions Panel ──

    private JPanel buildSessionsPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout());
        top.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER_COLOR));
        JLabel title = sectionTitle("Active Attack Sessions");
        JLabel hint = hint("Created by Claude via MCP. Shows persistent session state not visible in Burp's native tabs.");
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

    // ── Findings Panel ──

    private JPanel buildFindingsPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout());
        top.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER_COLOR));
        JLabel title = sectionTitle("Manual Findings (saved by Claude)");
        JLabel hint2 = hint("Not duplicating Burp Scanner issues. These are Claude's manual vulnerability notes.");
        top.add(title, BorderLayout.WEST);
        top.add(hint2, BorderLayout.SOUTH);
        p.add(top, BorderLayout.NORTH);

        JTable table = new JTable(findingsModel);
        styleTable(table, new int[]{40, 80, 300, 250});

        // Color-code severity column
        table.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value, boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
                if (!sel && value != null) {
                    String sev = value.toString();
                    switch (sev) {
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

        p.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        btns.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER_COLOR));
        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refreshFindings());
        btns.add(refresh);
        p.add(btns, BorderLayout.SOUTH);

        return p;
    }

    private void refreshFindings() {
        findingsModel.setRowCount(0);
        if (findingsStore == null) return;
        for (Map<String, Object> f : findingsStore.getAll("")) {
            findingsModel.addRow(new Object[]{
                f.get("id"), f.get("severity"), f.get("title"), f.get("endpoint"),
            });
        }
    }

    // ── Activity Log Panel ──

    private JPanel buildLogPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout());
        top.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER_COLOR));
        JLabel title = sectionTitle("MCP Activity Log");
        JLabel hint3 = hint("Real-time stream of what Claude is doing via the extension API.");
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

    private void setStatus(String text, Color bg, Color border) {
        statusLabel.setText(" " + text + " ");
        statusLabel.setBackground(bg);
        statusLabel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(border),
            BorderFactory.createEmptyBorder(4, 8, 4, 8)));
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

    /** Thread-safe activity log entry. */
    public static void log(String message) {
        if (instance == null) return;
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        SwingUtilities.invokeLater(() -> {
            instance.logModel.addElement("[" + ts + "] " + message);
            while (instance.logModel.size() > 500) instance.logModel.remove(0);
        });
    }
}
