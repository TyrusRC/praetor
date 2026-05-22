package com.swissknife.ui;

import burp.api.montoya.MontoyaApi;
import com.swissknife.store.FindingsStore;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Supplier;

/**
 * Thin composer for the Swiss Knife MCP suite-tab UI. Wires the per-panel
 * classes ({@link DashboardPanel}, {@link SessionsPanel}, {@link ActivityLogPanel})
 * into a single {@link JTabbedPane}, owns the dashboard auto-refresh timer,
 * and exposes the static {@link #log(String)} entry point used by handlers
 * throughout the extension.
 */
public class ConfigTab {

    private static volatile ConfigTab instance;

    private final JPanel panel;
    private final DashboardPanel dashboardPanel;
    private final ActivityLogPanel activityLogPanel;
    private final javax.swing.Timer refreshTimer;

    public ConfigTab(MontoyaApi api, String currentHost, int currentPort, String version,
                     BiConsumer<String, Integer> restartCallback,
                     Supplier<List<String[]>> sessionSupplier, FindingsStore findingsStore) {
        this.activityLogPanel = new ActivityLogPanel();
        this.dashboardPanel = new DashboardPanel(
            currentHost, currentPort, version, restartCallback,
            sessionSupplier, findingsStore, activityLogPanel::append);
        SessionsPanel sessionsPanel = new SessionsPanel(sessionSupplier);

        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(tabs.getFont().deriveFont(Font.BOLD, 12f));
        tabs.addTab(" Dashboard ", dashboardPanel);
        tabs.addTab(" Sessions ", sessionsPanel);
        tabs.addTab(" Activity Log ", activityLogPanel);

        panel = new JPanel(new BorderLayout());
        panel.add(tabs, BorderLayout.CENTER);

        // Auto-refresh dashboard every 5 seconds.
        refreshTimer = new javax.swing.Timer(5000, e -> dashboardPanel.refreshStats());
        refreshTimer.start();

        // Publish the singleton LAST so log() callers never observe a
        // partially-constructed object (activityLogPanel still null, etc.).
        // instance is volatile, so this write happens-before any later read.
        instance = this;
    }

    public JPanel getPanel() { return panel; }

    /** Stop auto-refresh timer. Call on extension unload to prevent leaks. */
    public void stop() {
        refreshTimer.stop();
    }

    /** Thread-safe activity log entry. No-op if no ConfigTab is mounted. */
    public static void log(String message) {
        ConfigTab current = instance; // read volatile once
        if (current == null) return;
        current.activityLogPanel.append(message);
    }
}
