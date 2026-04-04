package com.swissknife.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.util.function.BiConsumer;

/**
 * Configuration tab for Swiss Knife MCP extension.
 * Allows users to configure API server host and port.
 */
public class ConfigTab {

    private final JPanel panel;
    private final JTextField hostField;
    private final JTextField portField;
    private final JLabel statusLabel;
    private final MontoyaApi api;

    public ConfigTab(MontoyaApi api, String currentHost, int currentPort, String version,
                     BiConsumer<String, Integer> restartCallback) {
        this.api = api;
        panel = new JPanel();
        panel.setLayout(new BorderLayout(10, 10));

        // Title
        JPanel headerPanel = new JPanel(new BorderLayout());
        JLabel titleLabel = new JLabel("Swiss Knife MCP — Configuration");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
        headerPanel.add(titleLabel, BorderLayout.WEST);
        JLabel versionLabel = new JLabel("v" + version);
        versionLabel.setForeground(Color.GRAY);
        headerPanel.add(versionLabel, BorderLayout.EAST);
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));
        panel.add(headerPanel, BorderLayout.NORTH);

        // Form
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Host
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("API Host:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        hostField = new JTextField(currentHost, 20);
        formPanel.add(hostField, gbc);

        // Port
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("API Port:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        portField = new JTextField(String.valueOf(currentPort), 10);
        formPanel.add(portField, gbc);

        // Help text
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        JLabel helpLabel = new JLabel("Default: 127.0.0.1:8111 — Change and click Apply to restart the API server.");
        helpLabel.setFont(helpLabel.getFont().deriveFont(Font.ITALIC, 11f));
        helpLabel.setForeground(Color.GRAY);
        formPanel.add(helpLabel, gbc);

        // Python config hint
        gbc.gridy = 3;
        JLabel pythonHint = new JLabel("Python MCP server must match: set BURP_API_HOST and BURP_API_PORT env vars.");
        pythonHint.setFont(pythonHint.getFont().deriveFont(Font.ITALIC, 11f));
        pythonHint.setForeground(new Color(150, 120, 50));
        formPanel.add(pythonHint, gbc);

        // Status (must init before button listener captures it)
        statusLabel = new JLabel("Server running on " + currentHost + ":" + currentPort);
        statusLabel.setForeground(new Color(0, 128, 0));

        // Apply button
        gbc.gridy = 4; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.NONE; gbc.anchor = GridBagConstraints.WEST;
        JButton applyButton = new JButton("Apply & Restart Server");
        applyButton.addActionListener(e -> {
            String newHost = hostField.getText().trim();
            int newPort;
            try {
                newPort = Integer.parseInt(portField.getText().trim());
                if (newPort < 1 || newPort > 65535) throw new NumberFormatException();
            } catch (NumberFormatException ex) {
                statusLabel.setText("Invalid port number (1-65535)");
                statusLabel.setForeground(Color.RED);
                return;
            }
            if (newHost.isEmpty()) {
                statusLabel.setText("Host cannot be empty");
                statusLabel.setForeground(Color.RED);
                return;
            }

            statusLabel.setText("Restarting server on " + newHost + ":" + newPort + "...");
            statusLabel.setForeground(Color.BLUE);

            // Run restart in background to avoid blocking Swing EDT
            new SwingWorker<Void, Void>() {
                @Override
                protected Void doInBackground() {
                    restartCallback.accept(newHost, newPort);
                    return null;
                }
                @Override
                protected void done() {
                    statusLabel.setText("Server running on " + newHost + ":" + newPort);
                    statusLabel.setForeground(new Color(0, 128, 0));
                }
            }.execute();
        });
        formPanel.add(applyButton, gbc);

        // Status label (already initialized above)
        gbc.gridy = 5;
        formPanel.add(statusLabel, gbc);

        panel.add(formPanel, BorderLayout.CENTER);

        // Info panel at bottom
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
        JTextArea infoText = new JTextArea(
            "Swiss Knife MCP exposes a REST API for Claude Code integration.\n\n" +
            "Architecture: Claude Code → Python MCP Server (stdio) → This Extension (REST API) → Burp Suite\n\n" +
            "The API server only accepts connections from the configured host.\n" +
            "For security, keep it on 127.0.0.1 unless testing remotely."
        );
        infoText.setEditable(false);
        infoText.setBackground(panel.getBackground());
        infoText.setFont(infoText.getFont().deriveFont(12f));
        infoText.setForeground(Color.DARK_GRAY);
        infoPanel.add(infoText, BorderLayout.CENTER);
        panel.add(infoPanel, BorderLayout.SOUTH);
    }

    public JPanel getPanel() {
        return panel;
    }
}
