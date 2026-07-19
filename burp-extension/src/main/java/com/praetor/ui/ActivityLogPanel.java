package com.praetor.ui;

import javax.swing.*;
import java.awt.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Real-time MCP activity log panel. Holds the log list model and accepts
 * append calls from any thread via {@link #append(String)}.
 */
public class ActivityLogPanel extends JPanel {

    private static final int MAX_ENTRIES = 500;
    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final DefaultListModel<String> logModel = new DefaultListModel<>();

    public ActivityLogPanel() {
        super(new BorderLayout(0, 6));
        buildUi();
    }

    private void buildUi() {
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout());
        top.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UiHelpers.BORDER_COLOR));
        top.add(UiHelpers.sectionTitle("MCP Activity Log"), BorderLayout.WEST);
        top.add(UiHelpers.hint("Real-time stream of API calls from Claude via the MCP server."), BorderLayout.SOUTH);
        add(top, BorderLayout.NORTH);

        JList<String> logList = new JList<>(logModel);
        logList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        logList.setBackground(new Color(252, 252, 252));
        logList.setSelectionBackground(UiHelpers.BG_INFO);
        add(new JScrollPane(logList), BorderLayout.CENTER);

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        btns.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, UiHelpers.BORDER_COLOR));
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> logModel.clear());
        btns.add(clearBtn);
        add(btns, BorderLayout.SOUTH);
    }

    /** Thread-safe append. Trims to {@value #MAX_ENTRIES}. */
    public void append(String message) {
        String entry = "[" + LocalDateTime.now().format(TS_FMT) + "] " + message;
        SwingUtilities.invokeLater(() -> {
            logModel.addElement(entry);
            // Bulk removeRange — single-element removes were O(n) per call.
            int over = logModel.size() - MAX_ENTRIES;
            if (over > 0) logModel.removeRange(0, over - 1);
        });
    }
}
