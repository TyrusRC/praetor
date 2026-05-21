package com.swissknife.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.function.Supplier;

/**
 * Active attack sessions panel. Re-reads the supplier on every refresh so
 * a server restart still surfaces fresh session state.
 */
public class SessionsPanel extends JPanel {

    private final Supplier<List<String[]>> sessionSupplier;
    private final DefaultTableModel sessionsModel;

    public SessionsPanel(Supplier<List<String[]>> sessionSupplier) {
        super(new BorderLayout(0, 6));
        this.sessionSupplier = sessionSupplier;
        this.sessionsModel = new DefaultTableModel(
            new String[]{"Session", "Base URL", "Cookies", "Variables", "Auth"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        buildUi();
    }

    private void buildUi() {
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout());
        top.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UiHelpers.BORDER_COLOR));
        top.add(UiHelpers.sectionTitle("Active Attack Sessions"), BorderLayout.WEST);
        top.add(UiHelpers.hint("Persistent session state created by Claude — cookies, auth tokens, extracted variables."),
            BorderLayout.SOUTH);
        add(top, BorderLayout.NORTH);

        JTable table = new JTable(sessionsModel);
        UiHelpers.styleTable(table, new int[]{120, 250, 60, 70, 50});
        add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        btns.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, UiHelpers.BORDER_COLOR));
        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refresh());
        btns.add(refresh);
        add(btns, BorderLayout.SOUTH);
    }

    private void refresh() {
        sessionsModel.setRowCount(0);
        if (sessionSupplier == null) return;
        for (String[] row : sessionSupplier.get()) {
            sessionsModel.addRow(row);
        }
    }
}
