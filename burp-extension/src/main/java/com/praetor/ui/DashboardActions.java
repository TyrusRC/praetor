package com.praetor.ui;

import com.praetor.store.FindingsStore;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.Component;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.function.Consumer;

/** Dashboard finding-detail + export actions, split out of DashboardPanel. */
final class DashboardActions {

    private DashboardActions() {}

    static void showFindingDetail(Component parent, DefaultTableModel findingsModel, FindingsStore findingsStore, int tableRow) {
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

        FindingDetailDialog.show(parent, findingId, finding, FindingsStore.REMEDIATION);
    }

    // ── Exports ──

    static void exportOpenApiToFile(Component parent, String serverHost, int serverPort, Consumer<String> log) {
        String prefix = JOptionPane.showInputDialog(parent,
            "Enter the target base URL (e.g. https://example.com):",
            "Export OpenAPI", JOptionPane.QUESTION_MESSAGE);
        if (prefix == null || prefix.isBlank()) return;

        JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
        fc.setSelectedFile(new File("openapi-export.yaml"));
        if (fc.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return;
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
                    JOptionPane.showMessageDialog(parent,
                        "Exported " + outFile.getName() + " (" + yaml.length() + " bytes)",
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
                    log.accept("Exported OpenAPI to " + outFile.getAbsolutePath());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(parent,
                        "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    static void exportFindingsReport(Component parent, FindingsStore findingsStore, Consumer<String> log) {
        if (findingsStore == null || findingsStore.getAll("").isEmpty()) {
            JOptionPane.showMessageDialog(parent, "No findings to export.", "Export Report", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
        fc.setSelectedFile(new File("pentest-report.md"));
        if (fc.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return;
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
                    JOptionPane.showMessageDialog(parent,
                        "Exported " + outFile.getName(),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
                    log.accept("Exported report to " + outFile.getAbsolutePath());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(parent,
                        "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }
}
