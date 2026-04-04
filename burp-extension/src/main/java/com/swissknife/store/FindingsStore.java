package com.swissknife.store;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe in-memory store for pentest findings/notes.
 */
public class FindingsStore {

    private final List<Map<String, Object>> findings = new CopyOnWriteArrayList<>();
    private final AtomicInteger idCounter = new AtomicInteger(0);

    public Map<String, Object> add(String title, String description, String severity,
                                    String endpoint, String evidence) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("id", idCounter.incrementAndGet());
        finding.put("title", title);
        finding.put("description", description);
        finding.put("severity", severity != null ? severity : "INFO");
        finding.put("endpoint", endpoint != null ? endpoint : "");
        finding.put("evidence", evidence != null ? evidence : "");
        finding.put("timestamp", java.time.Instant.now().toString());
        findings.add(finding);
        return finding;
    }

    public List<Map<String, Object>> getAll(String filterEndpoint) {
        if (filterEndpoint == null || filterEndpoint.isEmpty()) {
            return Collections.unmodifiableList(findings);
        }
        return findings.stream()
            .filter(f -> {
                String ep = (String) f.get("endpoint");
                return ep != null && ep.contains(filterEndpoint);
            })
            .toList();
    }

    public String exportMarkdown() {
        StringBuilder sb = new StringBuilder();
        sb.append("# Pentest Findings Report\n\n");
        sb.append("Generated: ").append(java.time.Instant.now()).append("\n\n");
        sb.append("Total findings: ").append(findings.size()).append("\n\n---\n\n");

        // Group by severity
        Map<String, List<Map<String, Object>>> bySeverity = new LinkedHashMap<>();
        for (String sev : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) {
            bySeverity.put(sev, new ArrayList<>());
        }
        for (var f : findings) {
            String sev = ((String) f.get("severity")).toUpperCase();
            bySeverity.computeIfAbsent(sev, k -> new ArrayList<>()).add(f);
        }

        for (var entry : bySeverity.entrySet()) {
            if (entry.getValue().isEmpty()) continue;
            sb.append("## ").append(entry.getKey()).append(" (").append(entry.getValue().size()).append(")\n\n");
            for (var f : entry.getValue()) {
                sb.append("### ").append(f.get("title")).append("\n\n");
                sb.append("- **Endpoint:** ").append(f.get("endpoint")).append("\n");
                sb.append("- **Timestamp:** ").append(f.get("timestamp")).append("\n\n");
                sb.append(f.get("description")).append("\n\n");
                String evidence = (String) f.get("evidence");
                if (evidence != null && !evidence.isEmpty()) {
                    sb.append("**Evidence:**\n```\n").append(evidence).append("\n```\n\n");
                }
                sb.append("---\n\n");
            }
        }

        return sb.toString();
    }

    public String exportJson() {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < findings.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(com.swissknife.util.JsonUtil.toJson(findings.get(i)));
        }
        return sb.append("]").toString();
    }
}
