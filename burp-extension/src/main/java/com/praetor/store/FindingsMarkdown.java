package com.praetor.store;

import java.util.*;

/** Markdown projection of findings, split out of FindingsStore (reads finding maps only). */
final class FindingsMarkdown {

    private FindingsMarkdown() {}

    static String export(List<Map<String, Object>> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Penetration Test Report\n\n");
        sb.append("**Generated:** ").append(java.time.Instant.now()).append("\n");
        sb.append("**Total Findings:** ").append(findings.size()).append("\n\n");

        // Group by severity
        Map<String, List<Map<String, Object>>> bySeverity = new LinkedHashMap<>();
        for (String sev : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) {
            bySeverity.put(sev, new ArrayList<>());
        }
        for (var f : findings) {
            String sev = String.valueOf(f.getOrDefault("severity", "INFO")).toUpperCase();
            bySeverity.computeIfAbsent(sev, k -> new ArrayList<>()).add(f);
        }

        // Executive summary
        sb.append("## Executive Summary\n\n");
        String highestSeverity = "None";
        for (String sev : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) {
            int count = bySeverity.getOrDefault(sev, List.of()).size();
            sb.append("- ").append(sev.charAt(0)).append(sev.substring(1).toLowerCase())
              .append(": ").append(count).append("\n");
            if (count > 0 && "None".equals(highestSeverity)) {
                highestSeverity = sev;
            }
        }
        sb.append("\n**Overall Risk Rating:** ").append(highestSeverity).append("\n\n");

        // Vulnerability summary table
        sb.append("## Vulnerability Summary\n\n");
        sb.append("| # | Severity | Title | Endpoint | CWE |\n");
        sb.append("|---|----------|-------|----------|-----|\n");
        int idx = 1;
        for (String sev : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) {
            for (var f : bySeverity.getOrDefault(sev, List.of())) {
                String cwe = inferCwe(f);
                sb.append("| ").append(idx++).append(" | ").append(sev)
                  .append(" | ").append(f.get("title"))
                  .append(" | ").append(f.get("endpoint"))
                  .append(" | ").append(cwe)
                  .append(" |\n");
            }
        }
        sb.append("\n");

        // Detailed findings
        sb.append("## Detailed Findings\n\n");
        for (String sev : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) {
            for (var f : bySeverity.getOrDefault(sev, List.of())) {
                String cwe = inferCwe(f);
                sb.append("### [").append(sev).append("] ").append(f.get("title")).append("\n\n");
                sb.append("- **Endpoint:** ").append(f.get("endpoint")).append("\n");
                if (!cwe.isEmpty()) {
                    sb.append("- **CWE:** ").append(cwe).append("\n");
                }
                sb.append("- **Timestamp:** ").append(f.get("timestamp")).append("\n\n");
                sb.append(f.get("description")).append("\n\n");
                String evidence = (String) f.get("evidence");
                if (evidence != null && !evidence.isEmpty()) {
                    sb.append("**Evidence:**\n```\n").append(evidence).append("\n```\n\n");
                }
                String remediation = FindingsStore.REMEDIATION.getOrDefault(cwe, "");
                if (!remediation.isEmpty()) {
                    sb.append("**Remediation:** ").append(remediation).append("\n\n");
                }
                sb.append("---\n\n");
            }
        }

        // Methodology
        sb.append("## Methodology\n\n");
        sb.append("Testing performed using Praetor MCP with Claude Code.\n");
        sb.append("Tools: Burp Suite Professional, adaptive knowledge-based scanning.\n");

        return sb.toString();
    }

    /** Infer CWE from a finding's title, description, or evidence fields. */
    static String inferCwe(Map<String, Object> finding) {
        String title = String.valueOf(finding.getOrDefault("title", "")).toLowerCase();
        String evidence = String.valueOf(finding.getOrDefault("evidence", "")).toLowerCase();
        String combined = title + " " + evidence;

        // Check for explicit CWE in evidence (auto-probe saves "CWE-XX" there)
        for (String cwe : FindingsStore.REMEDIATION.keySet()) {
            if (combined.contains(cwe.toLowerCase())) {
                return cwe;
            }
        }

        // Keyword-based inference
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

}
