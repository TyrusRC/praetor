package com.swissknife.analysis;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Pure helper functions extracted from SessionHandler to keep the dispatcher
 * file readable. Everything in here is stateless except {@link #PROBE_MARKER_SEQ},
 * which is the same shared monotonic counter SessionHandler uses for collision-
 * free probe markers.
 */
public final class SessionProbeHelpers {

    /**
     * Monotonic counter so probe markers stay unique even within the same
     * millisecond. Shared across SessionHandler.handleAutoProbe (auto_probe
     * path) and {@link #selectAdaptivePayloads} (probe-endpoint path) so the
     * two paths can never collide on the same marker.
     */
    public static final AtomicLong PROBE_MARKER_SEQ = new AtomicLong();

    private SessionProbeHelpers() {}

    /**
     * Adaptive payload selection. Returns SQLi/SSTI/path-traversal candidates
     * tuned to the detected tech stack, plus a unique XSS marker payload.
     */
    public static List<String> selectAdaptivePayloads(List<String> techs, String parameter) {
        List<String> payloads = new ArrayList<>();
        boolean isNumeric = parameter.matches("(?i)id|num|page|limit|offset|count|idx|index");

        // SQLi payloads adapted to tech
        if (techs.contains("IIS") || techs.contains("ASP.NET")) {
            payloads.add(isNumeric ? "1'" : "test'");
            payloads.add(isNumeric ? "1; WAITFOR DELAY '0:0:2'--" : "'; WAITFOR DELAY '0:0:2'--");
            payloads.add(isNumeric ? "1 AND 1=CONVERT(int,@@version)--" : "' AND 1=CONVERT(int,@@version)--");
        } else if (techs.contains("PHP") || techs.contains("Apache")) {
            payloads.add(isNumeric ? "1'" : "test'");
            payloads.add(isNumeric ? "1 AND SLEEP(2)-- -" : "' AND SLEEP(2)-- -");
            payloads.add(isNumeric ? "1 UNION SELECT NULL-- -" : "' UNION SELECT NULL-- -");
        } else if (techs.contains("Django") || techs.contains("Flask")) {
            payloads.add(isNumeric ? "1'" : "test'");
            payloads.add("{{7*7}}");
        } else {
            payloads.add(isNumeric ? "1'" : "test'");
            payloads.add(isNumeric ? "1 OR 1=1-- -" : "' OR '1'='1");
        }

        // XSS probe — base36 ms+seq, unique within the same millisecond.
        long seq = PROBE_MARKER_SEQ.incrementAndGet();
        payloads.add("<xss_probe_" + Long.toString(System.currentTimeMillis(), 36)
            + "_" + Long.toString(seq, 36) + ">");

        if (parameter.matches("(?i)file|path|item|page|template|include|url|src|doc|dir")) {
            payloads.add("../../../etc/passwd");
        }

        return payloads;
    }

    /**
     * Multi-variant reflection detection: raw, URL-encoded, HTML-entity,
     * JS-escaped. Returns the first variant that matched plus its context.
     */
    public static Map<String, Object> detectReflection(String payload, String responseBody) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (payload == null || responseBody == null || payload.isEmpty()) return result;

        if (responseBody.contains(payload)) {
            result.put("type", "raw");
            result.put("context", guessReflectionContext(payload, responseBody));
            return result;
        }
        String urlEnc = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8);
        if (!urlEnc.equals(payload) && responseBody.contains(urlEnc)) {
            result.put("type", "url_encoded");
            return result;
        }
        String htmlEnc = payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
        if (!htmlEnc.equals(payload) && responseBody.contains(htmlEnc)) {
            result.put("type", "html_encoded");
            return result;
        }
        String jsEnc = payload.replace("\\", "\\\\").replace("'", "\\'").replace("\"", "\\\"");
        if (!jsEnc.equals(payload) && responseBody.contains(jsEnc)) {
            result.put("type", "js_escaped");
            return result;
        }
        return result;
    }

    /** Heuristic: where is the payload reflected? javascript / attribute / html_comment / html_body. */
    public static String guessReflectionContext(String payload, String body) {
        int idx = body.indexOf(payload);
        if (idx < 0) return "unknown";
        String before = body.substring(Math.max(0, idx - 50), idx).toLowerCase();
        if (before.contains("<script") || before.contains("javascript:")) return "javascript";
        if (before.contains("value=") || before.contains("href=") || before.contains("src=")) return "attribute";
        if (before.contains("<!--")) return "html_comment";
        return "html_body";
    }

    /**
     * Detect vendor / template / shell / parser error patterns in a response body.
     * Returns a list of {type, [database], description, confidence} maps.
     *
     * Tightened from the original: path-traversal requires root:x:0 / shadow /
     * boot.ini structure (was matching every IIS 404 page that mentioned
     * c:\windows). SSTI requires an actual engine name; bare "template"+"error"
     * was misclassifying every "Email Template Error" CMS page.
     */
    public static List<Map<String, Object>> detectErrorPatterns(String body, int status) {
        List<Map<String, Object>> patterns = new ArrayList<>();
        String lower = body.toLowerCase();

        String[][] sqlPatterns = {
            {"mssql", "unclosed quotation mark", "high"}, {"mssql", "incorrect syntax near", "high"},
            {"mssql", "microsoft ole db", "high"}, {"mssql", "microsoft sql server", "medium"},
            {"mssql", "sql server driver", "medium"}, {"mssql", "odbc sql server", "medium"},
            {"mysql", "you have an error in your sql syntax", "high"}, {"mysql", "warning: mysql", "medium"},
            {"mysql", "mysqli_", "medium"}, {"mysql", "mysql_fetch", "medium"},
            {"postgresql", "pg_query", "high"}, {"postgresql", "psql error", "high"},
            {"postgresql", "unterminated quoted string", "high"},
            {"oracle", "ora-", "high"}, {"oracle", "oracleexception", "high"},
            {"sqlite", "sqlite3.", "high"}, {"sqlite", "unrecognized token", "high"},
            {"generic", "sql syntax", "medium"}, {"generic", "database error", "medium"},
            {"generic", "query failed", "medium"}, {"generic", "sql exception", "medium"},
        };
        for (String[] p : sqlPatterns) {
            if (lower.contains(p[1])) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("type", "sqli"); m.put("database", p[0]); m.put("description", p[1]); m.put("confidence", p[2]);
                patterns.add(m); break;
            }
        }

        if (lower.contains("root:x:0") || lower.contains("/etc/shadow")
            || (lower.contains("[boot loader]") && lower.contains("[operating systems]"))
            || lower.contains("for 16-bit app support")) {
            patterns.add(Map.of("type", "path_traversal", "description", "System file contents leaked", "confidence", "high"));
        }

        if (lower.contains("jinja2") || lower.contains("freemarker") || lower.contains("velocity") ||
            lower.contains("thymeleaf") || lower.contains("twig") || lower.contains("mako") ||
            lower.contains("smarty") || lower.contains("erb") || lower.contains("pug") || lower.contains("nunjucks")) {
            patterns.add(Map.of("type", "ssti", "description", "Template engine error detected", "confidence", "high"));
        }

        if (lower.contains("uid=") && lower.contains("gid=") || lower.contains("command not found") ||
            lower.contains("sh:") || lower.contains("bash:")) {
            patterns.add(Map.of("type", "rce", "description", "Command execution evidence", "confidence", "high"));
        }

        if ((lower.contains("<!entity") || lower.contains("<!doctype")) && lower.contains("system")) {
            patterns.add(Map.of("type", "xxe", "description", "XXE processing detected", "confidence", "medium"));
        }

        if (lower.contains("connection refused") || lower.contains("connection timed out") || lower.contains("unreachable")) {
            patterns.add(Map.of("type", "ssrf", "description", "SSRF connection attempt", "confidence", "medium"));
        }

        if (lower.contains("stack trace") || lower.contains("at java.") || lower.contains("at system.") ||
            lower.contains("traceback") || lower.contains("exception in") || lower.contains("at line")) {
            patterns.add(Map.of("type", "info_disclosure", "description", "Stack trace leaked", "confidence", "high"));
        }

        return patterns;
    }
}
