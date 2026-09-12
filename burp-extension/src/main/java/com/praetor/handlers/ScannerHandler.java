package com.praetor.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.praetor.http.HttpExchange;
import com.praetor.server.BaseHandler;
import com.praetor.util.JsonUtil;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * GET  /api/scanner/findings?severity=HIGH&confidence=CERTAIN&limit=100
 * POST /api/scanner/scan      - start active scan on URL or proxy history item
 * POST /api/scanner/crawl     - start crawl on seed URLs
 * GET  /api/scanner/status    - get status of active scans
 */
public class ScannerHandler extends BaseHandler {

    private final MontoyaApi api;
    private final List<ScanRecord> activeScans = new CopyOnWriteArrayList<>();
    private final AtomicInteger scanIdCounter = new AtomicInteger(0);

    public ScannerHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        if (path.equals("/api/scanner/scan") && "POST".equalsIgnoreCase(method)) {
            new ScanLauncher(api, activeScans, scanIdCounter).startScan(exchange, readJsonBody(exchange));
        } else if (path.equals("/api/scanner/crawl") && "POST".equalsIgnoreCase(method)) {
            new ScanLauncher(api, activeScans, scanIdCounter).startCrawl(exchange, readJsonBody(exchange));
        } else if (path.equals("/api/scanner/status") && "GET".equalsIgnoreCase(method)) {
            handleStatus(exchange);
        } else if (path.equals("/api/scanner/findings")) {
            handleFindings(exchange);
        } else if (path.equals("/api/scanner/findings/new") && "GET".equalsIgnoreCase(method)) {
            handleNewFindings(exchange);
        } else if (path.matches("/api/scanner/scan/\\d+") && "DELETE".equalsIgnoreCase(method)) {
            handleCancelScan(exchange, path);
        } else {
            sendError(exchange, 404, "Not found");
        }
    }

    /**
     * Start an active scan/audit on specific requests.
     * Body: {"url": "https://target.com/path"} or {"index": 42} or {"urls": ["url1","url2"]}
     */

    /**
     * Get status of active and completed scans.
     */
    private void handleStatus(HttpExchange exchange) throws Exception {
        List<Map<String, Object>> items = new ArrayList<>();

        for (ScanRecord record : activeScans) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("scan_id", record.id);
            entry.put("description", record.description);
            entry.put("started_at", new Date(record.startedAt).toString());

            if (record.audit != null) {
                try {
                    entry.put("request_count", record.audit.requestCount());
                    entry.put("insertion_point_count", record.audit.insertionPointCount());
                    entry.put("issue_count", record.audit.issues().size());
                    entry.put("error_count", record.audit.errorCount());
                    entry.put("status_message", record.audit.statusMessage());
                } catch (Exception e) {
                    entry.put("status_message", "Error reading status: " + e.getMessage());
                }
            }

            items.add(entry);
        }

        // Also report total scanner findings
        int totalFindings;
        try {
            totalFindings = api.siteMap().issues().size();
        } catch (Exception e) {
            totalFindings = -1;
        }

        sendJson(exchange, JsonUtil.object(
            "active_scans", items.size(),
            "scans", items,
            "total_scanner_findings", totalFindings
        ));
    }

    /**
     * Get scanner/audit findings.
     */
    private void handleFindings(HttpExchange exchange) throws Exception {
        Map<String, String> params = queryParams(exchange);
        String filterSeverity = params.getOrDefault("severity", "").toUpperCase();
        String filterConfidence = params.getOrDefault("confidence", "").toUpperCase();
        int limit = intParam(params, "limit", 100);

        List<AuditIssue> issues;
        try {
            issues = api.siteMap().issues();
        } catch (Exception e) {
            sendError(exchange, 500, "Scanner not available (requires Burp Professional): " + e.getMessage());
            return;
        }

        List<Map<String, Object>> items = new ArrayList<>();
        int count = 0;

        for (AuditIssue issue : issues) {
            if (count >= limit) break;

            String severity = issue.severity().toString();
            String confidence = issue.confidence().toString();

            if (!filterSeverity.isEmpty() && !severity.equalsIgnoreCase(filterSeverity)) continue;
            if (!filterConfidence.isEmpty() && !confidence.equalsIgnoreCase(filterConfidence)) continue;

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", issue.name());
            entry.put("severity", severity);
            entry.put("confidence", confidence);
            entry.put("base_url", issue.baseUrl());
            entry.put("detail", truncate(issue.detail(), 2000));
            entry.put("remediation", truncate(issue.remediation(), 1000));

            var reqResps = issue.requestResponses();
            List<Map<String, Object>> evidence = new ArrayList<>();
            for (var rr : reqResps) {
                Map<String, Object> ev = new LinkedHashMap<>();
                ev.put("url", rr.request().url());
                ev.put("method", rr.request().method());
                ev.put("status_code", rr.response() != null ? rr.response().statusCode() : 0);
                evidence.add(ev);
            }
            entry.put("evidence", evidence);
            items.add(entry);
            count++;
        }

        sendJson(exchange, JsonUtil.object(
            "total_findings", issues.size(),
            "returned", items.size(),
            "items", items
        ));
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "... (truncated)";
    }


    /**
     * Cancel/remove an active scan from tracking.
     * DELETE /api/scanner/scan/{id}
     * Note: Montoya API Audit does not expose cancel/delete — we remove from our tracking list.
     */
    private void handleCancelScan(HttpExchange exchange, String path) throws Exception {
        int scanId = extractScanId(path);
        if (scanId < 0) {
            sendError(exchange, 400, "Invalid scan id in path: " + path);
            return;
        }
        ScanRecord record = findScan(scanId);
        if (record == null) {
            sendError(exchange, 404, "Scan #" + scanId + " not found");
            return;
        }
        activeScans.remove(record);
        sendOk(exchange, "Scan #" + scanId + " removed from tracking");
    }

    // pause / resume removed: Burp's Montoya API does not expose them and
    // the corresponding Python tools were dropped in v0.5.

    /**
     * Get new scanner findings since a given count.
     * GET /api/scanner/findings/new?since=N
     */
    private void handleNewFindings(HttpExchange exchange) throws Exception {
        Map<String, String> params = queryParams(exchange);
        int since = intParam(params, "since", 0);

        List<AuditIssue> issues;
        try {
            issues = api.siteMap().issues();
        } catch (Exception e) {
            sendError(exchange, 500, "Scanner not available: " + e.getMessage());
            return;
        }

        int total = issues.size();
        if (since >= total) {
            sendJson(exchange, JsonUtil.object(
                "total", total,
                "new_count", 0,
                "items", new ArrayList<>()
            ));
            return;
        }

        List<Map<String, Object>> items = new ArrayList<>();
        for (int i = since; i < total; i++) {
            AuditIssue issue = issues.get(i);
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("index", i);
            entry.put("name", issue.name());
            entry.put("severity", issue.severity().toString());
            entry.put("confidence", issue.confidence().toString());
            entry.put("base_url", issue.baseUrl());
            entry.put("detail", truncate(issue.detail(), 500));
            items.add(entry);
        }

        sendJson(exchange, JsonUtil.object(
            "total", total,
            "new_count", items.size(),
            "since", since,
            "items", items
        ));
    }

    private int extractScanId(String path) {
        String[] parts = path.split("/");
        for (int i = parts.length - 1; i >= 0; i--) {
            try {
                return Integer.parseInt(parts[i]);
            } catch (NumberFormatException ignored) {}
        }
        return -1;
    }

    private ScanRecord findScan(int scanId) {
        for (ScanRecord record : activeScans) {
            if (record.id == scanId) return record;
        }
        return null;
    }

    record ScanRecord(int id, String description, Audit audit, long startedAt) {}
}
