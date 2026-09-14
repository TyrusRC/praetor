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
                // Isolate each Montoya call: some builds throw "Currently
                // unsupported" on Audit.issues()/statusMessage(). A single
                // failing call must not blank the counters that DO work — and
                // must not stop statusMessage() (the completion signal) from
                // being tried just because issues() threw first.
                final ScanRecord r = record;
                Object rc = tryGet(() -> r.audit.requestCount());
                if (rc != null) entry.put("request_count", rc);
                Object ipc = tryGet(() -> r.audit.insertionPointCount());
                if (ipc != null) entry.put("insertion_point_count", ipc);
                Object ec = tryGet(() -> r.audit.errorCount());
                if (ec != null) entry.put("error_count", ec);
                Object isc = tryGet(() -> r.audit.issues().size());
                if (isc != null) entry.put("issue_count", isc);
                Object sm = tryGet(() -> r.audit.statusMessage());
                entry.put("status_message", sm != null ? sm
                    : "live status text unsupported by this Burp build — infer progress from request_count");
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
        String filterHost = params.getOrDefault("host", "");
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
        int matched = 0;

        for (AuditIssue issue : issues) {
            String severity = issue.severity().toString();
            String confidence = issue.confidence().toString();

            if (!issueMatches(filterSeverity, filterConfidence, filterHost,
                              severity, confidence, issue.baseUrl())) continue;
            matched++;
            if (count >= limit) continue;

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
            "matched_filter", matched,
            "returned", items.size(),
            "items", items
        ));
    }

    /**
     * Pure filter predicate for scanner findings. Empty filter = match-all;
     * severity/confidence are case-insensitive exact matches; host is a
     * substring match against the issue's base URL (null base URL never
     * matches a non-empty host filter). Package-private for unit testing.
     */
    static boolean issueMatches(String filterSeverity, String filterConfidence,
                                String filterHost, String severity,
                                String confidence, String baseUrl) {
        if (!filterSeverity.isEmpty() && !severity.equalsIgnoreCase(filterSeverity)) return false;
        if (!filterConfidence.isEmpty() && !confidence.equalsIgnoreCase(filterConfidence)) return false;
        if (!filterHost.isEmpty() && (baseUrl == null || !baseUrl.contains(filterHost))) return false;
        return true;
    }

    /** Supplier that may throw — for isolating individual Montoya calls. */
    @FunctionalInterface
    interface ThrowingSupplier {
        Object get() throws Exception;
    }

    /** Run {@code s}, returning its value or null if it throws (e.g. a Montoya
     *  call unsupported in the running Burp build). */
    static Object tryGet(ThrowingSupplier s) {
        try {
            return s.get();
        } catch (Exception e) {
            return null;
        }
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
