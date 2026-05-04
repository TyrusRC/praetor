package com.swissknife.handlers;

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
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

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
            handleStartScan(exchange);
        } else if (path.equals("/api/scanner/crawl") && "POST".equalsIgnoreCase(method)) {
            handleStartCrawl(exchange);
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
    private void handleStartScan(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);

        try {
            // Collect request-responses BEFORE creating audit (avoid leaked audits on validation failure)
            List<HttpRequestResponse> targets = new ArrayList<>();
            String description;

            // Option 1: Scan by proxy history index
            Object indexObj = body.get("index");
            if (indexObj instanceof Number n) {
                int index = n.intValue();
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                if (index < 0 || index >= history.size()) {
                    sendError(exchange, 404, "Index out of range");
                    return;
                }
                ProxyHttpRequestResponse item = history.get(index);
                targets.add(HttpRequestResponse.httpRequestResponse(
                    item.finalRequest(), item.originalResponse()));
                description = "Audit of proxy item #" + index + " (" + item.finalRequest().url() + ")";
            }
            // Option 2: Scan by single URL
            else if (body.containsKey("url")) {
                String url = (String) body.get("url");
                if (url == null || url.isEmpty()) {
                    sendError(exchange, 400, "Missing 'url' field");
                    return;
                }
                if (!api.scope().isInScope(url)) {
                    sendError(exchange, 403, "URL is out of scope: " + url, "out_of_scope",
                        "Use configure_scope/add_to_scope to include the host before scanning.");
                    return;
                }
                HttpService service = HttpService.httpService(url);
                HttpRequest request = HttpRequest.httpRequest(service, buildGetRequest(url, service.host()));
                targets.add(com.swissknife.http.ProxyTunnel.sendOrFallback(api, request));
                description = "Audit of " + url;
            }
            // Option 3: Scan multiple URLs
            else if (body.containsKey("urls")) {
                @SuppressWarnings("unchecked")
                List<String> urls = (List<String>) body.get("urls");
                List<String> oos = new ArrayList<>();
                for (String url : urls) {
                    if (!api.scope().isInScope(url)) { oos.add(url); continue; }
                    HttpService service = HttpService.httpService(url);
                    HttpRequest request = HttpRequest.httpRequest(service, buildGetRequest(url, service.host()));
                    targets.add(com.swissknife.http.ProxyTunnel.sendOrFallback(api, request));
                }
                if (!oos.isEmpty() && targets.isEmpty()) {
                    sendError(exchange, 403, "All URLs are out of scope: " + oos.size(), "out_of_scope", "");
                    return;
                }
                description = "Audit of " + urls.size() + " URLs (" + oos.size() + " skipped, out of scope)";
            } else {
                sendError(exchange, 400, "Provide 'url', 'urls', or 'index'");
                return;
            }

            // Create audit AFTER validation — prevents leaked audits on error paths
            AuditConfiguration config = AuditConfiguration.auditConfiguration(
                BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
            );
            Audit audit = api.scanner().startAudit(config);
            for (HttpRequestResponse rr : targets) {
                audit.addRequestResponse(rr);
            }

            int scanId = scanIdCounter.incrementAndGet();
            activeScans.add(new ScanRecord(scanId, description, audit, System.currentTimeMillis()));

            sendJson(exchange, JsonUtil.object(
                "status", "ok",
                "scan_id", scanId,
                "message", "Scan started: " + description
            ));

        } catch (Exception e) {
            sendError(exchange, 500, "Failed to start scan (requires Burp Professional): " + e.getMessage());
        }
    }

    /**
     * Start a crawl on seed URLs.
     * Body: {"urls": ["https://target.com"]} or {"url": "https://target.com"}
     */
    private void handleStartCrawl(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);

        try {
            List<String> seedUrls = new ArrayList<>();

            if (body.containsKey("url")) {
                seedUrls.add((String) body.get("url"));
            } else if (body.containsKey("urls")) {
                @SuppressWarnings("unchecked")
                List<String> urls = (List<String>) body.get("urls");
                seedUrls.addAll(urls);
            } else {
                sendError(exchange, 400, "Provide 'url' or 'urls'");
                return;
            }

            // Rule 1 (HARD) — Burp Pro will actively crawl whatever we hand it,
            // so every seed must be in scope. Reject the whole batch on the
            // first OOS hit; surfacing the bad URL is better than silently
            // crawling out-of-scope assets.
            for (String u : seedUrls) {
                if (!requireInScope(api, exchange, u)) return;
            }

            api.scanner().startCrawl(
                CrawlConfiguration.crawlConfiguration(seedUrls.toArray(new String[0]))
            );

            int scanId = scanIdCounter.incrementAndGet();
            String description = "Crawl of " + String.join(", ", seedUrls);
            activeScans.add(new ScanRecord(scanId, description, null, System.currentTimeMillis()));

            sendJson(exchange, JsonUtil.object(
                "status", "ok",
                "scan_id", scanId,
                "message", "Crawl started: " + description,
                "seed_urls", seedUrls
            ));
        } catch (Exception e) {
            sendError(exchange, 500, "Failed to start crawl (requires Burp Professional): " + e.getMessage());
        }
    }

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

    private String buildGetRequest(String url, String host) {
        String path;
        try {
            java.net.URI uri = new java.net.URI(url);
            path = uri.getRawPath();
            if (path == null || path.isEmpty()) path = "/";
            if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
        } catch (Exception e) {
            path = "/";
        }
        return "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n";
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

    private record ScanRecord(int id, String description, Audit audit, long startedAt) {}
}
