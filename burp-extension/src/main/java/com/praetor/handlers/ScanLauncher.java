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
import com.praetor.attack.AttackScope;
import com.praetor.http.HttpExchange;
import com.praetor.http.HttpResponses;
import com.praetor.util.JsonUtil;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Starts active scans / crawls (Burp Pro), split out of ScannerHandler. */
final class ScanLauncher {

    private final MontoyaApi api;
    private final List<ScannerHandler.ScanRecord> activeScans;
    private final AtomicInteger scanIdCounter;

    ScanLauncher(MontoyaApi api, List<ScannerHandler.ScanRecord> activeScans, AtomicInteger scanIdCounter) {
        this.api = api;
        this.activeScans = activeScans;
        this.scanIdCounter = scanIdCounter;
    }

    void startScan(HttpExchange exchange, Map<String, Object> body) throws Exception {

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
                    HttpResponses.sendError(exchange, 404, "Index out of range");
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
                    HttpResponses.sendError(exchange, 400, "Missing 'url' field");
                    return;
                }
                if (!api.scope().isInScope(url)) {
                    HttpResponses.sendError(exchange, 403, "URL is out of scope: " + url, "out_of_scope",
                        "Use configure_scope/add_to_scope to include the host before scanning.");
                    return;
                }
                HttpService service = HttpService.httpService(url);
                HttpRequest request = HttpRequest.httpRequest(service, buildGetRequest(url, service.host()));
                HttpRequestResponse seed = com.praetor.http.ProxyTunnel.sendOrFallback(api, request);
                if (seed == null) {
                    String why = com.praetor.http.ProxyTunnel.lastSendError();
                    HttpResponses.sendError(exchange, 502,
                        "Failed to fetch seed request for scan" + (why.isEmpty() ? "" : " — " + why),
                        "send_failed",
                        "Verify the target is reachable and Burp proxy listener is up.");
                    return;
                }
                targets.add(seed);
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
                    HttpRequestResponse seed = com.praetor.http.ProxyTunnel.sendOrFallback(api, request);
                    // Skip unreachable seeds — don't NPE inside audit.addRequestResponse.
                    if (seed != null) targets.add(seed);
                }
                if (!oos.isEmpty() && targets.isEmpty()) {
                    HttpResponses.sendError(exchange, 403, "All URLs are out of scope: " + oos.size(), "out_of_scope", "");
                    return;
                }
                description = "Audit of " + urls.size() + " URLs (" + oos.size() + " skipped, out of scope)";
            } else {
                HttpResponses.sendError(exchange, 400, "Provide 'url', 'urls', or 'index'");
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
            activeScans.add(new ScannerHandler.ScanRecord(scanId, description, audit, System.currentTimeMillis()));

            HttpResponses.sendJson(exchange, JsonUtil.object(
                "status", "ok",
                "scan_id", scanId,
                "message", "Scan started: " + description
            ));

        } catch (Exception e) {
            HttpResponses.sendError(exchange, 500, "Failed to start scan (requires Burp Professional): " + e.getMessage());
        }
    }

    /**
     * Start a crawl on seed URLs.
     * Body: {"urls": ["https://target.com"]} or {"url": "https://target.com"}
     */
    void startCrawl(HttpExchange exchange, Map<String, Object> body) throws Exception {

        try {
            List<String> seedUrls = new ArrayList<>();

            if (body.containsKey("url")) {
                seedUrls.add((String) body.get("url"));
            } else if (body.containsKey("urls")) {
                @SuppressWarnings("unchecked")
                List<String> urls = (List<String>) body.get("urls");
                seedUrls.addAll(urls);
            } else {
                HttpResponses.sendError(exchange, 400, "Provide 'url' or 'urls'");
                return;
            }

            // Rule 1 (HARD) — Burp Pro will actively crawl whatever we hand it,
            // so every seed must be in scope. Reject the whole batch on the
            // first OOS hit; surfacing the bad URL is better than silently
            // crawling out-of-scope assets.
            for (String u : seedUrls) {
                if (!AttackScope.requireInScope(api, exchange, u)) return;
            }

            api.scanner().startCrawl(
                CrawlConfiguration.crawlConfiguration(seedUrls.toArray(new String[0]))
            );

            int scanId = scanIdCounter.incrementAndGet();
            String description = "Crawl of " + String.join(", ", seedUrls);
            activeScans.add(new ScannerHandler.ScanRecord(scanId, description, null, System.currentTimeMillis()));

            HttpResponses.sendJson(exchange, JsonUtil.object(
                "status", "ok",
                "scan_id", scanId,
                "message", "Crawl started: " + description,
                "seed_urls", seedUrls
            ));
        } catch (Exception e) {
            HttpResponses.sendError(exchange, 500, "Failed to start crawl (requires Burp Professional): " + e.getMessage());
        }
    }

    private static String buildGetRequest(String url, String host) {
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
}
