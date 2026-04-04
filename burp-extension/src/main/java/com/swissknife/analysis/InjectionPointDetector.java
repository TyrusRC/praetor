package com.swissknife.analysis;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.*;

/**
 * Identify potential injection points in a request/response pair.
 * Checks for reflected parameters, common injection-prone param names,
 * and interesting response characteristics.
 */
public final class InjectionPointDetector {

    private InjectionPointDetector() {}

    // Parameter names commonly vulnerable to injection
    private static final Set<String> SQLI_PARAM_NAMES = Set.of(
        "id", "uid", "user_id", "item_id", "product_id", "cat_id", "category",
        "page", "sort", "order", "orderby", "sortby", "filter", "where",
        "query", "search", "q", "keyword", "table", "column", "field",
        "limit", "offset", "from", "to", "start", "end", "year", "month", "day"
    );

    private static final Set<String> XSS_PARAM_NAMES = Set.of(
        "name", "user", "username", "email", "comment", "message", "body",
        "title", "subject", "description", "text", "content", "value",
        "input", "query", "q", "search", "keyword", "url", "link",
        "redirect", "return", "next", "callback", "ref", "referrer"
    );

    private static final Set<String> PATH_TRAVERSAL_NAMES = Set.of(
        "file", "filename", "path", "filepath", "document", "folder", "dir",
        "directory", "template", "page", "include", "require", "load",
        "read", "download", "attachment", "image", "img", "src"
    );

    private static final Set<String> SSRF_PARAM_NAMES = Set.of(
        "url", "uri", "link", "href", "src", "source", "dest", "destination",
        "redirect", "return", "next", "target", "proxy", "fetch", "request",
        "callback", "webhook", "api", "endpoint", "host", "domain"
    );

    private static final Set<String> CMD_INJECTION_NAMES = Set.of(
        "cmd", "command", "exec", "execute", "run", "ping", "ip", "host",
        "hostname", "domain", "address", "server", "process", "daemon"
    );

    public static Map<String, Object> detect(HttpRequest request, HttpResponse response) {
        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> injectionPoints = new ArrayList<>();

        String responseBody = response != null ? response.bodyToString() : "";
        String responseLower = responseBody.toLowerCase();

        for (HttpParameter param : request.parameters()) {
            String name = param.name().toLowerCase();
            String value = param.value();
            String location = param.type().toString().toLowerCase();

            Map<String, Object> point = new LinkedHashMap<>();
            point.put("name", param.name());
            point.put("value", value.length() > 200 ? value.substring(0, 200) + "..." : value);
            point.put("location", location);

            List<String> potentialVulns = new ArrayList<>();

            // Check if parameter value is reflected in response
            if (!value.isEmpty() && value.length() > 2 && responseBody.contains(value)) {
                potentialVulns.add("REFLECTED (value appears in response - test XSS/injection)");
            }

            // Check parameter name against known vulnerable patterns
            if (SQLI_PARAM_NAMES.contains(name)) potentialVulns.add("SQL_INJECTION (common SQLi parameter name)");
            if (XSS_PARAM_NAMES.contains(name)) potentialVulns.add("XSS (common XSS parameter name)");
            if (PATH_TRAVERSAL_NAMES.contains(name)) potentialVulns.add("PATH_TRAVERSAL (file-related parameter)");
            if (SSRF_PARAM_NAMES.contains(name)) potentialVulns.add("SSRF (URL/network parameter)");
            if (CMD_INJECTION_NAMES.contains(name)) potentialVulns.add("COMMAND_INJECTION (command-related parameter)");

            // Check value patterns
            if (value.matches("\\d+")) potentialVulns.add("IDOR (numeric ID - test authorization)");
            if (value.startsWith("http://") || value.startsWith("https://")) potentialVulns.add("SSRF (URL value)");
            if (value.contains("/") || value.contains("\\")) potentialVulns.add("PATH_TRAVERSAL (path-like value)");
            if (value.contains("..")) potentialVulns.add("PATH_TRAVERSAL (contains ..)");

            if (!potentialVulns.isEmpty()) {
                point.put("potential_vulnerabilities", potentialVulns);
                point.put("risk_score", potentialVulns.size());
                injectionPoints.add(point);
            }
        }

        // Sort by risk score descending
        injectionPoints.sort((a, b) -> (int) b.get("risk_score") - (int) a.get("risk_score"));

        // Response-level indicators
        Map<String, Object> responseInfo = new LinkedHashMap<>();
        if (response != null) {
            responseInfo.put("has_error_messages", responseLower.contains("error") || responseLower.contains("exception") || responseLower.contains("stack trace"));
            responseInfo.put("has_sql_keywords", responseLower.contains("sql") || responseLower.contains("mysql") || responseLower.contains("postgresql") || responseLower.contains("sqlite") || responseLower.contains("oracle"));
            responseInfo.put("has_debug_info", responseLower.contains("debug") || responseLower.contains("stacktrace") || responseLower.contains("traceback"));
            responseInfo.put("has_file_paths", responseLower.contains("/etc/") || responseLower.contains("c:\\") || responseLower.contains("/var/") || responseLower.contains("/home/"));
            responseInfo.put("has_version_info", responseLower.contains("version") || responseLower.contains("powered by"));
            responseInfo.put("content_type", response.headerValue("Content-Type"));
            responseInfo.put("server_header", response.headerValue("Server"));
        }

        result.put("injection_points", injectionPoints);
        result.put("total_injection_points", injectionPoints.size());
        result.put("response_indicators", responseInfo);
        result.put("url", request.url());
        result.put("method", request.method());

        return result;
    }
}
