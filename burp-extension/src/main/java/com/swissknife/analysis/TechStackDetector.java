package com.swissknife.analysis;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.*;

/**
 * Detect technology stack from response headers and body fingerprints.
 */
public final class TechStackDetector {

    private TechStackDetector() {}

    public static Map<String, Object> detect(HttpResponse response) {
        Map<String, Object> result = new LinkedHashMap<>();
        List<String> technologies = new ArrayList<>();
        Map<String, Object> headers = new LinkedHashMap<>();
        List<String> securityHeaders = new ArrayList<>();
        List<String> missingSecurityHeaders = new ArrayList<>();

        // Analyze response headers
        for (HttpHeader h : response.headers()) {
            String name = h.name().toLowerCase();
            String value = h.value();

            switch (name) {
                case "server" -> {
                    headers.put("server", value);
                    technologies.add("Server: " + value);
                }
                case "x-powered-by" -> {
                    headers.put("x-powered-by", value);
                    technologies.add("Powered by: " + value);
                }
                case "x-aspnet-version", "x-aspnetmvc-version" -> {
                    technologies.add("ASP.NET: " + value);
                }
                case "x-generator" -> {
                    technologies.add("Generator: " + value);
                }
                case "set-cookie" -> {
                    // Detect frameworks from cookie names
                    if (value.contains("PHPSESSID")) technologies.add("PHP");
                    if (value.contains("JSESSIONID")) technologies.add("Java/Servlet");
                    if (value.contains("ASP.NET_SessionId")) technologies.add("ASP.NET");
                    if (value.contains("connect.sid")) technologies.add("Node.js/Express");
                    if (value.contains("_rails") || value.contains("_session")) technologies.add("Ruby on Rails");
                    if (value.contains("laravel_session")) technologies.add("Laravel");
                    if (value.contains("django") || value.contains("csrftoken")) technologies.add("Django");
                    if (value.contains("flask") || value.contains("session=")) technologies.add("Flask");
                }
                // Security headers
                case "strict-transport-security" -> securityHeaders.add("HSTS: " + value);
                case "content-security-policy" -> securityHeaders.add("CSP: " + truncate(value, 200));
                case "x-frame-options" -> securityHeaders.add("X-Frame-Options: " + value);
                case "x-content-type-options" -> securityHeaders.add("X-Content-Type-Options: " + value);
                case "x-xss-protection" -> securityHeaders.add("X-XSS-Protection: " + value);
                case "referrer-policy" -> securityHeaders.add("Referrer-Policy: " + value);
                case "permissions-policy" -> securityHeaders.add("Permissions-Policy: " + truncate(value, 200));
                case "access-control-allow-origin" -> securityHeaders.add("CORS: " + value);
            }
        }

        // Check for missing security headers
        Set<String> headerNames = new HashSet<>();
        for (HttpHeader h : response.headers()) headerNames.add(h.name().toLowerCase());

        if (!headerNames.contains("strict-transport-security")) missingSecurityHeaders.add("HSTS");
        if (!headerNames.contains("content-security-policy")) missingSecurityHeaders.add("CSP");
        if (!headerNames.contains("x-frame-options")) missingSecurityHeaders.add("X-Frame-Options");
        if (!headerNames.contains("x-content-type-options")) missingSecurityHeaders.add("X-Content-Type-Options");
        if (!headerNames.contains("referrer-policy")) missingSecurityHeaders.add("Referrer-Policy");

        // Body fingerprinting
        String body = response.bodyToString().toLowerCase();
        if (body.contains("wp-content") || body.contains("wp-includes")) technologies.add("WordPress");
        if (body.contains("drupal")) technologies.add("Drupal");
        if (body.contains("joomla")) technologies.add("Joomla");
        if (body.contains("react") || body.contains("__next")) technologies.add("React/Next.js");
        if (body.contains("vue") || body.contains("__nuxt")) technologies.add("Vue.js/Nuxt");
        if (body.contains("angular")) technologies.add("Angular");
        if (body.contains("jquery")) technologies.add("jQuery");
        if (body.contains("bootstrap")) technologies.add("Bootstrap");
        if (body.contains("cloudflare")) technologies.add("Cloudflare");
        if (body.contains("swagger") || body.contains("openapi")) technologies.add("Swagger/OpenAPI");
        if (body.contains("graphql")) technologies.add("GraphQL");

        result.put("technologies", technologies);
        result.put("security_headers_present", securityHeaders);
        result.put("security_headers_missing", missingSecurityHeaders);
        result.put("interesting_headers", headers);

        return result;
    }

    private static String truncate(String s, int max) {
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }
}
