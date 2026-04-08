package com.swissknife.analysis;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extract API endpoints, URLs, and JavaScript references from response body.
 */
public final class EndpointExtractor {

    private EndpointExtractor() {}

    // Match paths like /api/v1/users, /admin/settings, etc.
    private static final Pattern API_PATH_PATTERN = Pattern.compile(
        "[\"'](/(?:api|v\\d+|rest|graphql|admin|auth|login|register|upload|download|search|webhook|callback)[/\\w.-]*)[\"']",
        Pattern.CASE_INSENSITIVE
    );

    // Match fetch/axios/XMLHttpRequest URLs
    private static final Pattern JS_FETCH_PATTERN = Pattern.compile(
        "(?:fetch|axios\\.\\w+|\\$\\.(?:ajax|get|post)|XMLHttpRequest)\\s*\\(\\s*[\"'`]([^\"'`]+)[\"'`]",
        Pattern.CASE_INSENSITIVE
    );

    // Match href/src/action attributes with paths
    private static final Pattern HREF_PATTERN = Pattern.compile(
        "(?:href|src|action)\\s*=\\s*[\"']([^\"'#][^\"']*)[\"']",
        Pattern.CASE_INSENSITIVE
    );

    // Match absolute URLs
    private static final Pattern URL_PATTERN = Pattern.compile(
        "https?://[\\w.-]+(?::\\d+)?[/\\w._~:/?#\\[\\]@!$&'()*+,;=-]*",
        Pattern.CASE_INSENSITIVE
    );

    public static Map<String, Object> extract(String body, String baseUrl) {
        Map<String, Object> result = new LinkedHashMap<>();
        Set<String> apiEndpoints = new LinkedHashSet<>();
        Set<String> jsEndpoints = new LinkedHashSet<>();
        Set<String> links = new LinkedHashSet<>();
        Set<String> externalUrls = new LinkedHashSet<>();

        String baseHost = "";
        try {
            java.net.URI uri = new java.net.URI(baseUrl);
            baseHost = uri.getHost();
        } catch (Exception ignored) {}

        // API paths
        Matcher m = API_PATH_PATTERN.matcher(body);
        while (m.find()) apiEndpoints.add(m.group(1));

        // JS fetch/ajax calls
        m = JS_FETCH_PATTERN.matcher(body);
        while (m.find()) jsEndpoints.add(m.group(1));

        // href/src links
        m = HREF_PATTERN.matcher(body);
        while (m.find()) {
            String link = m.group(1);
            if (!link.startsWith("javascript:") && !link.startsWith("data:")) {
                links.add(link);
            }
        }

        // Absolute URLs
        m = URL_PATTERN.matcher(body);
        while (m.find()) {
            String url = m.group(0);
            try {
                java.net.URI uri = new java.net.URI(url);
                String uriHost = uri.getHost();
                if (uriHost != null && !uriHost.equals(baseHost)) {
                    externalUrls.add(url);
                }
            } catch (Exception ignored) {}
        }

        result.put("api_endpoints", new ArrayList<>(apiEndpoints));
        result.put("js_endpoints", new ArrayList<>(jsEndpoints));
        result.put("links", new ArrayList<>(links));
        result.put("external_urls", new ArrayList<>(externalUrls));
        result.put("total_found", apiEndpoints.size() + jsEndpoints.size() + links.size());
        return result;
    }
}
