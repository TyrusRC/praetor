package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.swissknife.http.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.util.*;
import java.util.regex.*;

/**
 * POST /api/extract-text/regex         - regex extraction from response body
 * POST /api/extract-text/css-selector  - CSS-selector-like extraction from HTML response body
 * POST /api/extract-text/links         - extract all links from HTML response body
 */
public class ExtractTextHandler extends BaseHandler {

    private final MontoyaApi api;

    public ExtractTextHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        String path = exchange.getRequestURI().getPath();

        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        switch (path) {
            case "/api/extract-text/regex" -> handleRegex(exchange);
            case "/api/extract-text/css-selector" -> handleCssSelector(exchange);
            case "/api/extract-text/links" -> handleLinks(exchange);
            default -> sendError(exchange, 404, "Not found");
        }
    }

    // ── Helpers ──────────────────────────────────────────────────

    private ProxyHttpRequestResponse getHistoryItem(int index) {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index < 0 || index >= history.size()) return null;
        return history.get(index);
    }

    private int readIndex(Map<String, Object> body) {
        Object val = body.get("index");
        return val instanceof Number n ? n.intValue() : -1;
    }

    private String getResponseBody(int index) {
        ProxyHttpRequestResponse item = getHistoryItem(index);
        if (item == null) return null;
        HttpResponse resp = item.originalResponse();
        if (resp == null) return null;
        return resp.bodyToString();
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }

    // ── 1. Regex extraction ─────────────────────────────────────

    private void handleRegex(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        int index = readIndex(body);
        String patternStr = (String) body.get("pattern");
        int group = body.get("group") instanceof Number n ? n.intValue() : 0;
        boolean all = Boolean.TRUE.equals(body.get("all"));

        if (patternStr == null || patternStr.isEmpty()) {
            sendError(exchange, 400, "Missing 'pattern' field");
            return;
        }

        String responseBody = getResponseBody(index);
        if (responseBody == null) {
            sendError(exchange, 400, "Invalid index or no response at index " + index);
            return;
        }

        Pattern pattern;
        try {
            pattern = Pattern.compile(patternStr);
        } catch (PatternSyntaxException e) {
            sendError(exchange, 400, "Invalid regex pattern: " + e.getMessage());
            return;
        }

        Matcher matcher = pattern.matcher(responseBody);
        List<String> matches = new ArrayList<>();

        if (all) {
            while (matcher.find()) {
                if (group <= matcher.groupCount()) {
                    String m = matcher.group(group);
                    if (m != null) matches.add(m);
                }
            }
        } else {
            if (matcher.find() && group <= matcher.groupCount()) {
                String m = matcher.group(group);
                if (m != null) matches.add(m);
            }
        }

        sendJson(exchange, JsonUtil.object("matches", matches, "count", matches.size()));
    }

    // ── 2. CSS selector extraction ──────────────────────────────

    private void handleCssSelector(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        int index = readIndex(body);
        String selector = (String) body.get("selector");
        String attribute = (String) body.get("attribute");

        if (selector == null || selector.isEmpty()) {
            sendError(exchange, 400, "Missing 'selector' field");
            return;
        }

        String responseBody = getResponseBody(index);
        if (responseBody == null) {
            sendError(exchange, 400, "Invalid index or no response at index " + index);
            return;
        }

        // Parse the selector into components
        String tagName = null;
        String className = null;
        String idValue = null;
        String attrName = null;
        String attrValue = null;

        // tag[attr=value]
        Matcher attrValMatcher = Pattern.compile("^(\\w+)\\[([\\w-]+)=([^\\]]+)]$").matcher(selector);
        // tag[attr]
        Matcher attrMatcher = Pattern.compile("^(\\w+)\\[([\\w-]+)]$").matcher(selector);
        // tag#id
        Matcher idMatcher = Pattern.compile("^(\\w+)#([\\w-]+)$").matcher(selector);
        // tag.class
        Matcher classMatcher = Pattern.compile("^(\\w+)\\.([\\w-]+)$").matcher(selector);
        // tag only
        Matcher tagMatcher = Pattern.compile("^(\\w+)$").matcher(selector);

        if (attrValMatcher.matches()) {
            tagName = attrValMatcher.group(1);
            attrName = attrValMatcher.group(2);
            attrValue = attrValMatcher.group(3).replaceAll("^\"|\"$|^'|'$", "");
        } else if (attrMatcher.matches()) {
            tagName = attrMatcher.group(1);
            attrName = attrMatcher.group(2);
        } else if (idMatcher.matches()) {
            tagName = idMatcher.group(1);
            idValue = idMatcher.group(2);
        } else if (classMatcher.matches()) {
            tagName = classMatcher.group(1);
            className = classMatcher.group(2);
        } else if (tagMatcher.matches()) {
            tagName = tagMatcher.group(1);
        } else {
            sendError(exchange, 400, "Unsupported CSS selector syntax: " + selector);
            return;
        }

        // Build a regex to find matching elements (both self-closing and open/close tags)
        String tagPattern = "<" + tagName + "\\b([^>]*)(?:/>|>(.*?)</" + tagName + ">)";
        Pattern pattern = Pattern.compile(tagPattern, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher elementMatcher = pattern.matcher(responseBody);

        List<Map<String, Object>> elements = new ArrayList<>();

        while (elementMatcher.find()) {
            String attrs = elementMatcher.group(1) != null ? elementMatcher.group(1) : "";
            String innerText = elementMatcher.group(2) != null ? elementMatcher.group(2) : "";
            String outerHtml = elementMatcher.group(0);

            // Apply filters
            if (className != null && !matchesAttribute(attrs, "class", className, true)) continue;
            if (idValue != null && !matchesAttribute(attrs, "id", idValue, false)) continue;
            if (attrName != null && attrValue != null && !matchesAttribute(attrs, attrName, attrValue, false)) continue;
            if (attrName != null && attrValue == null && !attrs.contains(attrName)) continue;

            Map<String, Object> elem = new LinkedHashMap<>();
            elem.put("outer_html", truncate(outerHtml, 500));
            elem.put("text", innerText.replaceAll("<[^>]+>", "").trim());

            // Extract requested attribute value
            if (attribute != null) {
                String val = extractAttribute(attrs, attribute);
                elem.put("attribute_value", val != null ? val : "");
            }

            elements.add(elem);
        }

        sendJson(exchange, JsonUtil.object("elements", elements, "count", elements.size()));
    }

    private boolean matchesAttribute(String attrs, String name, String value, boolean partialMatch) {
        Pattern p = Pattern.compile(name + "\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(attrs);
        if (!m.find()) return false;
        String attrVal = m.group(1);
        if (partialMatch) {
            // For class, check if any class token matches
            for (String cls : attrVal.split("\\s+")) {
                if (cls.equals(value)) return true;
            }
            return false;
        }
        return attrVal.equals(value);
    }

    private String extractAttribute(String attrs, String name) {
        Pattern p = Pattern.compile(name + "\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(attrs);
        if (m.find()) return m.group(1);
        return null;
    }

    // ── 3. Links extraction ─────────────────────────────────────

    private void handleLinks(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readJsonBody(exchange);
        int index = readIndex(body);
        String filter = (String) body.getOrDefault("filter", "all");

        ProxyHttpRequestResponse item = getHistoryItem(index);
        if (item == null) {
            sendError(exchange, 400, "Invalid index: " + index);
            return;
        }

        HttpResponse resp = item.originalResponse();
        if (resp == null) {
            sendError(exchange, 400, "No response at index " + index);
            return;
        }

        String responseBody = resp.bodyToString();
        String requestHost = extractHost(item.finalRequest().url());

        List<Map<String, Object>> links = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        // Define extraction patterns: tag -> attribute -> type label
        String[][] patterns = {
            {"a", "href", "anchor"},
            {"form", "action", "form"},
            {"script", "src", "script"},
            {"link", "href", "link"},
            {"img", "src", "img"},
            {"iframe", "src", "iframe"},
        };

        for (String[] spec : patterns) {
            String tag = spec[0];
            String attr = spec[1];
            String type = spec[2];

            Pattern p = Pattern.compile(
                "<" + tag + "\\b[^>]*" + attr + "\\s*=\\s*[\"']([^\"']+)[\"']",
                Pattern.CASE_INSENSITIVE
            );
            Matcher m = p.matcher(responseBody);

            while (m.find()) {
                String url = m.group(1).trim();
                if (url.isEmpty() || url.startsWith("#") || url.startsWith("javascript:") || url.startsWith("data:")) {
                    continue;
                }

                String key = url + "|" + type;
                if (seen.contains(key)) continue;
                seen.add(key);

                boolean internal = isInternal(url, requestHost);

                if ("internal".equals(filter) && !internal) continue;
                if ("external".equals(filter) && internal) continue;

                Map<String, Object> link = new LinkedHashMap<>();
                link.put("url", url);
                link.put("type", type);
                link.put("internal", internal);
                links.add(link);
            }
        }

        sendJson(exchange, JsonUtil.object("links", links, "count", links.size()));
    }

    private String extractHost(String url) {
        try {
            if (url.contains("://")) {
                String afterProto = url.substring(url.indexOf("://") + 3);
                int slashIdx = afterProto.indexOf('/');
                String hostPort = slashIdx >= 0 ? afterProto.substring(0, slashIdx) : afterProto;
                int colonIdx = hostPort.indexOf(':');
                return colonIdx >= 0 ? hostPort.substring(0, colonIdx) : hostPort;
            }
        } catch (Exception ignored) {}
        return "";
    }

    private boolean isInternal(String url, String requestHost) {
        if (url.startsWith("/") || url.startsWith("./") || url.startsWith("../") || !url.contains("://")) {
            return true;
        }
        String linkHost = extractHost(url);
        return linkHost.equalsIgnoreCase(requestHost);
    }
}
