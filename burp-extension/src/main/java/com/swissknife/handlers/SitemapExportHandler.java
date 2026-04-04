package com.swissknife.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
import com.swissknife.server.BaseHandler;
import com.swissknife.util.JsonUtil;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/**
 * GET /api/export/sitemap?format=json|openapi&prefix=https://target.com
 *
 * Builds a comprehensive API map from proxy history.
 * - json (default): compact LLM-optimized endpoint listing
 * - openapi: valid OpenAPI 3.0 YAML spec
 */
public class SitemapExportHandler extends BaseHandler {

    private final MontoyaApi api;

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[\\w.+-]+@[\\w.-]+\\.[a-zA-Z]{2,}$");
    private static final Pattern UUID_PATTERN = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", Pattern.CASE_INSENSITIVE);
    private static final Pattern URL_PATTERN = Pattern.compile("^https?://", Pattern.CASE_INSENSITIVE);
    private static final Pattern NUMBER_PATTERN = Pattern.compile("^-?\\d+(\\.\\d+)?$");
    private static final Pattern BOOLEAN_PATTERN = Pattern.compile("^(true|false)$", Pattern.CASE_INSENSITIVE);

    public SitemapExportHandler(MontoyaApi api) {
        this.api = api;
    }

    @Override
    protected void handleRequest(HttpExchange exchange) throws Exception {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        Map<String, String> params = queryParams(exchange);
        String format = params.getOrDefault("format", "json");
        String prefix = params.getOrDefault("prefix", "");

        if (prefix.isEmpty()) {
            sendError(exchange, 400, "Missing 'prefix' parameter");
            return;
        }

        // Collect endpoint data from proxy history
        Map<String, EndpointData> endpoints = collectEndpoints(prefix);

        if ("openapi".equalsIgnoreCase(format)) {
            String yaml = buildOpenApiYaml(prefix, endpoints);
            byte[] bytes = yaml.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/yaml; charset=utf-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        } else {
            sendJson(exchange, buildCompactJson(prefix, endpoints));
        }
    }

    // ── Data collection ───────────────────────────────────────────

    private Map<String, EndpointData> collectEndpoints(String prefix) {
        Map<String, EndpointData> endpoints = new LinkedHashMap<>();
        List<ProxyHttpRequestResponse> history = api.proxy().history();

        for (ProxyHttpRequestResponse item : history) {
            HttpRequest req = item.finalRequest();
            String url = req.url();

            if (!url.startsWith(prefix)) continue;

            String basePath;
            try {
                URI uri = new URI(url);
                basePath = uri.getPath();
                if (basePath == null || basePath.isEmpty()) basePath = "/";
            } catch (Exception e) {
                continue;
            }

            EndpointData ep = endpoints.computeIfAbsent(basePath, k -> new EndpointData(k));
            ep.methods.add(req.method());

            // Collect query parameters
            for (var p : req.parameters()) {
                String paramType = p.type().toString().toLowerCase();
                String location;
                switch (paramType) {
                    case "url" -> location = "query";
                    case "body" -> location = "body";
                    case "cookie" -> location = "cookie";
                    default -> location = paramType;
                }
                ParamKey key = new ParamKey(p.name(), location);
                ParamData pd = ep.parameters.computeIfAbsent(key, k -> new ParamData(p.name(), location));
                if (p.value() != null && !p.value().isEmpty()) {
                    pd.examples.add(p.value());
                }
            }

            // Detect path parameters (numeric or UUID segments)
            detectPathParams(basePath, ep);

            // Collect response info
            HttpResponse resp = item.originalResponse();
            if (resp != null) {
                ResponseData rd = new ResponseData(resp.statusCode());
                String contentType = "";
                for (HttpHeader h : resp.headers()) {
                    if ("Content-Type".equalsIgnoreCase(h.name())) {
                        contentType = h.value().split(";")[0].trim();
                        break;
                    }
                }
                rd.contentType = contentType;
                rd.size = resp.body().length();
                ep.responses.add(rd);
            }

            // Detect auth
            for (HttpHeader h : req.headers()) {
                String name = h.name().toLowerCase();
                if (name.equals("authorization") || name.equals("cookie")) {
                    ep.authRequired = true;
                    break;
                }
            }
        }

        return endpoints;
    }

    private void detectPathParams(String path, EndpointData ep) {
        String[] segments = path.split("/");
        for (int i = 0; i < segments.length; i++) {
            String seg = segments[i];
            if (seg.isEmpty()) continue;
            if (NUMBER_PATTERN.matcher(seg).matches() || UUID_PATTERN.matcher(seg).matches()) {
                String paramName = "path_param_" + i;
                ParamKey key = new ParamKey(paramName, "path");
                ParamData pd = ep.parameters.computeIfAbsent(key, k -> new ParamData(paramName, "path"));
                pd.examples.add(seg);
            }
        }
    }

    // ── Compact JSON format ───────────────────────────────────────

    private String buildCompactJson(String prefix, Map<String, EndpointData> endpoints) {
        List<Map<String, Object>> items = new ArrayList<>();

        for (EndpointData ep : endpoints.values()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("path", ep.path);
            entry.put("methods", new ArrayList<>(ep.methods));

            // Build parameter list
            List<Map<String, Object>> paramList = new ArrayList<>();
            for (ParamData pd : ep.parameters.values()) {
                Map<String, Object> pm = new LinkedHashMap<>();
                pm.put("name", pd.name);
                pm.put("in", pd.location);
                String example = pd.examples.isEmpty() ? "" : pd.examples.iterator().next();
                pm.put("type", inferType(example));
                pm.put("example", example);
                paramList.add(pm);
            }
            entry.put("parameters", paramList);

            // Deduplicate responses by status code
            List<Map<String, Object>> respList = new ArrayList<>();
            Set<Integer> seenStatuses = new HashSet<>();
            for (ResponseData rd : ep.responses) {
                if (seenStatuses.add(rd.statusCode)) {
                    Map<String, Object> rm = new LinkedHashMap<>();
                    rm.put("status", rd.statusCode);
                    rm.put("content_type", rd.contentType);
                    rm.put("size", rd.size);
                    respList.add(rm);
                }
            }
            entry.put("responses", respList);
            entry.put("auth_required", ep.authRequired);

            items.add(entry);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("base_url", prefix);
        result.put("total_endpoints", items.size());
        result.put("endpoints", items);

        return JsonUtil.toJson(result);
    }

    // ── OpenAPI 3.0 YAML format ───────────────────────────────────

    private String buildOpenApiYaml(String prefix, Map<String, EndpointData> endpoints) {
        StringBuilder sb = new StringBuilder();
        sb.append("openapi: \"3.0.3\"\n");
        sb.append("info:\n");
        sb.append("  title: \"API Export from Burp Suite\"\n");
        sb.append("  version: \"1.0.0\"\n");
        sb.append("  description: \"Auto-generated from proxy history\"\n");
        sb.append("servers:\n");
        sb.append("  - url: ").append(yamlEscape(prefix)).append("\n");
        sb.append("paths:\n");

        for (EndpointData ep : endpoints.values()) {
            sb.append("  ").append(yamlEscape(ep.path)).append(":\n");

            for (String method : ep.methods) {
                String lowerMethod = method.toLowerCase();
                sb.append("    ").append(lowerMethod).append(":\n");
                sb.append("      summary: \"").append(method).append(" ").append(yamlEscapeInline(ep.path)).append("\"\n");

                if (ep.authRequired) {
                    sb.append("      security:\n");
                    sb.append("        - bearerAuth: []\n");
                }

                // Parameters (query, path, cookie — not body)
                List<ParamData> nonBodyParams = new ArrayList<>();
                List<ParamData> bodyParams = new ArrayList<>();
                for (ParamData pd : ep.parameters.values()) {
                    if ("body".equals(pd.location)) {
                        bodyParams.add(pd);
                    } else {
                        nonBodyParams.add(pd);
                    }
                }

                if (!nonBodyParams.isEmpty()) {
                    sb.append("      parameters:\n");
                    for (ParamData pd : nonBodyParams) {
                        String example = pd.examples.isEmpty() ? "" : pd.examples.iterator().next();
                        String type = inferType(example);
                        sb.append("        - name: ").append(yamlEscape(pd.name)).append("\n");
                        sb.append("          in: ").append(pd.location).append("\n");
                        sb.append("          schema:\n");
                        sb.append("            type: ").append(openApiType(type)).append("\n");
                        if (!example.isEmpty()) {
                            sb.append("          example: ").append(yamlEscape(example)).append("\n");
                        }
                    }
                }

                // Request body for body params
                if (!bodyParams.isEmpty() && ("post".equals(lowerMethod) || "put".equals(lowerMethod) || "patch".equals(lowerMethod))) {
                    sb.append("      requestBody:\n");
                    sb.append("        content:\n");
                    sb.append("          application/x-www-form-urlencoded:\n");
                    sb.append("            schema:\n");
                    sb.append("              type: object\n");
                    sb.append("              properties:\n");
                    for (ParamData pd : bodyParams) {
                        String example = pd.examples.isEmpty() ? "" : pd.examples.iterator().next();
                        String type = inferType(example);
                        sb.append("                ").append(yamlEscape(pd.name)).append(":\n");
                        sb.append("                  type: ").append(openApiType(type)).append("\n");
                        if (!example.isEmpty()) {
                            sb.append("                  example: ").append(yamlEscape(example)).append("\n");
                        }
                    }
                }

                // Responses
                sb.append("      responses:\n");
                Set<Integer> seenStatuses = new HashSet<>();
                boolean hasResponses = false;
                for (ResponseData rd : ep.responses) {
                    if (seenStatuses.add(rd.statusCode)) {
                        hasResponses = true;
                        sb.append("        \"").append(rd.statusCode).append("\":\n");
                        sb.append("          description: \"HTTP ").append(rd.statusCode).append("\"\n");
                        if (rd.contentType != null && !rd.contentType.isEmpty()) {
                            sb.append("          content:\n");
                            sb.append("            ").append(yamlEscape(rd.contentType)).append(":\n");
                            sb.append("              schema:\n");
                            sb.append("                type: object\n");
                        }
                    }
                }
                if (!hasResponses) {
                    sb.append("        \"200\":\n");
                    sb.append("          description: \"OK\"\n");
                }
            }
        }

        // Security schemes
        sb.append("components:\n");
        sb.append("  securitySchemes:\n");
        sb.append("    bearerAuth:\n");
        sb.append("      type: http\n");
        sb.append("      scheme: bearer\n");

        return sb.toString();
    }

    // ── Type inference ────────────────────────────────────────────

    private String inferType(String value) {
        if (value == null || value.isEmpty()) return "string";
        if (BOOLEAN_PATTERN.matcher(value).matches()) return "boolean";
        if (NUMBER_PATTERN.matcher(value).matches()) {
            return value.contains(".") ? "number" : "integer";
        }
        if (UUID_PATTERN.matcher(value).matches()) return "uuid";
        if (EMAIL_PATTERN.matcher(value).matches()) return "email";
        if (URL_PATTERN.matcher(value).matches()) return "url";
        return "string";
    }

    private String openApiType(String inferredType) {
        return switch (inferredType) {
            case "integer" -> "integer";
            case "number" -> "number";
            case "boolean" -> "boolean";
            default -> "string";
        };
    }

    // ── YAML helpers ──────────────────────────────────────────────

    private String yamlEscape(String value) {
        if (value == null) return "\"\"";
        if (value.contains(":") || value.contains("#") || value.contains("\"")
                || value.contains("'") || value.contains("{") || value.contains("}")
                || value.contains("[") || value.contains("]") || value.contains("@")
                || value.contains("&") || value.contains("*")) {
            return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }
        return value;
    }

    private String yamlEscapeInline(String value) {
        if (value == null) return "";
        return value.replace("\"", "\\\"");
    }

    // ── Data classes ──────────────────────────────────────────────

    private static class EndpointData {
        final String path;
        final Set<String> methods = new LinkedHashSet<>();
        final Map<ParamKey, ParamData> parameters = new LinkedHashMap<>();
        final List<ResponseData> responses = new ArrayList<>();
        boolean authRequired = false;

        EndpointData(String path) {
            this.path = path;
        }
    }

    private record ParamKey(String name, String location) {}

    private static class ParamData {
        final String name;
        final String location;
        final Set<String> examples = new LinkedHashSet<>();

        ParamData(String name, String location) {
            this.name = name;
            this.location = location;
        }
    }

    private static class ResponseData {
        final int statusCode;
        String contentType = "";
        int size = 0;

        ResponseData(int statusCode) {
            this.statusCode = statusCode;
        }
    }
}
