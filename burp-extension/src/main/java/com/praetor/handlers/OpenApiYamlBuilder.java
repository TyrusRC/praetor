package com.praetor.handlers;

import java.util.*;

/** OpenAPI-YAML projection of a collected sitemap, split from SitemapExportHandler. */
final class OpenApiYamlBuilder {

    private OpenApiYamlBuilder() {}

    static String buildOpenApiYaml(String prefix, Map<String, SitemapExportHandler.EndpointData> endpoints) {
        StringBuilder sb = new StringBuilder();
        sb.append("openapi: \"3.0.3\"\n");
        sb.append("info:\n");
        sb.append("  title: \"API Export from Burp Suite\"\n");
        sb.append("  version: \"1.0.0\"\n");
        sb.append("  description: \"Auto-generated from proxy history\"\n");
        sb.append("servers:\n");
        sb.append("  - url: ").append(yamlEscape(prefix)).append("\n");
        sb.append("paths:\n");

        for (SitemapExportHandler.EndpointData ep : endpoints.values()) {
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
                List<SitemapExportHandler.ParamData> nonBodyParams = new ArrayList<>();
                List<SitemapExportHandler.ParamData> bodyParams = new ArrayList<>();
                for (SitemapExportHandler.ParamData pd : ep.parameters.values()) {
                    if ("body".equals(pd.location)) {
                        bodyParams.add(pd);
                    } else {
                        nonBodyParams.add(pd);
                    }
                }

                if (!nonBodyParams.isEmpty()) {
                    sb.append("      parameters:\n");
                    for (SitemapExportHandler.ParamData pd : nonBodyParams) {
                        String example = pd.examples.isEmpty() ? "" : pd.examples.iterator().next();
                        String type = SitemapExportHandler.inferType(example);
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
                    for (SitemapExportHandler.ParamData pd : bodyParams) {
                        String example = pd.examples.isEmpty() ? "" : pd.examples.iterator().next();
                        String type = SitemapExportHandler.inferType(example);
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
                for (SitemapExportHandler.ResponseData rd : ep.responses) {
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


    static String openApiType(String inferredType) {
        return switch (inferredType) {
            case "integer" -> "integer";
            case "number" -> "number";
            case "boolean" -> "boolean";
            default -> "string";
        };
    }

    // ── YAML helpers ──────────────────────────────────────────────

    static String yamlEscape(String value) {
        if (value == null) return "\"\"";
        if (value.contains(":") || value.contains("#") || value.contains("\"")
                || value.contains("'") || value.contains("{") || value.contains("}")
                || value.contains("[") || value.contains("]") || value.contains("@")
                || value.contains("&") || value.contains("*")) {
            return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }
        return value;
    }

    static String yamlEscapeInline(String value) {
        if (value == null) return "";
        return value.replace("\"", "\\\"");
    }

}
