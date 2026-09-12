package com.praetor.handlers;

import java.util.*;
import java.util.regex.*;

/** HTML attribute + URL host helpers, split out of ExtractTextHandler (pure). */
final class HtmlExtractHelpers {

    private HtmlExtractHelpers() {}

    static boolean matchesAttribute(String attrs, String name, String value, boolean partialMatch) {
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

    static String extractAttribute(String attrs, String name) {
        Pattern p = Pattern.compile(name + "\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(attrs);
        if (m.find()) return m.group(1);
        return null;
    }

    // ── 3. Links extraction ─────────────────────────────────────


    static String extractHost(String url) {
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

    static boolean isInternal(String url, String requestHost) {
        if (url.startsWith("/") || url.startsWith("./") || url.startsWith("../") || !url.contains("://")) {
            return true;
        }
        String linkHost = extractHost(url);
        return linkHost.equalsIgnoreCase(requestHost);
    }
}
