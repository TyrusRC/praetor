package com.swissknife.audit;

import com.swissknife.util.JsonUtil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/** Append-only JSONL audit log of out-of-scope requests in operator mode. */
public final class ScopeAuditLog {

    private static final Path LOG = Path.of(".burp-intel", "_audit.log");
    private static final Set<String> SEEN_HOSTS = new HashSet<>();

    private ScopeAuditLog() {}

    public static synchronized void append(String tool, String url, String mode) {
        try {
            Files.createDirectories(LOG.getParent());
            String host = extractHost(url);
            boolean firstSeen = SEEN_HOSTS.add(host);
            String line = JsonUtil.object(
                "ts", Instant.now().toString(),
                "tool", tool == null ? "" : tool,
                "url", url,
                "host", host,
                "host_first_seen", firstSeen,
                "mode", mode
            ) + "\n";
            Files.writeString(LOG, line,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // Audit failure is non-fatal; the request still proceeds.
        }
    }

    private static String extractHost(String url) {
        try {
            return java.net.URI.create(url).getHost();
        } catch (Exception e) {
            return url;
        }
    }
}
