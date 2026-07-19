package com.praetor.audit;

import com.praetor.util.JsonUtil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/** Append-only JSONL audit log of out-of-scope requests in operator mode. */
public final class ScopeAuditLog {

    private static final Path LOG = Path.of(".burp-intel", "_audit.log");
    private static final Set<String> SEEN_HOSTS = new HashSet<>();
    private static final long MAX_SIZE = 10L * 1024 * 1024;  // 10 MB
    private static final int MAX_ARCHIVES = 5;

    private ScopeAuditLog() {}

    public static synchronized void append(String tool, String url, String mode) {
        try {
            Files.createDirectories(LOG.getParent());
            rotateIfNeeded(LOG);
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

    private static void rotateIfNeeded(Path log) {
        try {
            if (!Files.exists(log)) return;
            long size = Files.size(log);
            if (size < MAX_SIZE) return;

            Path dir = log.getParent();
            String base = log.getFileName().toString();

            // shift archives: .4 -> .5 (drops existing .5), .3 -> .4, ..., .1 -> .2
            for (int i = MAX_ARCHIVES - 1; i >= 1; i--) {
                Path src = dir.resolve(base + "." + i);
                Path dst = dir.resolve(base + "." + (i + 1));
                if (Files.exists(src)) {
                    Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING);
                }
            }
            // current -> .1
            Files.move(log, dir.resolve(base + ".1"), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException ignored) {
            // Rotation failure must not break tool calls; continue appending to existing log.
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
