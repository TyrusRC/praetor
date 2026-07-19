package com.praetor.audit;

import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ScopeAuditLogRotationTest {

    @Test
    void rotatesAtTenMegabytes() throws Exception {
        Path intel = Paths.get(".burp-intel");
        Files.createDirectories(intel);
        Path log = intel.resolve("_audit.log");
        Path archive1 = intel.resolve("_audit.log.1");

        // back up existing state (test may be re-run on a dev box)
        byte[] originalLog = Files.exists(log) ? Files.readAllBytes(log) : null;
        byte[] originalArchive = Files.exists(archive1) ? Files.readAllBytes(archive1) : null;

        try {
            Files.deleteIfExists(archive1);
            // write 11 MB
            byte[] chunk = new byte[1024];
            for (int i = 0; i < 1024; i++) chunk[i] = 'x';
            try (OutputStream os = Files.newOutputStream(log,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                for (int i = 0; i < 11 * 1024; i++) os.write(chunk);
            }
            assertTrue(Files.size(log) > 10L * 1024 * 1024);

            // trigger via a single append — should rotate
            ScopeAuditLog.append("test", "https://example.com/probe", "operator");

            assertTrue(Files.exists(archive1), ".1 archive must exist after rotation");
            assertTrue(Files.size(archive1) > 10L * 1024 * 1024, ".1 must hold the old large log");
            assertTrue(Files.size(log) < 1024, "current log must contain only the new line");
        } finally {
            // restore
            if (originalLog != null) Files.write(log, originalLog);
            else Files.deleteIfExists(log);
            if (originalArchive != null) Files.write(archive1, originalArchive);
            else Files.deleteIfExists(archive1);
        }
    }

    @Test
    void doesNotRotateWhenUnderThreshold() throws Exception {
        Path intel = Paths.get(".burp-intel");
        Files.createDirectories(intel);
        Path log = intel.resolve("_audit.log");
        Path archive1Probe = intel.resolve("_audit.log.1");

        byte[] originalLog = Files.exists(log) ? Files.readAllBytes(log) : null;
        boolean archiveExisted = Files.exists(archive1Probe);

        try {
            // 1 KB log
            Files.write(log, new byte[1024]);
            assertTrue(Files.size(log) < 10L * 1024 * 1024);

            long sizeBefore = Files.size(log);
            ScopeAuditLog.append("test", "https://example.com", "operator");
            long sizeAfter = Files.size(log);

            assertTrue(sizeAfter > sizeBefore, "append must extend the log when not rotating");
        } finally {
            if (originalLog != null) Files.write(log, originalLog);
            else Files.deleteIfExists(log);
            if (!archiveExisted) Files.deleteIfExists(archive1Probe);
        }
    }
}
