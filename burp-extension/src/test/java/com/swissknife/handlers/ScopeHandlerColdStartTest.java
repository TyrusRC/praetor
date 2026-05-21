package com.swissknife.handlers;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cold-start coverage for {@link ScopeHandler#currentMode}. The static
 * initializer loads {@code .burp-intel/_scope_mode.json} once at class load.
 * Because static init cannot be re-run from a test, we exercise the same
 * filesystem read via the package-private {@link ScopeHandler#reloadMode()}
 * helper — same code path, same parse, same write to the volatile field.
 */
class ScopeHandlerColdStartTest {

    @Test
    void coldStartReadsModeFromStateFile() throws Exception {
        Path intel = Path.of(".burp-intel");
        Files.createDirectories(intel);
        Path state = intel.resolve("_scope_mode.json");
        String originalContent = Files.exists(state) ? Files.readString(state) : null;
        String originalMode = ScopeHandler.currentMode;

        try {
            // strict — present on disk, valid value
            Files.writeString(state, "{\"mode\":\"strict\"}");
            ScopeHandler.reloadMode();
            assertEquals("strict", ScopeHandler.currentMode,
                "reloadMode must promote currentMode to 'strict' from the state file");

            // operator — valid downgrade
            Files.writeString(state, "{\"mode\":\"operator\"}");
            ScopeHandler.reloadMode();
            assertEquals("operator", ScopeHandler.currentMode,
                "reloadMode must accept 'operator' as a valid mode value");

            // garbage value — must be ignored, current mode preserved
            ScopeHandler.currentMode = "strict";
            Files.writeString(state, "{\"mode\":\"bogus\"}");
            ScopeHandler.reloadMode();
            assertEquals("strict", ScopeHandler.currentMode,
                "Unknown mode values must be rejected — keep the previous mode");

            // malformed JSON — non-fatal, current mode preserved
            ScopeHandler.currentMode = "operator";
            Files.writeString(state, "not even json");
            ScopeHandler.reloadMode();
            assertEquals("operator", ScopeHandler.currentMode,
                "Malformed state file must not crash reloadMode or mutate currentMode");
        } finally {
            // Restore: file contents (or remove if it didn't exist) AND in-memory
            // mode so other tests in the suite aren't affected by leakage.
            if (originalContent != null) {
                Files.writeString(state, originalContent);
            } else {
                Files.deleteIfExists(state);
            }
            ScopeHandler.currentMode = originalMode;
        }
    }
}
