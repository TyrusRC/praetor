package com.swissknife.session;

import com.swissknife.handlers.Session;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Seed coverage for {@link VariableExtractor}. Behaviour-preserving from
 * the pre-split SessionHandler helpers:
 *  - interpolateString: {{var}} replacement against a variable map
 *  - extractByRegex: capture-group-1 fallback to group-0
 *  - simpleJsonExtract: $.parent.child traversal of string values
 *  - mergeVariables: additive merge with 200-entry cap
 */
class VariableExtractorTest {

    @Test
    void interpolateStringReplacesKnownVariables() {
        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("token", "abc123");
        vars.put("user", "alice");

        assertEquals("Bearer abc123",
            VariableExtractor.interpolateString("Bearer {{token}}", vars));
        assertEquals("Hello alice, token=abc123",
            VariableExtractor.interpolateString("Hello {{user}}, token={{token}}", vars));
        assertEquals("no vars here",
            VariableExtractor.interpolateString("no vars here", vars));
        // Unknown placeholders pass through untouched.
        assertEquals("keep {{unknown}}",
            VariableExtractor.interpolateString("keep {{unknown}}", vars));
        // Null safety.
        assertNull(VariableExtractor.interpolateString(null, vars));
    }

    @Test
    void extractByRegexPrefersCaptureGroupOne() {
        // Group 1 present -> returns group 1.
        assertEquals("12345",
            VariableExtractor.extractByRegex("id=12345&x=y", "id=(\\d+)"));
        // No groups -> returns whole match (group 0).
        assertEquals("error",
            VariableExtractor.extractByRegex("found error here", "error"));
        // No match -> null.
        assertNull(VariableExtractor.extractByRegex("nothing", "missing"));
        // Bad regex -> null (try/catch swallow).
        assertNull(VariableExtractor.extractByRegex("text", "[unclosed"));
    }

    @Test
    void simpleJsonExtractTraversesNestedPath() {
        String json = "{\"data\":{\"user\":{\"name\":\"alice\",\"id\":42}}}";

        assertEquals("alice",
            VariableExtractor.simpleJsonExtract(json, "$.data.user.name"));
        assertEquals("42",
            VariableExtractor.simpleJsonExtract(json, "$.data.user.id"));
        // Missing key -> null.
        assertNull(VariableExtractor.simpleJsonExtract(json, "$.data.user.missing"));
        // Path that doesn't start with $. -> null (silent reject).
        assertNull(VariableExtractor.simpleJsonExtract(json, "data.user.name"));
        // Null path -> null.
        assertNull(VariableExtractor.simpleJsonExtract(json, null));
    }

    @Test
    void mergeVariablesIsAdditiveAndCapped() {
        Session s = new Session();
        Map<String, String> first = new LinkedHashMap<>();
        first.put("a", "1");
        first.put("b", "2");
        VariableExtractor.mergeVariables(s, first);
        assertEquals(2, s.variables.size());
        assertEquals("1", s.variables.get("a"));

        // Second merge adds new + overwrites existing.
        Map<String, String> second = new LinkedHashMap<>();
        second.put("b", "2b");
        second.put("c", "3");
        VariableExtractor.mergeVariables(s, second);
        assertEquals(3, s.variables.size());
        assertEquals("2b", s.variables.get("b"));
        assertEquals("3", s.variables.get("c"));

        // 200-entry cap: push 250 distinct keys, expect <= 200.
        Map<String, String> flood = new LinkedHashMap<>();
        for (int i = 0; i < 250; i++) flood.put("k" + i, "v" + i);
        VariableExtractor.mergeVariables(s, flood);
        assertTrue(s.variables.size() <= 200,
            "variables map must be capped at 200 entries, was " + s.variables.size());
    }

    @Test
    void truncateRespectsLimit() {
        assertEquals("", VariableExtractor.truncate(null, 10));
        assertEquals("short", VariableExtractor.truncate("short", 10));
        assertEquals("12345...", VariableExtractor.truncate("12345678", 5));
    }
}
