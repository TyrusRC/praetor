package com.praetor.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression cover for the evidence↔endpoint cross-check.
 *
 * Before this existed, an evidence index only had to be in range. An in-range
 * index pointing at unrelated traffic passed the save gate, and the Burp
 * comment, the finding markdown and the client report then all cited a request
 * that had nothing to do with the finding.
 *
 * The URL-comparison helpers are unit-testable directly; the MontoyaApi-facing
 * entry point is exercised end-to-end by the save-finding gate.
 */
class EvidenceMatchTest {

    @Test
    void hostExtraction() {
        assertEquals("api.example.com", EvidenceMatch.hostOf("https://api.example.com/v1/orders"));
        assertEquals("example.com", EvidenceMatch.hostOf("http://example.com:8080/x?y=1"));
        assertEquals("example.com", EvidenceMatch.hostOf("https://user@Example.com/x"));
        assertEquals("", EvidenceMatch.hostOf("/api/orders"), "path-only endpoint has no host to compare");
    }

    @Test
    void pathExtraction() {
        assertEquals("/v1/orders", EvidenceMatch.pathOf("https://api.example.com/v1/orders?id=1"));
        assertEquals("/v1/orders", EvidenceMatch.pathOf("https://api.example.com/v1/orders/"));
        assertEquals("/", EvidenceMatch.pathOf("https://api.example.com"));
        assertEquals("/api/orders", EvidenceMatch.pathOf("/api/orders#frag"));
    }

    @Test
    void hostsAgreeAcrossSubdomainForms() {
        assertTrue(EvidenceMatch.hostsAgree("example.com", "example.com"));
        assertTrue(EvidenceMatch.hostsAgree("api.example.com", "example.com"));
        assertFalse(EvidenceMatch.hostsAgree("example.com", "evil.com"));
        assertFalse(EvidenceMatch.hostsAgree("example.com", "notexample.com"));
    }

    @Test
    void pathsAgreeOnPlaceholderAndPrefixForms() {
        assertTrue(EvidenceMatch.pathsAgree("/users/42", "/users/{id}"));
        assertTrue(EvidenceMatch.pathsAgree("/users/{id}/orders", "/users/42/orders"));
        assertTrue(EvidenceMatch.pathsAgree("/api", "/api/orders"), "base path vs full path");
        assertTrue(EvidenceMatch.pathsAgree("/", "/anything"));
    }

    @Test
    void unrelatedPathsDisagree() {
        // The exact case that used to slip through: a finding on an API
        // endpoint citing a static-asset fetch.
        assertFalse(EvidenceMatch.pathsAgree("/api/orders", "/static/logo.png"));
        assertFalse(EvidenceMatch.pathsAgree("/login", "/logout"));
        assertFalse(EvidenceMatch.pathsAgree("/users/42/orders", "/users/42/profile"));
    }

    /**
     * A mismatch used to leave the caller (AnnotationHandler, NotesHandler) with
     * a bare "these don't match" 400 and no way to find the request that DOES
     * match. The hint is what turns that into something actionable.
     */
    @Test
    void actionableHintNamesTheDerivedPath() {
        String hint = EvidenceMatch.actionableHint("/v1/orders");
        assertTrue(hint.contains("query_history_dsl"));
        assertTrue(hint.contains("/v1/orders"), "hint should cite the endpoint's own path");
        assertTrue(hint.contains("search_history"));
    }

    @Test
    void actionableHintFallsBackWhenNoPathIsDerivable() {
        String hint = EvidenceMatch.actionableHint("");
        assertTrue(hint.contains("search_history") || hint.contains("query_history_dsl"));
        assertFalse(hint.contains("url ~"), "no path to filter on -> no fabricated query_history_dsl clause");
    }
}
