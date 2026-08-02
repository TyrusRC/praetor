package com.praetor.session;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Probes declared with context-level matchers must still be scored.
 *
 * The knowledge base uses two shapes for matchers: per-probe (the common one)
 * and per-context (a handful of files, including the cloud-metadata SSRF set).
 * Only per-probe was read, so every per-context probe was SENT and matched
 * against nothing — the payload went out, no finding came back, and auto_probe
 * then recorded a documented negative that suppressed the re-test.
 */
class AutoProbeMatcherResolutionTest {

    private static final List<Map<String, Object>> CONTEXT_MATCHERS =
        List.of(Map.of("type", "word", "words", List.of("ami-id", "iam/security-credentials")));

    private static final List<Map<String, Object>> PROBE_MATCHERS =
        List.of(Map.of("type", "status", "status", 500));

    @Test
    void probeWithoutMatchersInheritsContextMatchers() {
        Map<String, Object> probe = Map.of("payload", "http://169.254.169.254/latest/meta-data/");
        assertSame(CONTEXT_MATCHERS,
            AutoProbeOrchestrator.resolveMatchers(probe, CONTEXT_MATCHERS),
            "cloud-metadata probes must be scored against the context's matchers");
    }

    @Test
    void probeWithOwnMatchersKeepsThem() {
        Map<String, Object> probe = Map.of("payload", "x", "matchers", PROBE_MATCHERS);
        assertSame(PROBE_MATCHERS,
            AutoProbeOrchestrator.resolveMatchers(probe, CONTEXT_MATCHERS),
            "a probe's own matchers always win over the context's");
    }

    @Test
    void emptyProbeMatcherListFallsBackRatherThanScoringNothing() {
        Map<String, Object> probe = Map.of("payload", "x", "matchers", List.of());
        assertSame(CONTEXT_MATCHERS,
            AutoProbeOrchestrator.resolveMatchers(probe, CONTEXT_MATCHERS));
    }

    @Test
    void noMatchersAnywhereStaysNull() {
        Map<String, Object> probe = Map.of("payload", "x");
        assertNull(AutoProbeOrchestrator.resolveMatchers(probe, null),
            "downstream already treats null as 'nothing to score'");
    }

    @Test
    void referenceOnlyProbesAreNotSent() {
        // Their "payload" is prose for the operator, not a payload.
        assertTrue(AutoProbeOrchestrator.isReferenceOnly(Map.of("reference_only", true)));
        assertTrue(AutoProbeOrchestrator.isReferenceOnly(Map.of("reference_only", "true")));
        assertFalse(AutoProbeOrchestrator.isReferenceOnly(Map.of("reference_only", false)));
        assertFalse(AutoProbeOrchestrator.isReferenceOnly(Map.of("sleep", "5")));
        assertFalse(AutoProbeOrchestrator.isReferenceOnly(Map.of()));
        assertFalse(AutoProbeOrchestrator.isReferenceOnly(null));
    }

    @Test
    void resolutionDoesNotMutateTheSharedKnowledgeBase() {
        // The KB map is shared across probing threads; writing the inherited
        // list back onto the probe would be a data race.
        Map<String, Object> probe = new java.util.LinkedHashMap<>(Map.of("payload", "x"));
        AutoProbeOrchestrator.resolveMatchers(probe, CONTEXT_MATCHERS);
        assertFalse(probe.containsKey("matchers"),
            "resolveMatchers must not write back into the shared probe map");
    }
}
