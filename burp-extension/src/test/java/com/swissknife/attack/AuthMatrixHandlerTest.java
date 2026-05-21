package com.swissknife.attack;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Smoke + behaviour coverage for {@link AuthMatrixHandler}. The {@code handle}
 * method needs Montoya, so we test the package-private {@code calculateSimilarity}
 * helper directly — same algorithm that drives the IDOR flag.
 *
 * Behaviour-preserving from the pre-split AttackHandler.calculateSimilarity.
 */
class AuthMatrixHandlerTest {

    private final AuthMatrixHandler handler = new AuthMatrixHandler(null);

    @Test
    void constructorAcceptsApiAndExposesHelper() {
        assertNotNull(handler);
    }

    @Test
    void identicalStringsScoreOne() {
        assertEquals(1.0, handler.calculateSimilarity("abc", "abc"));
        assertEquals(1.0, handler.calculateSimilarity("", ""));
        assertEquals(1.0, handler.calculateSimilarity(null, null));
    }

    @Test
    void nullOrEmptyMismatchScoresZero() {
        assertEquals(0.0, handler.calculateSimilarity(null, "x"));
        assertEquals(0.0, handler.calculateSimilarity("x", null));
        assertEquals(0.0, handler.calculateSimilarity("", "x"));
        assertEquals(0.0, handler.calculateSimilarity("x", ""));
    }

    @Test
    void identicalLongStringsScoreOne() {
        String body = "x".repeat(1000);
        assertEquals(1.0, handler.calculateSimilarity(body, body));
    }

    @Test
    void heavilyDivergentStringsScoreLow() {
        // Length differs >20% AND content differs -> capped at 0.7 by length penalty.
        String a = "a".repeat(100);
        String b = "z".repeat(500);
        double sim = handler.calculateSimilarity(a, b);
        assertTrue(sim <= 0.7, "expected length-penalty cap to apply, got " + sim);
    }

    @Test
    void verySimilarStringsScoreAboveIdorThreshold() {
        // Body length within 20% and most characters identical at sampled positions:
        // should land >0.9 so the IDOR flag triggers in the real handler.
        String a = "user_id=42&role=admin&token=abc123def456ghi789jkl0";
        String b = "user_id=42&role=admin&token=abc123def456ghi789jkl1";
        double sim = handler.calculateSimilarity(a, b);
        assertTrue(sim > 0.9, "expected >0.9 similarity for near-identical bodies, got " + sim);
    }
}
