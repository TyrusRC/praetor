package com.praetor.analysis;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Seed coverage for {@link MatcherEngine}. Focus is the {@code not_status}
 * branch (commit f67d84d shipped inspection-only) and the fail-closed
 * behaviour on unknown matcher types.
 *
 * Note: Montoya {@link HttpResponse#httpResponse} requires the in-process
 * {@code ObjectFactoryLocator.FACTORY} which is only initialised when running
 * inside Burp. Under JUnit/Surefire there is no Burp, so we stub the
 * interfaces via {@link java.lang.reflect.Proxy} — {@link MatcherEngine#evaluate}
 * only calls {@code statusCode()}, {@code bodyToString()} and {@code headers()},
 * everything else is unreachable for the matcher types this test exercises.
 */
class MatcherEngineTest {

    private static HttpHeader stubHeader(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
            HttpHeader.class.getClassLoader(),
            new Class<?>[]{HttpHeader.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "name" -> name;
                case "value" -> value;
                case "toString" -> name + ": " + value;
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                default -> throw new UnsupportedOperationException(
                    "HttpHeader." + method.getName() + " not stubbed");
            }
        );
    }

    private static HttpResponse stubResponse(int status, String body, List<HttpHeader> headers) {
        return (HttpResponse) Proxy.newProxyInstance(
            HttpResponse.class.getClassLoader(),
            new Class<?>[]{HttpResponse.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "statusCode" -> (short) status;  // HttpResponse.statusCode() returns primitive short
                case "bodyToString" -> body;
                case "headers" -> headers;
                case "toString" -> "stub(" + status + ")";
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                default -> throw new UnsupportedOperationException(
                    "HttpResponse." + method.getName() + " not stubbed");
            }
        );
    }

    @Test
    void notStatusMatcherFiresWhenStatusDoesNotMatch() {
        Map<String, Object> matcher = Map.of(
            "type", "not_status",
            "status", List.of(200, 201, 204)
        );

        Map<String, Object> hit = MatcherEngine.evaluate(
            List.of(matcher), stubResponse(500, "", List.of()), 10L, null, "");
        assertEquals(Boolean.TRUE, hit.get("matched"),
            "not_status must match when probe status (500) is outside the listed set");

        Map<String, Object> miss = MatcherEngine.evaluate(
            List.of(matcher), stubResponse(200, "", List.of()), 10L, null, "");
        assertEquals(Boolean.FALSE, miss.get("matched"),
            "not_status must NOT match when probe status (200) is in the listed set");
    }

    @Test
    void unknownMatcherTypeFailsClosed() {
        Map<String, Object> matcher = Map.of("type", "nonexistent_matcher");

        Map<String, Object> result = MatcherEngine.evaluate(
            List.of(matcher), stubResponse(200, "", List.of()), 10L, null, "");

        assertEquals(Boolean.FALSE, result.get("matched"),
            "Unknown matcher types must fail closed (no false-positive probes from KB drift)");
        @SuppressWarnings("unchecked")
        List<String> descriptions = (List<String>) result.get("matched_matchers");
        assertNotNull(descriptions);
        assertTrue(descriptions.stream().anyMatch(d -> d.startsWith("unknown_matcher_type:")),
            "Drift tag 'unknown_matcher_type:' must appear in matched_matchers for diagnostics");
    }

    // ── Unfalsifiable matcher sets ────────────────────────────────────────
    // A live run returned 16 findings, 9 of them HIGH, every one from a matcher
    // set that any 200 response satisfies. A matcher that cannot fail is not a
    // matcher, so those sets must not score.

    @Test
    void statusSuccessPlusEmptyNegativeIsNotDiscriminating() {
        assertFalse(MatcherEngine.isDiscriminating(List.of(
            Map.of("type", "status", "status", List.of(200)),
            Map.of("type", "not_word", "words", List.of())
        )), "status:200 + empty not_word is satisfied by any healthy page");
    }

    @Test
    void statusSuccessAloneIsNotDiscriminating() {
        assertFalse(MatcherEngine.isDiscriminating(List.of(
            Map.of("type", "status", "status", List.of(200, 204))
        )));
    }

    @Test
    void errorStatusIsDiscriminating() {
        assertTrue(MatcherEngine.isDiscriminating(List.of(
            Map.of("type", "status", "status", List.of(500))
        )), "a 500 where the baseline gave 200 is how blind SQLi is confirmed");
    }

    @Test
    void notStatusIsDiscriminating() {
        assertTrue(MatcherEngine.isDiscriminating(List.of(
            Map.of("type", "not_status", "status", List.of(200))
        )));
    }

    @Test
    void populatedNegativeMatchersAreDiscriminating() {
        assertTrue(MatcherEngine.isDiscriminating(List.of(
            Map.of("type", "status", "status", List.of(200)),
            Map.of("type", "not_header", "header", "Strict-Transport-Security")
        )));
        assertTrue(MatcherEngine.isDiscriminating(List.of(
            Map.of("type", "not_word", "words", List.of("login"))
        )));
    }

    @Test
    void contentMatchersAreDiscriminating() {
        assertTrue(MatcherEngine.isDiscriminating(List.of(
            Map.of("type", "word", "words", List.of("SQL syntax"))
        )));
    }

    @Test
    void emptyMatcherSetIsNotDiscriminating() {
        assertFalse(MatcherEngine.isDiscriminating(List.of()));
    }

    // ── Baseline-equivalence guard ────────────────────────────────────────
    // isDiscriminating() judges matcher SHAPE and cannot see that the untouched
    // baseline already satisfies the set. status:200 + not_word:[auth-errors]
    // and the XFF-403-bypass shape "look" discriminating yet fire on every
    // public 200 page. The guard re-runs the matchers against the baseline; if
    // the baseline matches too, the probe proved nothing.

    @Test
    void baselineSatisfyingMatchersIsSuppressed() {
        // fail_open_on_parser_error shape against a public page: baseline is
        // already 200 and already lacks the auth-error words, so the malformed-
        // bearer probe response is indistinguishable from baseline.
        List<Map<String, Object>> matchers = List.of(
            Map.of("type", "status", "status", List.of(200)),
            Map.of("type", "not_word", "words", List.of("unauthorized", "forbidden", "invalid token"))
        );
        HttpResponse baseline = stubResponse(200, "<html>forum thread list</html>", List.of());
        HttpResponse probe = stubResponse(200, "<html>forum thread list</html>", List.of());

        Map<String, Object> r = MatcherEngine.evaluate(matchers, probe, 12L, baseline, "Bearer not_a_jwt");
        assertEquals(Boolean.FALSE, r.get("matched"),
            "a probe response identical to baseline must not score as a bypass");
        assertEquals(Boolean.TRUE, r.get("baseline_equivalent"),
            "suppression reason must be tagged for diagnostics");
    }

    @Test
    void xffBypassOnAlready200EndpointIsSuppressed() {
        // xff_403_bypass shape: status:[200,302] + not_status:[403,401].
        List<Map<String, Object>> matchers = List.of(
            Map.of("type", "status", "status", List.of(200, 302)),
            Map.of("type", "not_status", "status", List.of(403, 401))
        );
        HttpResponse baseline = stubResponse(200, "page", List.of());
        HttpResponse probe = stubResponse(200, "page", List.of());

        Map<String, Object> r = MatcherEngine.evaluate(matchers, probe, 5L, baseline, "1");
        assertEquals(Boolean.FALSE, r.get("matched"),
            "an XFF 'bypass' on an endpoint that was never 403 is a false positive");
    }

    @Test
    void genuineXffBypassAgainst403BaselineStillFires() {
        List<Map<String, Object>> matchers = List.of(
            Map.of("type", "status", "status", List.of(200, 302)),
            Map.of("type", "not_status", "status", List.of(403, 401))
        );
        HttpResponse baseline = stubResponse(403, "denied", List.of());        // ACL blocks by default
        HttpResponse probe = stubResponse(200, "admin panel", List.of());      // XFF flips it open

        Map<String, Object> r = MatcherEngine.evaluate(matchers, probe, 5L, baseline, "1");
        assertEquals(Boolean.TRUE, r.get("matched"),
            "a real 403->200 flip is the finding the guard must preserve");
    }

    @Test
    void errorStatusProbeNotSuppressedBy200Baseline() {
        List<Map<String, Object>> matchers = List.of(
            Map.of("type", "status", "status", List.of(500))
        );
        HttpResponse baseline = stubResponse(200, "ok", List.of());
        HttpResponse probe = stubResponse(500, "pg_query error", List.of());

        Map<String, Object> r = MatcherEngine.evaluate(matchers, probe, 5L, baseline, "' OR 1=1");
        assertEquals(Boolean.TRUE, r.get("matched"),
            "blind-SQLi 500-vs-200 must survive the baseline guard");
    }

    @Test
    void lengthDiffProbeSurvivesEvenWhenStatusMatchesBaseline() {
        // status matches baseline, but the length delta is genuine -> keep it.
        List<Map<String, Object>> matchers = List.of(
            Map.of("type", "status", "status", List.of(200)),
            Map.of("type", "length_diff", "min_diff", 50)
        );
        HttpResponse baseline = stubResponse(200, "short", List.of());
        HttpResponse probe = stubResponse(200, "x".repeat(500), List.of());

        Map<String, Object> r = MatcherEngine.evaluate(matchers, probe, 5L, baseline, "p");
        assertEquals(Boolean.TRUE, r.get("matched"),
            "a real length delta is discriminating even when status equals baseline");
    }
}
