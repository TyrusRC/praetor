package com.swissknife.analysis;

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
}
