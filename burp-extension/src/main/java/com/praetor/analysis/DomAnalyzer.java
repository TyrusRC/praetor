package com.praetor.analysis;

import com.praetor.analysis.dom.HtmlAnalyzer;
import com.praetor.analysis.dom.JsFlowAnalyzer;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Analyze HTML structure and detect JavaScript sinks, sources, prototype pollution,
 * and dangerous patterns for DOM XSS and client-side vulnerability detection.
 * Pure regex-based — no external dependencies or headless browser required.
 *
 * Thin facade. The implementation lives in {@link HtmlAnalyzer} and
 * {@link JsFlowAnalyzer}; the regex catalog is in {@code dom.DomPatterns}.
 */
public final class DomAnalyzer {

    private DomAnalyzer() {}

    /**
     * Analyze HTML body for DOM structure, JavaScript sinks/sources,
     * prototype pollution patterns, and dangerous code constructs.
     */
    public static Map<String, Object> analyze(String body) {
        if (body == null || body.isEmpty()) {
            Map<String, Object> empty = new LinkedHashMap<>();
            empty.put("html_analysis", new LinkedHashMap<>());
            empty.put("js_analysis", new LinkedHashMap<>());
            return empty;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("html_analysis", HtmlAnalyzer.analyze(body));
        result.put("js_analysis", JsFlowAnalyzer.analyze(body));
        return result;
    }
}
