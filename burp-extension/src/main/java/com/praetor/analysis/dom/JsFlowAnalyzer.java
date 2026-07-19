package com.praetor.analysis.dom;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * JavaScript flow analysis: sinks, sources, prototype pollution patterns,
 * dangerous constructs, and source→sink heuristic flow detection.
 */
public final class JsFlowAnalyzer {

    private JsFlowAnalyzer() {}

    public static Map<String, Object> analyze(String body) {
        Map<String, Object> js = new LinkedHashMap<>();

        // Collect all inline script contents for flow analysis.
        List<String> scriptBlocks = new ArrayList<>();
        Matcher scriptMatcher = DomPatterns.SCRIPT_BLOCK.matcher(body);
        while (scriptMatcher.find()) {
            String content = scriptMatcher.group(1).trim();
            if (!content.isEmpty()) scriptBlocks.add(content);
        }

        List<Map<String, Object>> sinks = detectSinks(body);
        List<Map<String, Object>> sources = detectSources(body);
        List<Map<String, Object>> protoPollution = detectPrototypePollution(body);
        List<Map<String, Object>> dangerousPatterns = detectDangerousPatterns(body);
        List<Map<String, Object>> potentialFlows = detectPotentialFlows(scriptBlocks);

        js.put("sinks", sinks);
        js.put("sources", sources);
        js.put("prototype_pollution", protoPollution);
        js.put("dangerous_patterns", dangerousPatterns);
        js.put("total_sinks", sinks.size());
        js.put("total_sources", sources.size());
        js.put("potential_flows", potentialFlows);

        return js;
    }

    private static List<Map<String, Object>> detectSinks(String body) {
        List<Map<String, Object>> sinks = new ArrayList<>();
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_INNER_HTML, "innerHTML/outerHTML", "HIGH");
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_DOC_WRITE, "document.write", "HIGH");
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_EVAL, "eval/Function", "CRITICAL");
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_TIMEOUT_STRING, "setTimeout/setInterval with string", "HIGH");
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_LOCATION_ASSIGN, "location assignment", "HIGH");
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_WINDOW_OPEN, "window.open", "MEDIUM");
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_JQUERY_HTML, "jQuery .html()", "HIGH");
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_VUE_HTML, "v-html (Vue)", "HIGH");
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_REACT_DANGEROUS, "dangerouslySetInnerHTML (React)", "HIGH");
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_ANGULAR_INNERHTML, "[innerHTML] (Angular)", "HIGH");
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_ELEMENT_SRC, "element.src/action assignment", "MEDIUM");
        DomHelpers.findPatternMatches(sinks, body, DomPatterns.SINK_POST_MESSAGE, "postMessage", "MEDIUM");
        return sinks;
    }

    private static List<Map<String, Object>> detectSources(String body) {
        List<Map<String, Object>> sources = new ArrayList<>();
        DomHelpers.findPatternMatches(sources, body, DomPatterns.SOURCE_LOCATION, "location property", "HIGH");
        DomHelpers.findPatternMatches(sources, body, DomPatterns.SOURCE_DOC_REFERRER, "document.referrer", "HIGH");
        DomHelpers.findPatternMatches(sources, body, DomPatterns.SOURCE_DOC_URL, "document.URL/documentURI", "HIGH");
        DomHelpers.findPatternMatches(sources, body, DomPatterns.SOURCE_WINDOW_NAME, "window.name", "HIGH");
        DomHelpers.findPatternMatches(sources, body, DomPatterns.SOURCE_COOKIE, "document.cookie", "MEDIUM");
        DomHelpers.findPatternMatches(sources, body, DomPatterns.SOURCE_STORAGE, "localStorage/sessionStorage", "MEDIUM");
        DomHelpers.findPatternMatches(sources, body, DomPatterns.SOURCE_URL_PARAMS, "URLSearchParams", "HIGH");
        DomHelpers.findPatternMatches(sources, body, DomPatterns.SOURCE_MESSAGE_LISTENER, "postMessage listener", "HIGH");
        DomHelpers.findPatternMatches(sources, body, DomPatterns.SOURCE_AJAX, "AJAX/fetch/XHR", "MEDIUM");
        return sources;
    }

    private static List<Map<String, Object>> detectPrototypePollution(String body) {
        List<Map<String, Object>> results = new ArrayList<>();
        DomHelpers.findPatternMatches(results, body, DomPatterns.PROTO_DIRECT, "__proto__ usage", "HIGH");
        DomHelpers.findPatternMatches(results, body, DomPatterns.PROTO_CONSTRUCTOR, "constructor.prototype", "HIGH");
        DomHelpers.findPatternMatches(results, body, DomPatterns.PROTO_MERGE, "deep merge/extend", "MEDIUM");
        DomHelpers.findPatternMatches(results, body, DomPatterns.PROTO_BRACKET, "bracket notation assignment", "LOW");
        return results;
    }

    private static List<Map<String, Object>> detectDangerousPatterns(String body) {
        List<Map<String, Object>> results = new ArrayList<>();
        DomHelpers.findPatternMatches(results, body, DomPatterns.DANGER_EVAL_VAR, "eval with variable", "CRITICAL");
        DomHelpers.findPatternMatches(results, body, DomPatterns.DANGER_TEMPLATE_LITERAL, "template literal interpolation", "MEDIUM");
        DomHelpers.findPatternMatches(results, body, DomPatterns.DANGER_JSON_PARSE, "JSON.parse", "LOW");
        return results;
    }

    /**
     * Heuristic flow detection: if a source keyword appears alongside a sink
     * keyword in the same script block, flag it as a potential data flow.
     */
    private static List<Map<String, Object>> detectPotentialFlows(List<String> scriptBlocks) {
        List<Map<String, Object>> flows = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        String[] sourceKeys = {
            "location.hash", "location.search", "location.href", "location.pathname",
            "document.referrer", "document.URL", "document.cookie",
            "window.name", "localStorage", "sessionStorage", "URLSearchParams"
        };

        String[] sinkKeys = {
            "innerHTML", "outerHTML", "document.write",
            ".html(", "v-html", "dangerouslySetInnerHTML",
            "window.open", "postMessage"
        };

        for (String block : scriptBlocks) {
            for (String sourceKey : sourceKeys) {
                if (!block.contains(sourceKey)) continue;

                for (String sinkKey : sinkKeys) {
                    if (!block.contains(sinkKey)) continue;

                    String flowKey = sourceKey + " -> " + sinkKey;
                    if (seen.add(flowKey)) {
                        Map<String, Object> flow = new LinkedHashMap<>();
                        flow.put("source", sourceKey);
                        flow.put("sink", sinkKey);
                        flow.put("description", sourceKey + " value flows to " + sinkKey + " assignment");
                        flows.add(flow);
                    }
                }
            }
        }

        return flows;
    }
}
