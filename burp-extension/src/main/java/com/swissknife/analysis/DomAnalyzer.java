package com.swissknife.analysis;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyze HTML structure and detect JavaScript sinks, sources, prototype pollution,
 * and dangerous patterns for DOM XSS and client-side vulnerability detection.
 * Pure regex-based — no external dependencies or headless browser required.
 */
public final class DomAnalyzer {

    private DomAnalyzer() {}

    private static final int MAX_CONTEXT_LENGTH = 200;

    // --- HTML Structure Patterns ---

    private static final Pattern HIDDEN_FIELD_PATTERN = Pattern.compile(
        "<input[^>]*type\\s*=\\s*[\"']hidden[\"'][^>]*>", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern HIDDEN_NAME_PATTERN = Pattern.compile(
        "name\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern HIDDEN_VALUE_PATTERN = Pattern.compile(
        "value\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SCRIPT_BLOCK_PATTERN = Pattern.compile(
        "<script[^>]*>(.*?)</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    private static final Pattern EVENT_HANDLER_PATTERN = Pattern.compile(
        "<(\\w+)[^>]*(on(?:click|load|error|mouseover|mouseout|mousedown|mouseup|mousemove|"
            + "keydown|keyup|keypress|submit|change|focus|blur|input|dblclick|contextmenu|"
            + "resize|scroll|unload|beforeunload|hashchange|popstate|message|storage|"
            + "drag|dragstart|dragend|dragover|dragenter|dragleave|drop|copy|cut|paste|"
            + "touchstart|touchend|touchmove))\\s*=\\s*[\"']([^\"']*)[\"']",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern IFRAME_PATTERN = Pattern.compile(
        "<iframe[^>]*src\\s*=\\s*[\"']([^\"']*)[\"'][^>]*>", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern COMMENT_PATTERN = Pattern.compile(
        "<!--(.*?)-->", Pattern.DOTALL
    );

    private static final Pattern META_PATTERN = Pattern.compile(
        "<meta[^>]*name\\s*=\\s*[\"']([^\"']*)[\"'][^>]*content\\s*=\\s*[\"']([^\"']*)[\"'][^>]*>",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern META_REVERSE_PATTERN = Pattern.compile(
        "<meta[^>]*content\\s*=\\s*[\"']([^\"']*)[\"'][^>]*name\\s*=\\s*[\"']([^\"']*)[\"'][^>]*>",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern DATA_ATTR_PATTERN = Pattern.compile(
        "(data-[\\w-]+)\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE
    );

    // --- Framework Detection Patterns ---

    private static final Pattern ANGULAR_NG_PATTERN = Pattern.compile(
        "(?:ng-app|ng-controller|ng-model|ng-bind|ng-click|ng-repeat|ng-if|ng-show|ng-hide|"
            + "\\[ngModel\\]|\\[ngIf\\]|\\(click\\)|\\(ngSubmit\\))",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern ANGULAR_TEMPLATE_PATTERN = Pattern.compile("\\{\\{.*?\\}\\}");

    private static final Pattern REACT_PATTERN = Pattern.compile(
        "(?:data-reactroot|data-reactid|_reactRootContainer|__NEXT_DATA__|__next)",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern VUE_PATTERN = Pattern.compile(
        "(?:v-model|v-bind|v-if|v-for|v-show|v-on:|:click|:class|:style|v-html|v-text|@click|@submit)",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern JQUERY_PATTERN = Pattern.compile("\\$\\s*\\(");

    private static final Pattern EMBER_PATTERN = Pattern.compile(
        "(?:data-ember-|ember-view|Ember\\.)", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SVELTE_PATTERN = Pattern.compile(
        "(?:svelte-|__svelte)", Pattern.CASE_INSENSITIVE
    );

    // --- JS Sink Patterns ---

    private static final Pattern SINK_INNER_HTML = Pattern.compile(
        "\\.(innerHTML|outerHTML)\\s*=", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SINK_DOC_WRITE = Pattern.compile(
        "document\\s*\\.\\s*(write|writeln)\\s*\\(", Pattern.CASE_INSENSITIVE
    );
    // Detects eval() and Function() calls — this is a DETECTION pattern, not execution
    private static final Pattern SINK_EVAL = Pattern.compile(
        "\\b(eval|Function)\\s*\\(", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SINK_TIMEOUT_STRING = Pattern.compile(
        "\\b(setTimeout|setInterval)\\s*\\(\\s*[^,)]*[^\"'`\\s,)]", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SINK_LOCATION_ASSIGN = Pattern.compile(
        "location\\s*\\.\\s*(href\\s*=|assign\\s*\\(|replace\\s*\\()", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SINK_WINDOW_OPEN = Pattern.compile(
        "window\\s*\\.\\s*open\\s*\\(", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SINK_JQUERY_HTML = Pattern.compile(
        "(?:\\$\\s*\\([^)]*\\)\\s*\\.\\s*html\\s*\\(|\\.html\\s*\\()", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SINK_VUE_HTML = Pattern.compile("v-html\\s*=", Pattern.CASE_INSENSITIVE);
    private static final Pattern SINK_REACT_DANGEROUS = Pattern.compile("dangerouslySetInnerHTML", Pattern.CASE_INSENSITIVE);
    private static final Pattern SINK_ANGULAR_INNERHTML = Pattern.compile("\\[innerHTML\\]", Pattern.CASE_INSENSITIVE);
    private static final Pattern SINK_ELEMENT_SRC = Pattern.compile(
        "\\.(src|action)\\s*=", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SINK_POST_MESSAGE = Pattern.compile(
        "\\.postMessage\\s*\\(", Pattern.CASE_INSENSITIVE
    );

    // --- JS Source Patterns ---

    private static final Pattern SOURCE_LOCATION = Pattern.compile(
        "location\\s*\\.\\s*(hash|search|href|pathname)", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SOURCE_DOC_REFERRER = Pattern.compile(
        "document\\s*\\.\\s*referrer", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SOURCE_DOC_URL = Pattern.compile(
        "document\\s*\\.\\s*(URL|documentURI)", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SOURCE_WINDOW_NAME = Pattern.compile(
        "window\\s*\\.\\s*name", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SOURCE_COOKIE = Pattern.compile(
        "document\\s*\\.\\s*cookie", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SOURCE_STORAGE = Pattern.compile(
        "(localStorage|sessionStorage)", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SOURCE_URL_PARAMS = Pattern.compile(
        "URLSearchParams", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SOURCE_MESSAGE_LISTENER = Pattern.compile(
        "(?:addEventListener\\s*\\(\\s*[\"']message[\"']|onmessage\\s*=)", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SOURCE_AJAX = Pattern.compile(
        "(?:\\$\\.ajax\\s*\\(|fetch\\s*\\(|XMLHttpRequest)", Pattern.CASE_INSENSITIVE
    );

    // --- Prototype Pollution Patterns ---

    private static final Pattern PROTO_DIRECT = Pattern.compile("__proto__");
    private static final Pattern PROTO_CONSTRUCTOR = Pattern.compile(
        "constructor\\s*\\.\\s*prototype", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern PROTO_MERGE = Pattern.compile(
        "(?:Object\\s*\\.\\s*assign|_\\.merge|\\$\\.extend|lodash\\.merge|deepmerge|deep[_-]?extend)",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern PROTO_BRACKET = Pattern.compile(
        "\\w+\\s*\\[\\s*\\w+\\s*\\]\\s*=", Pattern.CASE_INSENSITIVE
    );

    // --- Dangerous Pattern Detection ---
    // Detects dangerous eval with variable args — DETECTION only, not execution
    private static final Pattern DANGER_EVAL_VAR = Pattern.compile(
        "eval\\s*\\(\\s*[a-zA-Z_$][\\w$.]*\\s*\\)", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern DANGER_TEMPLATE_LITERAL = Pattern.compile(
        "`[^`]*\\$\\{[^}]+\\}[^`]*`"
    );
    private static final Pattern DANGER_JSON_PARSE = Pattern.compile(
        "JSON\\s*\\.\\s*parse\\s*\\(", Pattern.CASE_INSENSITIVE
    );

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
        result.put("html_analysis", analyzeHtml(body));
        result.put("js_analysis", analyzeJs(body));
        return result;
    }

    // ---- HTML Analysis ----

    private static Map<String, Object> analyzeHtml(String body) {
        Map<String, Object> html = new LinkedHashMap<>();

        html.put("hidden_fields", extractHiddenFields(body));
        html.put("inline_scripts", extractInlineScripts(body));
        html.put("event_handlers", extractEventHandlers(body));
        html.put("iframes", extractIframes(body));
        html.put("comments", extractComments(body));
        html.put("meta_tags", extractMetaTags(body));
        html.put("data_attributes", extractDataAttributes(body));
        html.put("frameworks", detectFrameworks(body));

        return html;
    }

    private static List<Map<String, Object>> extractHiddenFields(String body) {
        List<Map<String, Object>> fields = new ArrayList<>();
        Matcher m = HIDDEN_FIELD_PATTERN.matcher(body);
        while (m.find()) {
            String tag = m.group(0);
            Map<String, Object> field = new LinkedHashMap<>();

            Matcher nm = HIDDEN_NAME_PATTERN.matcher(tag);
            field.put("name", nm.find() ? nm.group(1) : "");

            Matcher vm = HIDDEN_VALUE_PATTERN.matcher(tag);
            field.put("value", vm.find() ? truncate(vm.group(1)) : "");

            fields.add(field);
        }
        return fields;
    }

    private static List<Map<String, Object>> extractInlineScripts(String body) {
        List<Map<String, Object>> scripts = new ArrayList<>();
        Matcher m = SCRIPT_BLOCK_PATTERN.matcher(body);
        while (m.find()) {
            String content = m.group(1).trim();
            if (content.isEmpty()) continue;

            Map<String, Object> script = new LinkedHashMap<>();
            script.put("content", truncate(content));
            script.put("line", lineNumber(body, m.start()));
            scripts.add(script);
        }
        return scripts;
    }

    private static List<Map<String, Object>> extractEventHandlers(String body) {
        List<Map<String, Object>> handlers = new ArrayList<>();
        Matcher m = EVENT_HANDLER_PATTERN.matcher(body);
        while (m.find()) {
            Map<String, Object> handler = new LinkedHashMap<>();
            handler.put("event", m.group(2).toLowerCase());
            handler.put("handler", truncate(m.group(3)));
            handler.put("element", m.group(1).toLowerCase());
            handlers.add(handler);
        }
        return handlers;
    }

    private static List<Map<String, Object>> extractIframes(String body) {
        List<Map<String, Object>> iframes = new ArrayList<>();
        Matcher m = IFRAME_PATTERN.matcher(body);
        while (m.find()) {
            Map<String, Object> iframe = new LinkedHashMap<>();
            iframe.put("src", m.group(1));
            iframes.add(iframe);
        }
        return iframes;
    }

    private static List<Map<String, Object>> extractComments(String body) {
        List<Map<String, Object>> comments = new ArrayList<>();
        Matcher m = COMMENT_PATTERN.matcher(body);
        while (m.find()) {
            String content = m.group(1).trim();
            if (content.isEmpty()) continue;

            Map<String, Object> comment = new LinkedHashMap<>();
            comment.put("content", truncate(content));
            comment.put("position", m.start());
            comments.add(comment);
        }
        return comments;
    }

    private static List<Map<String, Object>> extractMetaTags(String body) {
        List<Map<String, Object>> metas = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        // name then content order
        Matcher m = META_PATTERN.matcher(body);
        while (m.find()) {
            String name = m.group(1);
            if (seen.add(name.toLowerCase())) {
                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put("name", name);
                meta.put("content", truncate(m.group(2)));
                metas.add(meta);
            }
        }

        // content then name order
        m = META_REVERSE_PATTERN.matcher(body);
        while (m.find()) {
            String name = m.group(2);
            if (seen.add(name.toLowerCase())) {
                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put("name", name);
                meta.put("content", truncate(m.group(1)));
                metas.add(meta);
            }
        }

        return metas;
    }

    private static List<Map<String, Object>> extractDataAttributes(String body) {
        List<Map<String, Object>> attrs = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Matcher m = DATA_ATTR_PATTERN.matcher(body);
        while (m.find()) {
            String name = m.group(1);
            String value = m.group(2);
            String key = name.toLowerCase() + "=" + value;
            if (seen.add(key)) {
                Map<String, Object> attr = new LinkedHashMap<>();
                attr.put("name", name);
                attr.put("value", truncate(value));
                attrs.add(attr);
            }
        }
        return attrs;
    }

    private static List<String> detectFrameworks(String body) {
        List<String> frameworks = new ArrayList<>();

        if (ANGULAR_NG_PATTERN.matcher(body).find() || ANGULAR_TEMPLATE_PATTERN.matcher(body).find()) {
            frameworks.add("Angular");
        }
        if (REACT_PATTERN.matcher(body).find()) {
            frameworks.add("React");
        }
        if (VUE_PATTERN.matcher(body).find()) {
            frameworks.add("Vue.js");
        }
        if (JQUERY_PATTERN.matcher(body).find()) {
            // Try to find jQuery version
            Matcher verMatcher = Pattern.compile("jquery[/.-]?(\\d+\\.\\d+(?:\\.\\d+)?)", Pattern.CASE_INSENSITIVE).matcher(body);
            frameworks.add(verMatcher.find() ? "jQuery " + verMatcher.group(1) : "jQuery");
        }
        if (EMBER_PATTERN.matcher(body).find()) {
            frameworks.add("Ember.js");
        }
        if (SVELTE_PATTERN.matcher(body).find()) {
            frameworks.add("Svelte");
        }

        return frameworks;
    }

    // ---- JavaScript Analysis ----

    private static Map<String, Object> analyzeJs(String body) {
        Map<String, Object> js = new LinkedHashMap<>();

        // Collect all inline script contents for flow analysis
        List<String> scriptBlocks = new ArrayList<>();
        Matcher scriptMatcher = SCRIPT_BLOCK_PATTERN.matcher(body);
        while (scriptMatcher.find()) {
            String content = scriptMatcher.group(1).trim();
            if (!content.isEmpty()) {
                scriptBlocks.add(content);
            }
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

        findPatternMatches(sinks, body, SINK_INNER_HTML, "innerHTML/outerHTML", "HIGH");
        findPatternMatches(sinks, body, SINK_DOC_WRITE, "document.write", "HIGH");
        findPatternMatches(sinks, body, SINK_EVAL, "eval/Function", "CRITICAL");
        findPatternMatches(sinks, body, SINK_TIMEOUT_STRING, "setTimeout/setInterval with string", "HIGH");
        findPatternMatches(sinks, body, SINK_LOCATION_ASSIGN, "location assignment", "HIGH");
        findPatternMatches(sinks, body, SINK_WINDOW_OPEN, "window.open", "MEDIUM");
        findPatternMatches(sinks, body, SINK_JQUERY_HTML, "jQuery .html()", "HIGH");
        findPatternMatches(sinks, body, SINK_VUE_HTML, "v-html (Vue)", "HIGH");
        findPatternMatches(sinks, body, SINK_REACT_DANGEROUS, "dangerouslySetInnerHTML (React)", "HIGH");
        findPatternMatches(sinks, body, SINK_ANGULAR_INNERHTML, "[innerHTML] (Angular)", "HIGH");
        findPatternMatches(sinks, body, SINK_ELEMENT_SRC, "element.src/action assignment", "MEDIUM");
        findPatternMatches(sinks, body, SINK_POST_MESSAGE, "postMessage", "MEDIUM");

        return sinks;
    }

    private static List<Map<String, Object>> detectSources(String body) {
        List<Map<String, Object>> sources = new ArrayList<>();

        findPatternMatches(sources, body, SOURCE_LOCATION, "location property", "HIGH");
        findPatternMatches(sources, body, SOURCE_DOC_REFERRER, "document.referrer", "HIGH");
        findPatternMatches(sources, body, SOURCE_DOC_URL, "document.URL/documentURI", "HIGH");
        findPatternMatches(sources, body, SOURCE_WINDOW_NAME, "window.name", "HIGH");
        findPatternMatches(sources, body, SOURCE_COOKIE, "document.cookie", "MEDIUM");
        findPatternMatches(sources, body, SOURCE_STORAGE, "localStorage/sessionStorage", "MEDIUM");
        findPatternMatches(sources, body, SOURCE_URL_PARAMS, "URLSearchParams", "HIGH");
        findPatternMatches(sources, body, SOURCE_MESSAGE_LISTENER, "postMessage listener", "HIGH");
        findPatternMatches(sources, body, SOURCE_AJAX, "AJAX/fetch/XHR", "MEDIUM");

        return sources;
    }

    private static List<Map<String, Object>> detectPrototypePollution(String body) {
        List<Map<String, Object>> results = new ArrayList<>();

        findPatternMatches(results, body, PROTO_DIRECT, "__proto__ usage", "HIGH");
        findPatternMatches(results, body, PROTO_CONSTRUCTOR, "constructor.prototype", "HIGH");
        findPatternMatches(results, body, PROTO_MERGE, "deep merge/extend", "MEDIUM");
        findPatternMatches(results, body, PROTO_BRACKET, "bracket notation assignment", "LOW");

        return results;
    }

    private static List<Map<String, Object>> detectDangerousPatterns(String body) {
        List<Map<String, Object>> results = new ArrayList<>();

        findPatternMatches(results, body, DANGER_EVAL_VAR, "eval with variable", "CRITICAL");
        findPatternMatches(results, body, DANGER_TEMPLATE_LITERAL, "template literal interpolation", "MEDIUM");
        findPatternMatches(results, body, DANGER_JSON_PARSE, "JSON.parse", "LOW");

        return results;
    }

    /**
     * Heuristic flow detection: if a source keyword appears alongside a sink keyword
     * in the same script block, flag it as a potential data flow.
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

    // ---- Helpers ----

    private static void findPatternMatches(List<Map<String, Object>> results, String body,
                                           Pattern pattern, String type, String risk) {
        Matcher m = pattern.matcher(body);
        while (m.find()) {
            Map<String, Object> match = new LinkedHashMap<>();
            match.put("type", type);
            match.put("context", truncate(extractContext(body, m.start(), m.end())));
            match.put("line_approx", lineNumber(body, m.start()));
            match.put("risk", risk);
            results.add(match);
        }
    }

    private static String extractContext(String body, int matchStart, int matchEnd) {
        int lineStart = body.lastIndexOf('\n', matchStart);
        lineStart = (lineStart < 0) ? 0 : lineStart + 1;

        int lineEnd = body.indexOf('\n', matchEnd);
        if (lineEnd < 0) lineEnd = body.length();

        return body.substring(lineStart, Math.min(lineEnd, body.length())).trim();
    }

    private static int lineNumber(String body, int position) {
        int line = 1;
        for (int i = 0; i < position && i < body.length(); i++) {
            if (body.charAt(i) == '\n') line++;
        }
        return line;
    }

    private static String truncate(String s) {
        if (s == null) return "";
        return s.length() > MAX_CONTEXT_LENGTH ? s.substring(0, MAX_CONTEXT_LENGTH) + "..." : s;
    }
}
