package com.praetor.analysis.dom;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * HTML structure analysis: hidden fields, inline scripts, event handlers,
 * iframes, comments, meta tags, data-* attributes, framework detection.
 */
public final class HtmlAnalyzer {

    private HtmlAnalyzer() {}

    public static Map<String, Object> analyze(String body) {
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
        Matcher m = DomPatterns.HIDDEN_FIELD.matcher(body);
        while (m.find()) {
            String tag = m.group(0);
            Map<String, Object> field = new LinkedHashMap<>();
            Matcher nm = DomPatterns.HIDDEN_NAME.matcher(tag);
            field.put("name", nm.find() ? nm.group(1) : "");
            Matcher vm = DomPatterns.HIDDEN_VALUE.matcher(tag);
            field.put("value", vm.find() ? DomHelpers.truncate(vm.group(1)) : "");
            fields.add(field);
        }
        return fields;
    }

    private static List<Map<String, Object>> extractInlineScripts(String body) {
        List<Map<String, Object>> scripts = new ArrayList<>();
        Matcher m = DomPatterns.SCRIPT_BLOCK.matcher(body);
        while (m.find()) {
            String content = m.group(1).trim();
            if (content.isEmpty()) continue;
            Map<String, Object> script = new LinkedHashMap<>();
            script.put("content", DomHelpers.truncate(content));
            script.put("line", DomHelpers.lineNumber(body, m.start()));
            scripts.add(script);
        }
        return scripts;
    }

    private static List<Map<String, Object>> extractEventHandlers(String body) {
        List<Map<String, Object>> handlers = new ArrayList<>();
        Matcher m = DomPatterns.EVENT_HANDLER.matcher(body);
        while (m.find()) {
            Map<String, Object> handler = new LinkedHashMap<>();
            handler.put("event", m.group(2).toLowerCase());
            handler.put("handler", DomHelpers.truncate(m.group(3)));
            handler.put("element", m.group(1).toLowerCase());
            handlers.add(handler);
        }
        return handlers;
    }

    private static List<Map<String, Object>> extractIframes(String body) {
        List<Map<String, Object>> iframes = new ArrayList<>();
        Matcher m = DomPatterns.IFRAME.matcher(body);
        while (m.find()) {
            Map<String, Object> iframe = new LinkedHashMap<>();
            iframe.put("src", m.group(1));
            iframes.add(iframe);
        }
        return iframes;
    }

    private static List<Map<String, Object>> extractComments(String body) {
        List<Map<String, Object>> comments = new ArrayList<>();
        Matcher m = DomPatterns.COMMENT.matcher(body);
        while (m.find()) {
            String content = m.group(1).trim();
            if (content.isEmpty()) continue;
            Map<String, Object> comment = new LinkedHashMap<>();
            comment.put("content", DomHelpers.truncate(content));
            comment.put("position", m.start());
            comments.add(comment);
        }
        return comments;
    }

    private static List<Map<String, Object>> extractMetaTags(String body) {
        List<Map<String, Object>> metas = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        Matcher m = DomPatterns.META.matcher(body);
        while (m.find()) {
            String name = m.group(1);
            if (seen.add(name.toLowerCase())) {
                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put("name", name);
                meta.put("content", DomHelpers.truncate(m.group(2)));
                metas.add(meta);
            }
        }

        m = DomPatterns.META_REVERSE.matcher(body);
        while (m.find()) {
            String name = m.group(2);
            if (seen.add(name.toLowerCase())) {
                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put("name", name);
                meta.put("content", DomHelpers.truncate(m.group(1)));
                metas.add(meta);
            }
        }

        return metas;
    }

    private static List<Map<String, Object>> extractDataAttributes(String body) {
        List<Map<String, Object>> attrs = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Matcher m = DomPatterns.DATA_ATTR.matcher(body);
        while (m.find()) {
            String name = m.group(1);
            String value = m.group(2);
            String key = name.toLowerCase() + "=" + value;
            if (seen.add(key)) {
                Map<String, Object> attr = new LinkedHashMap<>();
                attr.put("name", name);
                attr.put("value", DomHelpers.truncate(value));
                attrs.add(attr);
            }
        }
        return attrs;
    }

    private static List<String> detectFrameworks(String body) {
        List<String> frameworks = new ArrayList<>();
        if (DomPatterns.ANGULAR_NG.matcher(body).find() || DomPatterns.ANGULAR_TEMPLATE.matcher(body).find()) {
            frameworks.add("Angular");
        }
        if (DomPatterns.REACT.matcher(body).find()) frameworks.add("React");
        if (DomPatterns.VUE.matcher(body).find()) frameworks.add("Vue.js");
        if (DomPatterns.JQUERY.matcher(body).find()) {
            Matcher verMatcher = DomPatterns.JQUERY_VERSION.matcher(body);
            frameworks.add(verMatcher.find() ? "jQuery " + verMatcher.group(1) : "jQuery");
        }
        if (DomPatterns.EMBER.matcher(body).find()) frameworks.add("Ember.js");
        if (DomPatterns.SVELTE.matcher(body).find()) frameworks.add("Svelte");
        return frameworks;
    }
}
