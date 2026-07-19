package com.praetor.analysis.dom;

import java.util.regex.Pattern;

/**
 * Compiled regex catalog for DOM/HTML/JS analysis. Patterns are pre-compiled
 * once at class load. Package-private — only the dom/* analyzers depend on
 * the layout.
 */
final class DomPatterns {

    private DomPatterns() {}

    // ── HTML structure ─────────────────────────────────────────

    static final Pattern HIDDEN_FIELD = Pattern.compile(
        "<input[^>]*type\\s*=\\s*[\"']hidden[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
    static final Pattern HIDDEN_NAME = Pattern.compile(
        "name\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
    static final Pattern HIDDEN_VALUE = Pattern.compile(
        "value\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

    static final Pattern SCRIPT_BLOCK = Pattern.compile(
        "<script[^>]*>(.*?)</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    static final Pattern EVENT_HANDLER = Pattern.compile(
        "<(\\w+)[^>]*(on(?:click|load|error|mouseover|mouseout|mousedown|mouseup|mousemove|"
            + "keydown|keyup|keypress|submit|change|focus|blur|input|dblclick|contextmenu|"
            + "resize|scroll|unload|beforeunload|hashchange|popstate|message|storage|"
            + "drag|dragstart|dragend|dragover|dragenter|dragleave|drop|copy|cut|paste|"
            + "touchstart|touchend|touchmove))\\s*=\\s*[\"']([^\"']*)[\"']",
        Pattern.CASE_INSENSITIVE);

    static final Pattern IFRAME = Pattern.compile(
        "<iframe[^>]*src\\s*=\\s*[\"']([^\"']*)[\"'][^>]*>", Pattern.CASE_INSENSITIVE);

    static final Pattern COMMENT = Pattern.compile("<!--(.*?)-->", Pattern.DOTALL);

    static final Pattern META = Pattern.compile(
        "<meta[^>]*name\\s*=\\s*[\"']([^\"']*)[\"'][^>]*content\\s*=\\s*[\"']([^\"']*)[\"'][^>]*>",
        Pattern.CASE_INSENSITIVE);
    static final Pattern META_REVERSE = Pattern.compile(
        "<meta[^>]*content\\s*=\\s*[\"']([^\"']*)[\"'][^>]*name\\s*=\\s*[\"']([^\"']*)[\"'][^>]*>",
        Pattern.CASE_INSENSITIVE);

    static final Pattern DATA_ATTR = Pattern.compile(
        "(data-[\\w-]+)\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

    // ── Framework detection ────────────────────────────────────

    static final Pattern ANGULAR_NG = Pattern.compile(
        "(?:ng-app|ng-controller|ng-model|ng-bind|ng-click|ng-repeat|ng-if|ng-show|ng-hide|"
            + "\\[ngModel\\]|\\[ngIf\\]|\\(click\\)|\\(ngSubmit\\))",
        Pattern.CASE_INSENSITIVE);
    static final Pattern ANGULAR_TEMPLATE = Pattern.compile("\\{\\{.*?\\}\\}");

    static final Pattern REACT = Pattern.compile(
        "(?:data-reactroot|data-reactid|_reactRootContainer|__NEXT_DATA__|__next)",
        Pattern.CASE_INSENSITIVE);

    static final Pattern VUE = Pattern.compile(
        "(?:v-model|v-bind|v-if|v-for|v-show|v-on:|:click|:class|:style|v-html|v-text|@click|@submit)",
        Pattern.CASE_INSENSITIVE);

    static final Pattern JQUERY = Pattern.compile("\\$\\s*\\(");

    static final Pattern EMBER = Pattern.compile(
        "(?:data-ember-|ember-view|Ember\\.)", Pattern.CASE_INSENSITIVE);

    static final Pattern SVELTE = Pattern.compile(
        "(?:svelte-|__svelte)", Pattern.CASE_INSENSITIVE);

    static final Pattern JQUERY_VERSION = Pattern.compile(
        "jquery[/.-]?(\\d+\\.\\d+(?:\\.\\d+)?)", Pattern.CASE_INSENSITIVE);

    // ── JS sinks ───────────────────────────────────────────────

    static final Pattern SINK_INNER_HTML = Pattern.compile(
        "\\.(innerHTML|outerHTML)\\s*=", Pattern.CASE_INSENSITIVE);
    static final Pattern SINK_DOC_WRITE = Pattern.compile(
        "document\\s*\\.\\s*(write|writeln)\\s*\\(", Pattern.CASE_INSENSITIVE);
    static final Pattern SINK_EVAL = Pattern.compile(
        "\\b(eval|Function)\\s*\\(", Pattern.CASE_INSENSITIVE);
    static final Pattern SINK_TIMEOUT_STRING = Pattern.compile(
        "\\b(setTimeout|setInterval)\\s*\\(\\s*[^,)]*[^\"'`\\s,)]", Pattern.CASE_INSENSITIVE);
    static final Pattern SINK_LOCATION_ASSIGN = Pattern.compile(
        "location\\s*\\.\\s*(href\\s*=|assign\\s*\\(|replace\\s*\\()", Pattern.CASE_INSENSITIVE);
    static final Pattern SINK_WINDOW_OPEN = Pattern.compile(
        "window\\s*\\.\\s*open\\s*\\(", Pattern.CASE_INSENSITIVE);
    static final Pattern SINK_JQUERY_HTML = Pattern.compile(
        "(?:\\$\\s*\\([^)]*\\)\\s*\\.\\s*html\\s*\\(|\\.html\\s*\\()", Pattern.CASE_INSENSITIVE);
    static final Pattern SINK_VUE_HTML = Pattern.compile("v-html\\s*=", Pattern.CASE_INSENSITIVE);
    static final Pattern SINK_REACT_DANGEROUS = Pattern.compile("dangerouslySetInnerHTML", Pattern.CASE_INSENSITIVE);
    static final Pattern SINK_ANGULAR_INNERHTML = Pattern.compile("\\[innerHTML\\]", Pattern.CASE_INSENSITIVE);
    static final Pattern SINK_ELEMENT_SRC = Pattern.compile(
        "\\.(src|action)\\s*=", Pattern.CASE_INSENSITIVE);
    static final Pattern SINK_POST_MESSAGE = Pattern.compile(
        "\\.postMessage\\s*\\(", Pattern.CASE_INSENSITIVE);

    // ── JS sources ─────────────────────────────────────────────

    static final Pattern SOURCE_LOCATION = Pattern.compile(
        "location\\s*\\.\\s*(hash|search|href|pathname)", Pattern.CASE_INSENSITIVE);
    static final Pattern SOURCE_DOC_REFERRER = Pattern.compile(
        "document\\s*\\.\\s*referrer", Pattern.CASE_INSENSITIVE);
    static final Pattern SOURCE_DOC_URL = Pattern.compile(
        "document\\s*\\.\\s*(URL|documentURI)", Pattern.CASE_INSENSITIVE);
    static final Pattern SOURCE_WINDOW_NAME = Pattern.compile(
        "window\\s*\\.\\s*name", Pattern.CASE_INSENSITIVE);
    static final Pattern SOURCE_COOKIE = Pattern.compile(
        "document\\s*\\.\\s*cookie", Pattern.CASE_INSENSITIVE);
    static final Pattern SOURCE_STORAGE = Pattern.compile(
        "(localStorage|sessionStorage)", Pattern.CASE_INSENSITIVE);
    static final Pattern SOURCE_URL_PARAMS = Pattern.compile(
        "URLSearchParams", Pattern.CASE_INSENSITIVE);
    static final Pattern SOURCE_MESSAGE_LISTENER = Pattern.compile(
        "(?:addEventListener\\s*\\(\\s*[\"']message[\"']|onmessage\\s*=)", Pattern.CASE_INSENSITIVE);
    static final Pattern SOURCE_AJAX = Pattern.compile(
        "(?:\\$\\.ajax\\s*\\(|fetch\\s*\\(|XMLHttpRequest)", Pattern.CASE_INSENSITIVE);

    // ── Prototype pollution ────────────────────────────────────

    static final Pattern PROTO_DIRECT = Pattern.compile("__proto__");
    static final Pattern PROTO_CONSTRUCTOR = Pattern.compile(
        "constructor\\s*\\.\\s*prototype", Pattern.CASE_INSENSITIVE);
    static final Pattern PROTO_MERGE = Pattern.compile(
        "(?:Object\\s*\\.\\s*assign|_\\.merge|\\$\\.extend|lodash\\.merge|deepmerge|deep[_-]?extend)",
        Pattern.CASE_INSENSITIVE);
    static final Pattern PROTO_BRACKET = Pattern.compile(
        "\\w+\\s*\\[\\s*\\w+\\s*\\]\\s*=", Pattern.CASE_INSENSITIVE);

    // ── Dangerous patterns ─────────────────────────────────────

    static final Pattern DANGER_EVAL_VAR = Pattern.compile(
        "eval\\s*\\(\\s*[a-zA-Z_$][\\w$.]*\\s*\\)", Pattern.CASE_INSENSITIVE);
    static final Pattern DANGER_TEMPLATE_LITERAL = Pattern.compile(
        "`[^`]*\\$\\{[^}]+\\}[^`]*`");
    static final Pattern DANGER_JSON_PARSE = Pattern.compile(
        "JSON\\s*\\.\\s*parse\\s*\\(", Pattern.CASE_INSENSITIVE);
}
