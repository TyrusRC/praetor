"""Catalogs used by the DOM probe: sink→vuln-class map, polyglot wrappers,
CSPP default keys, fragment-shape templates, destructive-href list."""


_SINK_TO_VULN_CLASS = {
    "innerHTML": ("dom_xss", "Marker reached innerHTML — DOM-based XSS sink"),
    "outerHTML": ("dom_xss", "Marker reached outerHTML — DOM-based XSS sink"),
    "document.write": ("dom_xss", "Marker reached document.write — DOM-based XSS sink"),
    "document.writeln": ("dom_xss", "Marker reached document.writeln — DOM-based XSS sink"),
    "eval": ("dom_xss", "Marker reached code-evaluation sink — DOM-based XSS / RCE"),
    "Function": ("dom_xss", "Marker reached Function() constructor — DOM-based XSS sink"),
    "setTimeout(string)": ("dom_xss", "Marker reached setTimeout(string) — DOM-based XSS sink"),
    "setInterval(string)": ("dom_xss", "Marker reached setInterval(string) — DOM-based XSS sink"),
    "$.fn.html": ("dom_xss", "Marker reached jQuery .html() — DOM-based XSS sink"),
    "location.assign": ("open_redirect_dom", "Marker controlled location.assign() — DOM open redirect"),
    "location.replace": ("open_redirect_dom", "Marker controlled location.replace() — DOM open redirect"),
    "location.href": ("open_redirect_dom", "Marker controlled location.href setter — DOM open redirect"),
    "window.open": ("open_redirect_dom", "Marker controlled window.open() URL — DOM open redirect"),
    "setAttribute(href)": ("link_manipulation", "Marker reached href via setAttribute — DOM link manipulation"),
    "setAttribute(src)": ("link_manipulation", "Marker reached src via setAttribute — DOM link manipulation"),
    "setAttribute(action)": ("link_manipulation", "Marker reached form action via setAttribute — link manipulation"),
    "setAttribute(formaction)": ("link_manipulation", "Marker reached formaction via setAttribute — link manipulation"),
    "script.src": ("dom_xss", "Marker reached HTMLScriptElement.src setter — DOM XSS via dynamic script load"),
    "appendChild(<script>)": ("dom_xss", "Marker reached <script> appendChild — DOM XSS via dynamic script load"),
    "insertBefore(<script>)": ("dom_xss", "Marker reached <script> insertBefore — DOM XSS via dynamic script load"),
    "replaceChild(<script>)": ("dom_xss", "Marker reached <script> replaceChild — DOM XSS via dynamic script load"),
    "appendChild(<iframe>)": ("link_manipulation", "Marker reached <iframe> appendChild — link manipulation / clickjacking"),
    "postMessage": ("postmessage_leak", "Marker passed to postMessage — potential cross-frame leak"),
    "angular_ng_bind": ("client_side_template_injection", "Marker rendered inside ng-bind / ng-include — AngularJS CSTI"),
}


# Polyglot exploit wrappers. Key = name; value = python format string with {marker}.
_POLYGLOTS: dict[str, str] = {
    "plain":         "{marker}",
    "angular_csti":  "{{{{{marker}}}}}",                     # {{<marker>}}
    "handlebars":    "{{{{= {marker} }}}}",                  # Handlebars triple-stash
    "proto_pollute": "__proto__[{marker}]=1",                # CSPP merge-gadget marker
    "proto_constr":  "constructor[prototype][{marker}]=1",   # CSPP via constructor
    "xss_svg":       "<svg/onload={marker}>",
    "xss_img":       "<img src=x onerror={marker}>",
    "url_break":     "\"><{marker}",
}


# CSPP "known-key" gadgets: pollute a real, app-used Object.prototype key
# (e.g. transport_url for searchLogger.js) with the marker as VALUE, then
# detect the marker arriving at any sink. Unlike `proto_pollute`, the
# polluted key is one the application code is expected to read.
_CSPP_DEFAULT_KEYS = (
    "transport_url",   # gnj searchLogger.js
    "src",
    "url",
    "html",
    "redirect_uri",
    "redirectUri",
    "next",
    "callback",
    "action",
    "include",
    "template",
)


# Fragment-shape variants — many SPAs use the URL fragment as a router
# input. The same payload has very different chances of reaching a sink
# depending on whether it's bare, after a `?` inside the fragment, after
# a slash, or shaped like a hash-route.
_FRAGMENT_SHAPES: dict[str, str] = {
    "bare":          "{payload}",
    "param":         "{param}={payload}",
    "amp_param":     "&{param}={payload}",
    "qs_in_hash":    "?{param}={payload}",
    "hash_route":    "/{payload}",
    "hash_route_kv": "/{param}/{payload}",
    "hashbang":      "!{payload}",
    "hashbang_kv":   "!/{param}/{payload}",
}


_DESTRUCTIVE_HREFS = ("/logout", "/signout", "/delete", "/remove", "/cancel")
