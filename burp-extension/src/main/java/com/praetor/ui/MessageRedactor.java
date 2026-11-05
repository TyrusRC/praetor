package com.praetor.ui;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Render-time redaction: replace secret values in a request/response BEFORE the
 * screenshot editors render them, so the secret never reaches the pixels. This is
 * the deterministic alternative to redacting the PNG after the fact — OCR-on-image
 * can misread a value and leave it readable; a byte-level replace cannot.
 *
 * <p>The transforms are pure {@code String -> String} (unit-tested without Burp).
 * {@link #applyToRequest}/{@link #applyToResponse} are the thin Montoya adapter
 * that walks the message headers/body and rebuilds the message.
 */
public final class MessageRedactor {

    private MessageRedactor() {}

    // ───────────────────────── config ─────────────────────────

    /** The resolved rule set for one capture. Built from the POST body by
     *  {@link #configFrom}; starts from {@link RedactRules} safe defaults when the
     *  caller asks for them. */
    public static final class Config {
        final Set<String> secretHeaders;
        final Set<String> hideHeaders;
        final Set<String> queryParams;
        final Set<String> bodyFields;
        final boolean redactBody;
        final boolean redactJwt;
        final String glyph;

        Config(Set<String> secretHeaders, Set<String> hideHeaders,
               Set<String> queryParams, Set<String> bodyFields,
               boolean redactBody, boolean redactJwt, String glyph) {
            this.secretHeaders = secretHeaders;
            this.hideHeaders = hideHeaders;
            this.queryParams = queryParams;
            this.bodyFields = bodyFields;
            this.redactBody = redactBody;
            this.redactJwt = redactJwt;
            this.glyph = glyph;
        }

        /** The safe-by-default rule set — all known secret headers / query params /
         *  body fields, plus JWT detection. */
        public static Config defaults() {
            return new Config(
                new LinkedHashSet<>(RedactRules.SECRET_HEADERS),
                new LinkedHashSet<>(),
                new LinkedHashSet<>(RedactRules.SECRET_QUERY_PARAMS),
                new LinkedHashSet<>(RedactRules.SECRET_BODY_FIELDS),
                true, true, RedactRules.GLYPH);
        }

        /** An empty rule set — redacts nothing until the caller adds rules. */
        public static Config empty() {
            return new Config(new LinkedHashSet<>(), new LinkedHashSet<>(),
                new LinkedHashSet<>(), new LinkedHashSet<>(),
                false, false, RedactRules.GLYPH);
        }

        /** Nothing to do — the handler skips the transform when inactive. */
        public boolean isActive() {
            return redactBody || redactJwt || !secretHeaders.isEmpty()
                || !hideHeaders.isEmpty() || !queryParams.isEmpty();
        }
    }

    /**
     * Build a {@link Config} from the message-screenshot POST body.
     *
     * <p>{@code redact} true / "defaults" starts from the safe default set; false /
     * absent starts empty. {@code redact_headers}, {@code redact_query},
     * {@code redact_body_fields} add names; {@code hide_headers} removes named
     * headers; {@code hide_groups} removes whole groups ("browser", "caching",
     * "cors", "security", "tracing", "all"); {@code redact_glyph} overrides the
     * replacement text.
     */
    @SuppressWarnings("unchecked")
    public static Config configFrom(Map<String, Object> body) {
        Object r = body.get("redact");
        boolean startDefaults = (r instanceof Boolean b && b)
            || (r instanceof String s && ("defaults".equalsIgnoreCase(s.trim())
                                          || "true".equalsIgnoreCase(s.trim())));
        Config base = startDefaults ? Config.defaults() : Config.empty();

        Set<String> secret = RedactRules.union(base.secretHeaders, asStrings(body.get("redact_headers")));
        Set<String> query = RedactRules.union(base.queryParams, asStrings(body.get("redact_query")));
        Set<String> fields = RedactRules.union(base.bodyFields, asStrings(body.get("redact_body_fields")));

        Set<String> hide = RedactRules.toLowerSet(asStrings(body.get("hide_headers")));
        for (String g : asStrings(body.get("hide_groups"))) {
            hide.addAll(RedactRules.hideGroup(g));
        }

        boolean redactBody = startDefaults || !fields.isEmpty();
        boolean redactJwt = startDefaults
            || (body.get("redact_jwt") instanceof Boolean jb && jb);
        String glyph = body.get("redact_glyph") instanceof String gs && !gs.isBlank()
            ? gs : base.glyph;

        return new Config(secret, hide, query, fields, redactBody, redactJwt, glyph);
    }

    private static Iterable<String> asStrings(Object o) {
        Set<String> out = new LinkedHashSet<>();
        if (o instanceof List<?> list) {
            for (Object e : list) {
                if (e != null) {
                    out.add(String.valueOf(e));
                }
            }
        } else if (o instanceof String s && !s.isBlank()) {
            for (String part : s.split(",")) {
                out.add(part.trim());
            }
        }
        return out;
    }

    // ───────────────────────── pure transforms ─────────────────────────

    /** Redact one header VALUE by the header's name. Keeps the structure a reader
     *  needs (cookie names, the auth scheme) and hides only the secret part. */
    public static String redactHeaderValue(String name, String value, String glyph) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        String n = name == null ? "" : name.trim().toLowerCase();
        if (n.equals("cookie")) {
            return redactCookiePairs(value, glyph, true);
        }
        if (n.equals("set-cookie")) {
            return redactCookiePairs(value, glyph, false);
        }
        if (n.equals("authorization") || n.equals("proxy-authorization")
            || n.equals("www-authenticate") || n.equals("proxy-authenticate")) {
            return redactAuthValue(value, glyph);
        }
        return glyph;
    }

    /** Cookie / Set-Cookie: replace each cookie VALUE with the glyph, keep the
     *  cookie NAME. When {@code allPairs} (Cookie header) every {@code k=v} is a
     *  cookie; otherwise (Set-Cookie) only the first pair is the cookie and the
     *  rest are attributes (Path, HttpOnly, ...) kept as-is. */
    static String redactCookiePairs(String value, String glyph, boolean allPairs) {
        String[] parts = value.split(";");
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            String seg = parts[i];
            if (i > 0) {
                out.append(';');
            }
            boolean redactThis = allPairs || i == 0;
            int eq = seg.indexOf('=');
            if (redactThis && eq >= 0) {
                // keep leading space + name + '=', replace the value
                String head = seg.substring(0, eq + 1);
                out.append(head).append(glyph);
            } else {
                out.append(seg);
            }
        }
        return out.toString();
    }

    /** Authorization-style value: keep the scheme word (Bearer / Basic / ...),
     *  glyph the credential. A value with no scheme is glyphed whole. */
    static String redactAuthValue(String value, String glyph) {
        String trimmed = value.trim();
        int sp = trimmed.indexOf(' ');
        if (sp > 0) {
            String scheme = trimmed.substring(0, sp);
            return scheme + " " + glyph;
        }
        return glyph;
    }

    /** Redact the named query parameters in a full path ({@code /a/b?x=1&token=..}).
     *  A path with no query is returned unchanged. */
    public static String redactPath(String path, Set<String> params, String glyph) {
        if (path == null) {
            return null;
        }
        int q = path.indexOf('?');
        if (q < 0 || params == null || params.isEmpty()) {
            return path;
        }
        String head = path.substring(0, q + 1);
        String query = path.substring(q + 1);
        return head + redactQueryString(query, params, glyph);
    }

    /** Redact named parameters in a raw query string ({@code a=1&token=xyz}). */
    public static String redactQueryString(String query, Set<String> params, String glyph) {
        if (query == null || query.isEmpty()) {
            return query;
        }
        String[] pairs = query.split("&");
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < pairs.length; i++) {
            if (i > 0) {
                out.append('&');
            }
            String p = pairs[i];
            int eq = p.indexOf('=');
            if (eq > 0) {
                String key = p.substring(0, eq);
                if (params.contains(key.trim().toLowerCase())) {
                    out.append(key).append('=').append(glyph);
                    continue;
                }
            }
            out.append(p);
        }
        return out.toString();
    }

    /** Redact secrets in a body: every JWT (when {@code jwt}) and every named
     *  field as a JSON string value or a form-encoded value. Keeps keys and
     *  structure; replaces only the value. */
    public static String redactBodyText(String body, Set<String> fields,
                                        boolean jwt, String glyph) {
        if (body == null || body.isEmpty()) {
            return body;
        }
        String out = body;
        if (jwt) {
            out = RedactRules.JWT.matcher(out).replaceAll(Matcher.quoteReplacement(glyph));
        }
        if (fields != null) {
            String g = Matcher.quoteReplacement(glyph);
            for (String f : fields) {
                String q = Pattern.quote(f);
                // JSON string: "field" : "value"  ->  "field":"████"
                Pattern json = Pattern.compile(
                    "(\"" + q + "\"\\s*:\\s*\")(?:\\\\.|[^\"\\\\])*(\")",
                    Pattern.CASE_INSENSITIVE);
                out = json.matcher(out).replaceAll("$1" + g + "$2");
                // form-encoded: field=value  ->  field=████  (stop at & or whitespace)
                Pattern form = Pattern.compile(
                    "(?i)(^|[&?])(" + q + "=)[^&\\s]*");
                out = form.matcher(out).replaceAll("$1$2" + g);
            }
        }
        return out;
    }

    // ───────────────────────── Montoya adapter ─────────────────────────

    /** Apply the config to a request: hide headers, redact secret header values,
     *  redact query params, redact the body. Returns a new request; the original
     *  is untouched. */
    public static HttpRequest applyToRequest(HttpRequest req, Config cfg) {
        if (req == null || cfg == null || !cfg.isActive()) {
            return req;
        }
        HttpRequest out = req;
        for (HttpHeader h : List.copyOf(req.headers())) {
            String name = h.name();
            if (RedactRules.matches(cfg.hideHeaders, name)) {
                out = out.withRemovedHeader(name);
            } else if (RedactRules.matches(cfg.secretHeaders, name)) {
                out = out.withUpdatedHeader(name,
                    redactHeaderValue(name, h.value(), cfg.glyph));
            }
        }
        if (!cfg.queryParams.isEmpty() && out.path() != null && out.path().indexOf('?') >= 0) {
            out = out.withPath(redactPath(out.path(), cfg.queryParams, cfg.glyph));
        }
        if (cfg.redactBody || cfg.redactJwt) {
            String b = out.bodyToString();
            if (b != null && !b.isEmpty()) {
                out = out.withBody(redactBodyText(b, cfg.bodyFields, cfg.redactJwt, cfg.glyph));
            }
        }
        return out;
    }

    /** Apply the config to a response: hide headers, redact secret header values
     *  (Set-Cookie, WWW-Authenticate, ...), redact the body (JWTs/tokens returned
     *  to the client). Returns a new response; the original is untouched. */
    public static HttpResponse applyToResponse(HttpResponse resp, Config cfg) {
        if (resp == null || cfg == null || !cfg.isActive()) {
            return resp;
        }
        HttpResponse out = resp;
        for (HttpHeader h : List.copyOf(resp.headers())) {
            String name = h.name();
            if (RedactRules.matches(cfg.hideHeaders, name)) {
                out = out.withRemovedHeader(name);
            } else if (RedactRules.matches(cfg.secretHeaders, name)) {
                out = out.withUpdatedHeader(name,
                    redactHeaderValue(name, h.value(), cfg.glyph));
            }
        }
        if (cfg.redactBody || cfg.redactJwt) {
            String b = out.bodyToString();
            if (b != null && !b.isEmpty()) {
                out = out.withBody(redactBodyText(b, cfg.bodyFields, cfg.redactJwt, cfg.glyph));
            }
        }
        return out;
    }
}
