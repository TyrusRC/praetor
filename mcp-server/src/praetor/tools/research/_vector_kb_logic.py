"""Pollution/auth/API/client/logic class deep-dive prompts (prototype_pollution/auth_bypass/graphql/websocket/cors/business_logic).

Data slice re-assembled by _vector_kb.py — do not import directly.
"""

from __future__ import annotations


_LOGIC: dict[str, dict[str, list[str]]] = {
    "prototype_pollution": {
        "deep_dive": [
            "Sink: lodash merge / extend / defaultsDeep, jQuery extend, custom deep-merge, JSON.parse + assign.",
            "Trigger: query string parser (qs, body-parser), JSON.parse, deep-merge of request body.",
            "Gadget chains: ejs render, command-line args, csurf token check — class-specific gadgets.",
            "Server-side vs client-side — server-side enables RCE via gadget; client-side typically XSS.",
            "Polluting via path notation: __proto__[x]=y, constructor[prototype][x]=y, nested merge.",
        ],
        "obscure": [
            "GraphQL variables → server-side merge → prototype pollution.",
            "CSV / XML / YAML body parsers with nested key support.",
            "Express body-parser with `parameterLimit` raised — large nested objects.",
            "WebSocket message handlers that deep-merge state.",
            "Cache key construction using Object.keys — polluted keys appear.",
        ],
        "chain": [
            "Server PP → ejs gadget → RCE.",
            "Server PP → bypass auth check (default role injection).",
            "Server PP → cache poisoning via polluted cache key.",
            "Client PP → DOM XSS (gadget in jQuery / handlebars / marked).",
        ],
    },
    "auth_bypass": {
        "deep_dive": [
            "Auth layer: middleware ordering (does the protected path register before auth middleware?), per-route guard, gateway-level (Kong/Envoy).",
            "Header smuggling: X-Original-URL / X-Rewrite-URL / X-Forwarded-Path can bypass front-end auth.",
            "Path normalization: /admin/../user/admin /admin%2f /admin;.json /admin..;/ — gateway parses different than backend.",
            "Method confusion: GET protected but HEAD/OPTIONS/PROPFIND not.",
            "Trailing slash / case sensitivity / null byte — gateway vs backend mismatch.",
        ],
        "obscure": [
            "Sign-up endpoint accepts role / admin / is_admin field (mass assignment).",
            "Password reset OTP brute force without rate limit (numeric 4-digit = 10000 tries).",
            "JWT alg=none, RS→HS confusion, kid injection, jku/x5u, claim swap, weak HS secret.",
            "OAuth flow: implicit-grant token in URL fragment leaks via referer.",
            "SAML signature wrapping / unsigned assertion / signature exclusion.",
        ],
        "chain": [
            "Header smuggling → admin panel → ATO of all users.",
            "Path normalization → unauth endpoint → cred reset → ATO.",
            "Mass assignment role=admin on signup → admin panel access.",
            "JWT forge → impersonate any user → ATO.",
        ],
    },
    "graphql": {
        "deep_dive": [
            "Introspection enabled in prod? Query __schema, __type to map.",
            "Field-level auth or just operation-level? Often introspection is auth'd but field execution isn't.",
            "Batched queries — single HTTP request with N operations: bypass rate limit, race conditions.",
            "Aliasing — same field N times with aliases: amplify brute force.",
            "Deep nesting → DoS / amplification (`{me{posts{author{posts{author{...}}}}}`).",
        ],
        "obscure": [
            "Mutation that wraps DB writes without per-field authz check.",
            "Resolver that uses request context but trusts a body-supplied user_id.",
            "Persisted query bypass via injection of new query into operation_name.",
            "GraphQL CSRF: POST with non-JSON content-type + GET-style query in body.",
            "Schema-stitching gateways aggregating internal services — auth at edge only.",
        ],
        "chain": [
            "Introspection → discover privileged mutations → IDOR / mass assignment via GQL.",
            "Aliasing → brute force OTP without rate limit.",
            "Batched mutation → race condition.",
            "GraphQL DoS → cost-based outage chain.",
        ],
    },
    "websocket": {
        "deep_dive": [
            "Origin check on upgrade? Per CSWSH — if no Origin validation, attacker.com can open authenticated socket.",
            "Auth model: cookie at upgrade / token in URL / first-message handshake / subprotocol-bearer.",
            "Message-level auth: server trusts client claims or re-validates each message?",
            "Subprotocol negotiation — flaw in `Sec-WebSocket-Protocol` selection.",
            "Persistent connections survive logout / role change? (state desync).",
        ],
        "obscure": [
            "Token in URL query string at upgrade — leaks via Referer / logs / proxy history.",
            "Cross-site WebSocket hijacking is a classic still missed (per Snyk's 2023 reports).",
            "WS over HTTP/2 — upgrade semantics different, some gateways skip Origin check.",
            "Long-poll fallback (Socket.io) — Origin-check applied to WS but not poll.",
            "Subscription/streaming endpoints over WS expose more data than REST.",
        ],
        "chain": [
            "CSWSH → exfil real-time data feed (chat / orderbook / location).",
            "CSWSH + persistent socket → state desync after logout.",
            "WS without msg auth → IDOR-via-WS unsubscribed channels.",
            "WS subprotocol smuggling → backend service bypass.",
        ],
    },
    "cors": {
        "deep_dive": [
            "Reflected Origin? Wildcard? Subdomain trust? Null origin acceptance?",
            "Credentialed CORS (Access-Control-Allow-Credentials: true) + reflected origin = data exfil to attacker.",
            "Path-level CORS — different per route; only sensitive endpoints matter.",
            "Pre-flight cache (Access-Control-Max-Age) — bypass requires invalidating.",
            "Subdomain takeover + CORS trust on *.target.com = cross-domain data exfil.",
        ],
        "obscure": [
            "Origin: null acceptance — exploitable via sandboxed iframe / data: URI.",
            "Wildcard subdomain in allowlist matching by substring.",
            "Trailing-dot Origin (https://target.com.) sometimes bypasses regex.",
            "CORS misconfig with internal IP / localhost trust.",
            "Reflected Referer header used instead of Origin.",
        ],
        "chain": [
            "Reflected-Origin + credentials → exfil cookies/csrf token from victim → ATO.",
            "CORS on sensitive API + low-priv user → exfil higher-priv data.",
            "CORS misconfig + XSS on subdomain → exfil parent-domain data.",
        ],
    },
    "business_logic": {
        "deep_dive": [
            "Order-of-operations: step skipping (skip payment step) / step replay / step reorder.",
            "State machine: are state transitions enforced server-side?",
            "Price/quantity manipulation: negative numbers, decimals beyond schema, very large integers.",
            "Coupon/promo chaining — stack codes that shouldn't combine.",
            "Limits: subscription tier limits, daily/monthly caps — what happens if you race past them?",
        ],
        "obscure": [
            "Returns/refunds without product return — refund-only state.",
            "Subscription cancellation during a payment window — get the goods AND a refund.",
            "Multi-user resource transfer — transfer A→B→C; does each check?",
            "Loyalty point earning during reversal — earn points on a refunded purchase.",
            "Test/staging promo codes that work in prod.",
        ],
        "chain": [
            "Free product chain → revenue impact (reportable).",
            "Negative price → balance increase → withdraw to attacker.",
            "Race + business logic → impossible state → privilege upgrade.",
            "Subscription bypass → premium features → competitive harm.",
        ],
    },
}
