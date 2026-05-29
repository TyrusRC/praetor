---
description: React Server Components + Server Actions attacks — Next.js 13+/14+/15 attack surface. CVE-2025-55182 / CVE-2025-66478. Server Action ID enumeration, payload tampering, RSC poisoning.
globs:
---

# Server Actions + RSC Attacks Deep-Dive

Load when: target is built on Next.js 13+ (App Router), 14, or 15. Identifiers: `_next/static/` paths, `RSC` query parameter, `Next.js` in `Server:` header, hydrated server components, server actions via form `action={someFn}`.

## What's a Server Action

React Server Components (RSC) + Server Actions = code runs on the server but is invoked from the client. The client sends a serialized request to a fixed endpoint (the page URL, with special headers) plus an opaque **Server Action ID** that maps to a server-side function.

```jsx
// app/profile/page.tsx (server component)
async function updateProfile(formData) {
  'use server'
  await db.users.update({ ... })
}

export default function Profile() {
  return <form action={updateProfile}>...</form>
}
```

The browser invokes `updateProfile` by POSTing to `/profile` with header `Next-Action: <opaque_id>` and body containing serialized arguments. Server looks up the ID, runs the function.

## Attack surface

| Surface | Attack | CVE |
|---|---|---|
| Server Action ID | Enumerable / leaked → bypass page-route authorization | CVE-2025-55182 (Next.js 15) |
| RSC payload | Server response includes serialized props → leak per-user data | CVE-2025-66478 |
| `Next-Action` header | Not bound to route → action runs on wrong page context | Next.js < 15.x patch |
| Cache poisoning of RSC | RSC response cached by URL but request body changes the action | W18 `nextjs_15_cache_key_confusion` |
| Server Action argument tampering | Trusted arguments not re-validated server-side | Per-app |

## Attack matrix

### 1. Server Action ID exposure (CVE-2025-55182 class)

Next.js generates a deterministic ID per action per build (hash of action body). The ID appears in:
- HTML/RSC payload as `data-action-id="..."`
- Bundled JS chunks
- The `Next-Action` header on captured POSTs

Once leaked, attacker can invoke ANY action from ANY URL — bypassing per-page authorization that depended on URL matching.

```
POST /any-page HTTP/1.1
Next-Action: <leaked_admin_action_id>
Next-Router-State-Tree: ...
Content-Type: text/plain
[serialized args]
```

If the admin action doesn't re-check authz at the action level (it relied on `/admin` route protection), this succeeds.

### 2. Server Action argument tampering

Server actions receive arguments via the RSC wire format (a specific serialization). Many apps trust the client-supplied arguments (`user_id`, `amount`, `role`). Standard BOLA / IDOR / mass-assignment patterns apply:

```js
// Client sends
updateUserRole(currentUserId, "admin")
// Attacker tampers
updateUserRole(victimUserId, "admin")
```

Same attack model as REST IDOR / mass assignment, but the surface is the Server Action endpoint, not REST.

### 3. RSC payload leak

The RSC streaming response (`Content-Type: text/x-component`) serializes the entire React tree including PROPS passed to server components. Sensitive data passed as a prop "for rendering" is fully visible to anyone who can fetch the page.

Detection: fetch the page with `Accept: text/x-component` or with `?_rsc=1` and inspect the response. Look for fields the rendered HTML wouldn't show (PII, internal IDs, secrets).

### 4. Next-Action route binding bypass

Next.js 15 patched this: the Action ID is now bound to the URL pattern. Pre-15, you could:

```
POST /public-page HTTP/1.1
Next-Action: <admin_action_id>
```

And the admin action runs without authentication that lived only on `/admin`.

### 5. Cache poisoning of RSC (W18 cross-ref)

W18's `nextjs_15_cache_key_confusion` covers this — the `x-now-route-matches` header (or similar unkeyed-at-CDN routing hints) lets attacker poison the cache for legitimate URLs. Combined with RSC payload leak (#3), the next victim sees attacker's tampered response.

### 6. Streaming injection

RSC responses are streamed. If any user-controlled data is interpolated into the stream without sanitization, attacker can inject chunks. Common in error messages reflected into the stream.

### 7. Server Action GET coercion

```
GET /profile?_rsc=1 → returns the page's RSC payload
```

Some setups also expose action invocation via GET when the action's serialized arg list happens to encode trivially. This bypasses CSRF protection that depended on POST-only.

## Tool chain

1. **Fingerprint Next.js version** — check `Server:` header, `X-Powered-By: Next.js`, `_next/static/` paths, `next.config.js` if accessible.
2. **Capture action invocations** — drive the app's UI through Burp; capture POSTs with `Next-Action` header.
3. **Extract action IDs** — grep proxy history for `Next-Action:`, `data-action-id=`, or `bundles/*.js` for action ID registry.
4. **Replay across pages** — `resend_with_modification(index, modify_path='/different-page')` — does the action still execute?
5. **RSC payload fetch** — `curl_request(url, headers={'Accept': 'text/x-component'})` and parse for prop leaks.
6. **W18 cache deception** — `auto_probe(categories=['cache_poisoning'])` fires `nextjs_15_cache_key_confusion`.

## Evidence ladder

| Verdict | Evidence shape | Save? |
|---|---|---|
| **CONFIRMED CRITICAL** | Admin action invoked from non-admin page using leaked Action ID; server processed without per-action authz | yes |
| **CONFIRMED HIGH** | RSC payload leaks per-user PII / secrets / internal IDs not in rendered HTML | yes |
| **CONFIRMED HIGH** | Server Action argument tampering — privesc / IDOR via action invocation | yes |
| **CONFIRMED MEDIUM** | Action ID enumerable across bundles but no exploitable action found | yes |
| **SUSPECTED** | Next-Action header recognized but action requires re-auth | NO save |
| **FAILED** | Action IDs bound to route AND server validates authz per-action | NO |

## save_finding shape

```python
save_finding(
    vuln_type="server_action_authz_bypass",          # or rsc_payload_leak
    endpoint="https://target.com/profile",
    severity="critical",
    evidence={
        "logger_index": <bypass-confirmed index>,
        "summary": "Server Action ID `9d3f...c2a8` (from /admin page bundle) invoked via POST to /profile with Next-Action header. Server executed admin action (delete user account) without per-action authz check.",
        "next_version": "15.0.3",
        "action_id": "9d3f...c2a8",
        "action_purpose": "deleteUserAccount",
        "invoked_from": "/profile",
        "cve": "CVE-2025-55182",
    },
)
```

## Severity discipline

- Action-ID-leak + admin action invocable from public page = CRITICAL.
- RSC payload leaks PII = CRITICAL.
- Action argument tampering = HIGH-CRITICAL (depends on action impact).
- RSC payload exposes only public data = LOW (informational).
- Action ID enumeration without exploitable action = NEVER_SUBMIT alone.

## NEVER_SUBMIT traps

- "Server Action endpoint is `/profile`" — by design.
- "Action ID visible in HTML" — by design pre-15; the bug is the AUTHZ gap, not the visibility.
- "RSC payload contains my own data" — by design.
- "Next-Action header is required" — that's the protocol.
- Demonstrate per-action authz failure + actual impact (admin action / IDOR / privesc).

## Chain patterns

- **Action ID leak + admin action invocable from public page + missing per-action authz** = privesc to admin.
- **RSC payload leak (sensitive prop) + cache poisoning** = mass PII leak.
- **Server Action argument tampering + mass-assignment** = privesc per user.
- **Server Action ID + race condition** = double-spend / double-action.
- **W18 nextjs_15_cache_key_confusion + RSC payload** = poisoned admin response served to victims.

## Related

- `knowledge/cache_poisoning.nextjs_15_cache_key_confusion` (W18)
- `knowledge/tech_vulns.json` — track CVE-2025-55182 / CVE-2025-66478 entries
- `playbook-idor-bola.md` — Action-argument tampering is IDOR/BOLA via Server Action surface
- `playbook-cache-deception.md` — RSC cache poisoning surface
- Next.js Security Advisories: https://github.com/vercel/next.js/security/advisories
- Vercel Security blog 2025 — Server Action vulnerability disclosures
