---
name: ip-allowlist-coverage
description: Audit whether a service enforces its IP allowlist CONSISTENTLY across every surface (web UI, REST/GraphQL API, git, Pages, LFS, package registry, raw, webhooks) and report the gaps. Vendor-agnostic (GitHub, GitLab, Okta, admin panels, internal apps). Use when the org has an IP allowlist / network-restriction control and wants it verified for remediation.
---

# IP-Allowlist Coverage Audit

Load when the target enforces an IP allowlist (a.k.a. IP allow list, network
restriction, "restrict access by IP") and the engagement is to verify the
control is enforced **on every surface**, not just the front door. Read-only,
benign, defensive-by-purpose: the deliverable is the GAP list handed to the org
to fix. RoE must name the service under audit.

Tool: `ip_allowlist_coverage(surfaces, auth_header|auth_env, proxy, baseline_proxy, ...)`.

## The honest architecture note — you cannot spoof your way in

An IP allowlist on a TCP service is enforced at the transport/network layer: the
allowed source IP is the one that completes the **TCP handshake** and is what
egress filtering / the reverse proxy checks. You **cannot** forge it with an
`X-Forwarded-For` header, a `Via`, or any L3/L7 field — those are trusted only if
the app is *also* misconfigured (that is a separate finding, `test_host_header` /
header-trust). There is exactly one way to "appear from an allowed IP":

**Route the request through a host that is already on the allowlist** (an in-scope
foothold / egress). That is the pivot. No spoofing logic exists in this tool and
none would work.

## Build the pivot (on-list vantage)

Use Praetor's already-sanctioned tunnelling — do not hand-roll:

- **chisel** (network lane): `run_network_tool` to stand up a reverse SOCKS5
  through the allowlisted foothold, e.g. client `chisel client <c2> R:1080:socks`.
- **ligolo-ng** (network lane): agent on the foothold, a `socks`/tun listener on
  your side.
- **burp-expedition SOCKS5 listener**: `tcp_proxy_add_listener(protocol='socks5', port=<p>)`
  bound to an interface that egresses via the allowlisted host.

You now have `socks5://127.0.0.1:<port>` that egresses from an allowlisted IP.
(SOCKS needs the `httpx[socks]` extra; if it is missing the tool returns a clear
error — use an `http://` proxy or `uv pip install httpx[socks]`.)

## Run the audit

The tool compares two vantages per surface:

- **off_list** = `proxy` (or direct, when empty) — the source under audit,
  presumed NOT on the allowlist. A surface that SERVES this vantage is the gap.
- **on_list** = `baseline_proxy` — a known-allowlisted positive control (the
  pivot you just built). Optional but recommended: it distinguishes "the control
  blocked me" from "the surface was just down".

**Fast gap sweep** (off-list only — your ordinary egress):
```
ip_allowlist_coverage(
  surfaces='[{"label":"api-user","url":"https://api.example.com/user"}]',
  auth_env="AUDIT_TOKEN",
  domain="example",
)
```
Any surface that returns 2xx from your off-list source = enforcement GAP.

**Rigorous differential** (pivot as the on-list control):
```
ip_allowlist_coverage(
  surfaces=<...>,
  auth_env="AUDIT_TOKEN",
  proxy="",                              # off-list: your direct egress
  baseline_proxy="socks5://127.0.0.1:1080",   # on-list: the allowlisted pivot
  domain="example",
)
```
Verdicts: off BLOCKED + on ALLOWED = **ENFORCED**; off ALLOWED (either on) =
**GAP**; off BLOCKED + on BLOCKED = **INCONCLUSIVE** (surface down / bad pivot /
not actually on-list — fix the pivot and re-run, don't record it covered).

## Enumerate every surface — a gap hides on the one you forgot

The allowlist is only as strong as its weakest surface. Enumerate all that apply
to the target and pass each as its own labelled surface (the credential is
operator-supplied and REDACTED on every probe):

- **Web UI** — the dashboard / console (`GET /`, a logged-in page).
- **REST API** — identity/whoami (`GET /user`, `/api/v4/user`, `/api/v1/users/me`).
- **GraphQL** — a `viewer { login }` / `me { id }` query (`POST /graphql`).
- **git over HTTPS** — `GET <repo>.git/info/refs?service=git-upload-pack`.
- **git over SSH** — separate service/port; often a different enforcement path.
- **App / OAuth / installation tokens** — machine identities frequently bypass
  the user-IP allowlist.
- **CI runners / webhooks** — outbound and inbound callbacks.
- **Pages / static hosting**, **LFS**, **package/container registry**,
  **raw / codeload / artifact** endpoints — commonly forgotten, often on a
  different host that never sees the allowlist.

Use benign identity/HEAD/GET probes only — one request per surface. `preset=`
(`github`/`gitlab`/`okta`) expands a few identity probes as a convenience;
self-managed hosts read `$PRAETOR_ALLOWLIST_BASE`. The core path is
operator-supplied surfaces.

## Block detection

A response is a block when its status is in `blocked_status` (default `403,451`)
AND (a supplied `blocked_regex` matches OR, with no regex, a default allowlist
phrase is present: "ip allow list", "not permitted to access", "ip allowlist",
"access denied", "not allowed from your"). 2xx = ALLOWED (served). 401 =
BAD_AUTH (bad/missing credential — INCONCLUSIVE, fix the token and re-run).
Read the BODY, not just the status: a 200 that says "invalid token" is BAD_AUTH,
and a 403 for an unrelated reason is not an allowlist block — tune `blocked_regex`
to the target's actual block page.

## More bypass classes

The honest-architecture note above holds for a **network/TCP** allowlist. Three
adjacent classes are where the allowlist is actually a per-request check the app
(or a fronting proxy) gets wrong — test them when the surface has one.

### 1. Header-trust bypass — the app trusts a client-IP header as its ACL source

Distinct from the network allowlist: here the app reads `X-Forwarded-For` /
`Forwarded` / `True-Client-IP` and treats that value as the client IP for its
allow/deny decision. Inject a trusted/loopback value and the check is bypassed —
no pivot needed. This is a real, common misconfiguration (CloudStack
CVE-2024-29006, OpenClaw leftmost-XFF, 1Panel CVE-2025-66508, Heimdall
`Forwarded`).

Turn it on with `spoof_headers`:
```
ip_allowlist_coverage(
  surfaces='[{"label":"admin","url":"https://app.example.com/admin"}]',
  spoof_headers="auto",          # the standard set below; or a comma list
  spoof_value="127.0.0.1",       # the trusted/loopback IP to inject
  domain="example",
)
```
Standard set (`auto`): `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`,
`True-Client-IP`, `CF-Connecting-IP`, `X-Originating-IP`, `X-Forwarded-Host`,
`Forwarded` (sent as `for=<spoof_value>`).

**Leftmost vs rightmost parser differential.** With multiple hops
(`X-Forwarded-For: a, b, c`) different parsers pick a different value as "the
client". The tool sends both `<spoof_value>, 203.0.113.9` (leftmost) and
`203.0.113.9, <spoof_value>` (rightmost) for `X-Forwarded-For` and `Forwarded`
and records which position won — that position is the finding's key detail (it
tells the org exactly which parser to fix).

**Verdict:** the header test runs per surface **only after** the normal
baseline probe was BLOCKED (an already-served surface is a GAP already — the
header probe is N/A there, not double-counted). A spoof probe that returns 2xx
is a `HEADER_TRUST_BYPASS` for that `{header, position}`; see per-surface
`header_trust[]` and the top-level `header_bypasses[]`. Read-only, one request
per header, capped at ~12 extra probes/surface, credential redacted as always.

### 2. Partial-match / prefix allowlist flaw

The allowlist compares by **substring/prefix**, string-compares an unnormalised
value, or confuses IPv4/IPv6 — so an IP is accepted merely because it *contains*,
shares a prefix with, or is an alternate encoding of a trusted entry (n8n
CVE-2025-68949: an IP is accepted if it merely contains a trusted entry; the same
class as the classic SSRF/allowlist filter bypass). Two honest ways to test it —
one for a per-request header check, one for a real network source-IP check.

**(a) IP-format normalisation variants (header/filter re-parse).** When a filter
or a fronting proxy string-compares or re-parses a client-IP HEADER, an alternate
encoding of the trusted IP normalises back to it but dodges the comparison. Turn
it on with `spoof_headers` (same switch as header-trust): each IP-BEARING header
— `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`,
`CF-Connecting-IP`, `X-Originating-IP` (NOT `Forwarded`/`X-Forwarded-Host`, which
are not bare-IP fields) — is also sent one probe per encoding of `spoof_value`:

| Label | `127.0.0.1` becomes |
|---|---|
| dotless-decimal | `2130706433` |
| dotted/full octal | `0177.00.00.01` |
| per-octet hex | `0x7f.0x0.0x0.0x1` |
| hex-dword | `0x7f000001` |
| mixed/short | `127.1` |
| IPv6-mapped (+ bracketed) | `::ffff:127.0.0.1`, `[::ffff:127.0.0.1]` |
| trailing-dot | `127.0.0.1.` |
| IPv6 loopback (loopback input only) | `::1`, `[::1]` |

```
ip_allowlist_coverage(
  surfaces='[{"label":"admin","url":"https://app.example.com/admin"}]',
  spoof_headers="auto",          # or an IP-bearing header comma list
  spoof_value="127.0.0.1",       # the trusted IP whose encodings are generated
  domain="example",
)
```
Same gate as header-trust: format probes run per surface only after the baseline
was BLOCKED. A variant that returns 2xx is an `IP_FORMAT_BYPASS` for
`{header, format, value}` — see per-surface `ip_format[]` and top-level
`ip_format_bypasses[]`. Read-only, one request per variant, capped at ~24 extra
probes/surface (separate budget from the header-trust cap), credential redacted.

**(b) Real source-IP prefix/near-IP acceptance (`source_bind`).** A NETWORK
allowlist keyed on the real TCP source cannot be spoofed — the only honest test is
to actually source the probe from an IP you CONTROL that is adjacent to a trusted
entry (a trusted `10.0.0.1` vs a probe from `10.0.0.10` or `110.0.0.1`). Bind the
outgoing connection to an operator-owned local address:
```
ip_allowlist_coverage(
  surfaces=<...>,
  source_bind="10.0.0.10",       # an IP THIS host owns, near a trusted entry
  domain="example",
)
```
`source_bind` must be assigned to a local interface this host owns; if it cannot
be bound the run returns a clear error (it is not spoofing — that is impossible
for TCP). Combine with the pivot (`baseline_proxy`) when the near-IP lives behind
an allowlisted egress. Where you can only read the allowlist config and cannot
source every candidate IP, still report it as a config finding when the
comparison logic is visibly substring/prefix/unnormalised.

### 3. Request smuggling -> front-end ACL bypass

When the IP allowlist is enforced at a **front-end proxy** but the back-end
serves an allowlisted/localhost-only path, a desync smuggles a request past the
proxy's ACL to that path — CL.TE / TE.CL / TE.0 / CL.0 / h2c (Gunicorn
CVE-2024-1135, HAProxy CVE-2024-53008, Kong CVE-2024-33452, TE.0 on GCP LB).
Do **not** hand-roll this — cross-reference Praetor's existing smuggling tools:
`test_request_smuggling`, `build_capture_smuggle`, and the h2c/raw path
(`send_raw_request http_version=2`). Prove reach to the restricted path with a
benign marker (a localhost-only status/health endpoint), not a destructive call.

## Reporting

The deliverable is the **gap list** for the org to remediate: each surface that
served an off-list request, with the redacted credential shape (never the value),
the status, and the body marker snippet. Frame per-surface: "surface X serves
requests from sources not on the IP allowlist; enforce the allowlist at
<layer/host> for this surface." The run is recorded to the operator log
(Reconnaissance / T1590) with the credential redacted. RoE names the service.
