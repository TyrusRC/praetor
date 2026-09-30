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

## Reporting

The deliverable is the **gap list** for the org to remediate: each surface that
served an off-list request, with the redacted credential shape (never the value),
the status, and the body marker snippet. Frame per-surface: "surface X serves
requests from sources not on the IP allowlist; enforce the allowlist at
<layer/host> for this surface." The run is recorded to the operator log
(Reconnaissance / T1590) with the credential redacted. RoE names the service.
