"""Vendor-agnostic IP-allowlist enforcement auditor.

Verifies whether a service enforces its IP allowlist CONSISTENTLY across all of
its surfaces (web UI, REST/GraphQL API, git, Pages, LFS, package registry, raw,
webhooks — whatever the operator lists) and reports the GAPS for remediation.

Benign by construction — read-only recon of the ORG'S OWN control:
  * ONE request per surface per vantage; identity/whoami/refs/HEAD/GET only.
  * No writes, no brute-force, no credential guessing, no data exfiltration —
    the response body is kept only as a small status-marker snippet.
  * The operator-supplied auth credential is REDACTED everywhere (output, logs,
    operator log): shape only (`ghp_...4f2a`), never the value.
  * No IP spoofing (it does not work against a TCP allowlist). Reaching an
    on-list source is done by the operator routing a probe through an in-scope
    allowlisted egress (`baseline_proxy` / `proxy`) — the pivot, built with
    Praetor's already-sanctioned tunnelling tools.

RoE: the operator owns authorization for the service under audit (SoW names it).

Enforcement model (per surface):
  off_list  = probe via `proxy` (or direct) — the vantage under audit, presumed
              NOT on the allowlist.
  on_list   = probe via `baseline_proxy` — a known-allowlisted positive control
              (optional; enables the differential).

  single (no baseline):  off BLOCKED -> ENFORCED | off ALLOWED -> GAP | else INCONCLUSIVE
  differential:          off BLOCKED + on ALLOWED -> ENFORCED
                         off ALLOWED (either on) -> GAP
                         off BLOCKED + on BLOCKED -> INCONCLUSIVE (surface down / bad pivot)
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from ._oplog import record_action

# A response is "blocked-by-allowlist" when its status is in `blocked_status`
# AND (a given blocked_regex matches OR, with no regex, one of these phrases is
# present). Lowercased substring match.
DEFAULT_BLOCK_PHRASES = (
    "ip allow list",
    "ip allowlist",
    "not permitted to access",
    "access denied",
    "not allowed from your",
)

# How much body we look at for phrase matching, and how much we keep as evidence.
_MATCH_WINDOW = 4096
_SNIPPET = 160

# Header-trust bypass: client-IP headers an app may WRONGLY trust as its ACL
# source (distinct from a network/TCP allowlist — see the skill). Injecting a
# trusted/loopback value into one of these bypasses the check when the app reads
# it. Order = the `spoof_headers='auto'` set. `Forwarded` carries `for=<ip>`.
STANDARD_SPOOF_HEADERS = (
    "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP",
    "CF-Connecting-IP", "X-Originating-IP", "X-Forwarded-Host", "Forwarded",
)
# Multi-value headers whose leftmost-vs-rightmost parse decides which IP wins
# (CloudStack CVE-2024-29006, 1Panel CVE-2025-66508, Heimdall Forwarded). Each
# gets a single-value probe PLUS a leftmost and a rightmost differential variant.
_DIFFERENTIAL_SPOOF_HEADERS = {"x-forwarded-for", "forwarded"}
# Non-trusted decoy for the parser-differential variants (TEST-NET-3, RFC 5737).
_SPOOF_DECOY_IP = "203.0.113.9"
# Hard cap on extra probes per surface (8 headers + 2×2 variants = 12).
_SPOOF_CAP = 12

# IP-format normalisation bypass (partial-match / prefix-allowlist class, n8n
# CVE-2025-68949 + classic SSRF/allowlist filter bypass): a filter that
# string-compares — or a fronting proxy that re-parses — a client-IP header can
# be fooled by an ALTERNATE ENCODING of the trusted IP (dotless-decimal, octal,
# hex, IPv6-mapped, short form, trailing dot). Only the headers that actually
# CARRY a bare IP get the format variants (Forwarded uses `for=` syntax and
# X-Forwarded-Host is a hostname — both excluded here).
_IP_FORMAT_HEADERS = (
    "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
    "True-Client-IP", "CF-Connecting-IP", "X-Originating-IP",
)
# Hard cap on IP-format probes per surface (separate budget from _SPOOF_CAP).
_FMT_CAP = 24

# Optional convenience presets — read-only identity probes only. NOT the core
# path; operator-supplied surfaces are. gitlab/okta self-managed hosts come from
# $PRAETOR_ALLOWLIST_BASE (else those entries are skipped with a note).
def _presets(name: str, base: str) -> list[dict]:
    name = (name or "").strip().lower()
    if name == "github":
        return [
            {"label": "gh-api-user", "url": "https://api.github.com/user"},
            {"label": "gh-graphql-viewer", "url": "https://api.github.com/graphql",
             "method": "POST", "body": '{"query":"{viewer{login}}"}'},
        ]
    if name == "gitlab":
        b = base or "https://gitlab.com"
        return [{"label": "gl-api-user", "url": f"{b.rstrip('/')}/api/v4/user"}]
    if name == "okta":
        # Okta host is org-specific — needs a base, no universal default.
        return ([{"label": "okta-users-me", "url": f"{base.rstrip('/')}/api/v1/users/me"}]
                if base else [])
    return []  # "generic" or unknown -> nothing


def _shape_secret(value: str) -> str:
    """Redacted preview of a secret — recognisable, never the whole value."""
    v = (value or "").strip()
    if not v:
        return ""
    if len(v) <= 10:
        return f"{v[:2]}… (len {len(v)})"
    return f"{v[:4]}…{v[-4:]}"


def _redact(text: str, *secrets: str) -> str:
    """Replace every non-empty secret occurrence with its shape."""
    if not text:
        return text
    for s in secrets:
        s = (s or "").strip()
        if len(s) >= 6 and s in text:
            text = text.replace(s, _shape_secret(s))
    return text


def _parse_blocked_status(spec: str) -> set[int]:
    out: set[int] = set()
    for tok in re.split(r"[,\s]+", (spec or "").strip()):
        if tok.isdigit():
            out.add(int(tok))
    return out or {403, 451}


def _coerce_surface(item: Any) -> dict | None:
    """Normalise one surface entry (dict or string) to {label,url,method,headers,body}."""
    if isinstance(item, dict):
        url = (item.get("url") or item.get("URL") or "").strip()
        if not url:
            return None
        return {
            "label": (item.get("label") or item.get("name") or url).strip(),
            "url": url,
            "method": (item.get("method") or "GET").strip().upper(),
            "headers": item.get("headers") or {},
            "body": item.get("body") or item.get("data") or "",
        }
    if isinstance(item, str):
        entry = item.strip()
        if not entry or entry.startswith("#"):
            return None
        # "label|url|method"  OR  "label url method"  OR  bare url
        parts = [p.strip() for p in (entry.split("|") if "|" in entry else entry.split())]
        parts = [p for p in parts if p]
        url_tokens = [p for p in parts if "://" in p]
        if not url_tokens:
            return None
        url = url_tokens[0]
        idx = parts.index(url)
        label = parts[0] if idx > 0 else url
        method = "GET"
        if idx + 1 < len(parts) and parts[idx + 1].isalpha():
            method = parts[idx + 1].upper()
        return {"label": label, "url": url, "method": method, "headers": {}, "body": ""}
    return None


def _parse_surfaces(surfaces: Any) -> list[dict]:
    """Accept a list, a JSON string, or a newline/semicolon-delimited string."""
    if isinstance(surfaces, list):
        raw: list[Any] = surfaces
    else:
        s = (surfaces or "").strip()
        if not s:
            return []
        raw = []
        if s[0] in "[{":
            try:
                parsed = json.loads(s)
                raw = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                raw = re.split(r"[\n;]+", s)
        else:
            raw = re.split(r"[\n;]+", s)
    out: list[dict] = []
    for item in raw:
        surf = _coerce_surface(item)
        if surf:
            out.append(surf)
    return out


def _probe_verdict(
    status: int | None,
    body: str,
    blocked_statuses: set[int],
    blocked_regex: str,
) -> tuple[str, str]:
    """Classify ONE probe -> (ALLOWED|BLOCKED|BAD_AUTH|INCONCLUSIVE, note)."""
    if status is None:
        return "INCONCLUSIVE", "no response (connection/proxy error)"
    if 200 <= status < 300:
        return "ALLOWED", f"{status} served"
    if status == 401:
        return "BAD_AUTH", f"{status} — auth missing/invalid; supply a valid operator credential"
    if status in blocked_statuses:
        b = body or ""
        if blocked_regex:
            if re.search(blocked_regex, b, re.I):
                return "BLOCKED", f"{status} matches blocked_regex"
            return "INCONCLUSIVE", f"{status} but body did not match blocked_regex"
        low = b.lower()
        hit = next((p for p in DEFAULT_BLOCK_PHRASES if p in low), "")
        if hit:
            return "BLOCKED", f"{status} allowlist phrase '{hit}'"
        return "BLOCKED", f"{status} (status-only; no allowlist phrase matched)"
    return "INCONCLUSIVE", f"{status} unexpected"


def _surface_verdict(off_raw: str, on_raw: str | None) -> str:
    """Map probe classifications to ENFORCED / GAP / INCONCLUSIVE."""
    if on_raw is None:  # single mode
        if off_raw == "ALLOWED":
            return "GAP"
        if off_raw == "BLOCKED":
            return "ENFORCED"
        return "INCONCLUSIVE"
    # differential
    if off_raw == "ALLOWED":
        return "GAP"  # off-list served -> allowlist ignored (covers both-allowed)
    if off_raw == "BLOCKED" and on_raw == "ALLOWED":
        return "ENFORCED"
    return "INCONCLUSIVE"  # off blocked + on blocked/bad, or off bad-auth


def _spoof_header_value(header: str, ip: str) -> str:
    """`Forwarded` uses the `for=<ip>` syntax; every other header is the raw IP."""
    return f"for={ip}" if header.strip().lower() == "forwarded" else ip


def _spoof_probes(spoof_headers: str, spoof_value: str) -> list[dict]:
    """Build the header-trust probe list -> [{header, value, position}].

    Empty spoof_headers = off ([]). 'auto' = STANDARD_SPOOF_HEADERS; otherwise a
    comma list of header names. XFF/Forwarded each add leftmost + rightmost
    parser-differential variants. Capped at _SPOOF_CAP.
    """
    spec = (spoof_headers or "").strip()
    if not spec:
        return []
    names = (list(STANDARD_SPOOF_HEADERS) if spec.lower() == "auto"
             else [h.strip() for h in spec.split(",") if h.strip()])
    ip = (spoof_value or "127.0.0.1").strip() or "127.0.0.1"
    decoy = _SPOOF_DECOY_IP
    probes: list[dict] = []
    seen: set[str] = set()
    for h in names:
        key = h.lower()
        if key in seen:
            continue
        seen.add(key)
        probes.append({"header": h, "value": _spoof_header_value(h, ip),
                       "position": "single"})
        if key in _DIFFERENTIAL_SPOOF_HEADERS:
            trusted = _spoof_header_value(h, ip)
            noise = _spoof_header_value(h, decoy)
            probes.append({"header": h, "value": f"{trusted}, {noise}",
                           "position": "leftmost"})
            probes.append({"header": h, "value": f"{noise}, {trusted}",
                           "position": "rightmost"})
    return probes[:_SPOOF_CAP]


def _ip_format_variants(ip: str) -> list[tuple[str, str]]:
    """Alternate encodings of an IPv4 address that normalise back to it.

    Returns [(label, value)] — de-duped, order preserved. Covers dotless-decimal
    (2130706433), full octal (0177.0.0.1), per-octet hex (0x7f.0x0.0x0.0x1),
    hex-dword (0x7f000001), short form (127.1), IPv6-mapped
    (::ffff:127.0.0.1 + bracketed) and a trailing dot (127.0.0.1.). When the
    input is a loopback address the IPv6 loopback forms (::1 + bracketed) are
    added too. Returns [] for anything that is not a plain IPv4 literal.
    """
    try:
        addr = ipaddress.IPv4Address((ip or "").strip())
    except ValueError:
        return []
    o = [int(p) for p in addr.exploded.split(".")]
    dword = int(addr)
    short = (o[1] << 16) | (o[2] << 8) | o[3]  # last 3 octets fold into one field
    variants: list[tuple[str, str]] = [
        ("dotless-decimal", str(dword)),
        ("dotted-octal", ".".join(f"0{x:o}" for x in o)),
        ("hex-octet", ".".join(f"0x{x:x}" for x in o)),
        ("hex-dword", f"0x{dword:x}"),
        ("mixed-short", f"{o[0]}.{short}"),
        ("ipv6-mapped", f"::ffff:{addr}"),
        ("ipv6-mapped-bracketed", f"[::ffff:{addr}]"),
        ("trailing-dot", f"{addr}."),
    ]
    if addr.is_loopback:  # 127.0.0.0/8 — the IPv6 loopback aliases the same host
        variants += [("ipv6-loopback", "::1"), ("ipv6-loopback-bracketed", "[::1]")]
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for label, val in variants:
        if val in seen:
            continue
        seen.add(val)
        out.append((label, val))
    return out


def _ip_format_header_set(spoof_headers: str) -> list[str]:
    """The requested spoof headers that CARRY a bare IP (canonical casing).

    Intersects the spoof_headers spec ('auto' or a comma list) with
    _IP_FORMAT_HEADERS, so Forwarded / X-Forwarded-Host never receive IP-format
    variants. De-duped, order = _IP_FORMAT_HEADERS' first appearance.
    """
    spec = (spoof_headers or "").strip()
    if not spec:
        return []
    names = (list(STANDARD_SPOOF_HEADERS) if spec.lower() == "auto"
             else [h.strip() for h in spec.split(",") if h.strip()])
    ipf = {h.lower(): h for h in _IP_FORMAT_HEADERS}
    out: list[str] = []
    seen: set[str] = set()
    for h in names:
        k = h.lower()
        if k in ipf and k not in seen:
            seen.add(k)
            out.append(ipf[k])
    return out


def _ip_format_probes(spoof_headers: str, spoof_value: str) -> list[dict]:
    """Build the IP-format probe list -> [{header, label, value}], capped.

    For each IP-bearing header, one probe per encoding of spoof_value. Bounded
    by _FMT_CAP across the whole surface (separate from _SPOOF_CAP).
    """
    headers = _ip_format_header_set(spoof_headers)
    variants = _ip_format_variants(spoof_value)
    if not headers or not variants:
        return []
    probes: list[dict] = []
    for h in headers:
        for label, val in variants:
            probes.append({"header": h, "label": label, "value": val})
    return probes[:_FMT_CAP]


def _check_source_bind(addr: str) -> str:
    """Pre-flight for source_bind: '' when this host can bind `addr`, else why.

    Validates it is an IP literal and that the host actually owns it (a bind to
    an unassigned address fails EADDRNOTAVAIL) — an honest source-IP test needs
    an operator-owned local address, never a spoof.
    """
    a = (addr or "").strip()
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return f"source_bind '{a}' is not a valid IP address."
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.bind((a, 0))
    except OSError as e:
        return (f"source_bind '{a}' cannot be bound on this host "
                f"({type(e).__name__}: {e}) — it must be an IP assigned to a "
                f"local interface this host owns.")
    finally:
        s.close()
    return ""


def _socks_available() -> bool:
    try:
        import socksio  # noqa: F401
        return True
    except Exception:
        return False


async def _probe(client: httpx.AsyncClient, surface: dict, auth_value: str,
                 timeout: int) -> tuple[int | None, str, str]:
    """One request. Returns (status, body_match_window, error). Body is capped."""
    headers: dict[str, str] = {}
    if auth_value:
        headers["Authorization"] = auth_value
    headers.update(surface.get("headers") or {})
    method = surface.get("method") or "GET"
    body = surface.get("body") or None
    try:
        resp = await client.request(method, surface["url"], headers=headers,
                                    content=body, timeout=timeout)
        # NOTE: httpx downloads the full body; we keep only a bounded window and
        # a short snippet — never the whole response. Upgrade path: stream+abort
        # after _MATCH_WINDOW bytes if a surface ever returns a large payload.
        return resp.status_code, (resp.text or "")[:_MATCH_WINDOW], ""
    except Exception as e:  # network/proxy/TLS error -> INCONCLUSIVE for this probe
        return None, "", f"{type(e).__name__}: {e}"


async def _probe_spoofed(client: httpx.AsyncClient, surface: dict, auth_value: str,
                         timeout: int, header: str, value: str
                         ) -> tuple[int | None, str, str]:
    """One READ-ONLY probe with a single client-IP header injected. Caller wins
    ties only for real conflicts — the spoof header is added on top of the
    surface's own headers so the app sees the trusted value."""
    spoofed = dict(surface)
    merged = dict(surface.get("headers") or {})
    merged[header] = value
    spoofed["headers"] = merged
    return await _probe(client, spoofed, auth_value, timeout)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def ip_allowlist_coverage(
        surfaces: Any = "",
        auth_header: str = "",
        auth_env: str = "",
        proxy: str = "",
        baseline_proxy: str = "",
        blocked_status: str = "403,451",
        blocked_regex: str = "",
        spoof_headers: str = "",
        spoof_value: str = "127.0.0.1",
        source_bind: str = "",
        preset: str = "",
        domain: str = "",
        timeout: int = 20,
    ) -> dict:
        """Audit whether a service enforces its IP allowlist across ALL surfaces.

        Vendor-agnostic. Read-only recon of the org's OWN control (RoE names the
        service). ONE request per surface per vantage; the auth credential is
        REDACTED in every returned/logged string.

        Args:
            surfaces: the endpoints to test. Accepts (a) a JSON array of
                {label,url,method?,headers?,body?} objects, or (b) a
                newline/semicolon-delimited list where each line is
                `label|url|method`, `label url method`, or a bare url.
                method defaults to GET.
            auth_header: Authorization header VALUE sent on every probe
                (e.g. 'Bearer ghp_...', 'token ...', 'SSWS ...'). REDACTED.
            auth_env: name of an env var to read the auth value from when
                auth_header is empty (inline auth_header wins).
            proxy: egress for the off_list probe — the vantage under audit,
                presumed NOT allowlisted. socks5://host:port or http://host:port.
                Empty = direct/current source. (SOCKS needs the httpx[socks]
                extra; if absent the run returns a clear error.)
            baseline_proxy: egress for the on_list probe — a KNOWN-allowlisted
                positive control (the pivot through an in-scope foothold).
                Given -> each surface is probed through BOTH vantages and a
                differential is computed.
            blocked_status: comma list of statuses that mean allowlist-block
                (default '403,451').
            blocked_regex: if set, a blocked status is only a block when the
                body matches this regex; if unset, default allowlist phrases are
                used as the corroboration heuristic.
            spoof_headers: header-trust probe mode (distinct from a network
                allowlist — tests whether the APP trusts a client-IP header as
                its ACL source). Empty = off. 'auto' = the standard set
                (X-Forwarded-For, X-Real-IP, X-Client-IP, True-Client-IP,
                CF-Connecting-IP, X-Originating-IP, X-Forwarded-Host, Forwarded).
                Or a comma list of header names. When set, each surface whose
                BASELINE probe was BLOCKED gets one extra READ-ONLY probe per
                header injecting spoof_value; X-Forwarded-For and Forwarded also
                get leftmost/rightmost parser-differential variants. A spoof
                probe that returns 2xx = HEADER_TRUST_BYPASS. Capped at
                ~12 extra probes/surface. When set, the IP-BEARING headers
                (X-Forwarded-For, X-Real-IP, X-Client-IP, True-Client-IP,
                CF-Connecting-IP, X-Originating-IP — NOT X-Forwarded-Host /
                Forwarded) ALSO get one probe per ALTERNATE ENCODING of
                spoof_value (dotless-decimal, octal, hex-octet, hex-dword,
                short form, IPv6-mapped, trailing dot). A format probe that
                returns 2xx = IP_FORMAT_BYPASS (partial-match / prefix-allowlist
                class, n8n CVE-2025-68949). Capped at ~24 extra probes/surface,
                separate from the header-trust budget.
            spoof_value: the trusted/loopback IP injected into the spoof headers,
                and the IP whose alternate encodings are generated for the
                IP-format probes (default '127.0.0.1').
            source_bind: OPTIONAL local source IP to bind outgoing connections
                to (httpx local_address). This is the HONEST way to test a real
                source-IP prefix/near-IP acceptance flaw: source the probe from
                an IP you CONTROL (adjacent to a trusted entry) — NOT spoofing,
                which is impossible for TCP. Requires an operator-owned address
                assigned to a local interface; if the host cannot bind it the run
                returns a clear error instead of proceeding.
            preset: optional convenience expansion of benign identity probes —
                'github' | 'gitlab' | 'okta' | 'generic'. Merged with `surfaces`.
                gitlab/okta self-managed hosts read $PRAETOR_ALLOWLIST_BASE.
            domain: engagement key for the operator log (recon evidence).
            timeout: per-request seconds (default 20).

        Returns a matrix dict: {source, baseline, source_bind, auth,
        results:[{label,url,method, off_list:{status,verdict},
        on_list?:{status,verdict}, verdict, evidence,
        header_trust?:[{header,position,status,verdict}],
        ip_format?:[{header,format,value,status,verdict}]}], gaps:[labels],
        header_bypasses:[{label,header,position}],
        ip_format_bypasses:[{label,header,format,value}], summary}. verdict is
        ENFORCED / GAP / INCONCLUSIVE; header_trust / ip_format and their
        top-level bypass lists appear only when spoof mode is on.
        """
        auth_value = auth_header.strip() or (os.environ.get(auth_env, "").strip() if auth_env else "")
        auth_shape = _shape_secret(auth_value)

        base = os.environ.get("PRAETOR_ALLOWLIST_BASE", "").strip()
        surface_list = _presets(preset, base) if preset else []
        surface_list += _parse_surfaces(surfaces)
        if not surface_list:
            return {"error": "No surfaces to test. Supply `surfaces` (JSON array or "
                             "newline/semicolon list) and/or a `preset`."}

        blocked_statuses = _parse_blocked_status(blocked_status)

        # SOCKS proxies need the httpx[socks] extra — degrade with a clear error.
        for p in (proxy, baseline_proxy):
            if p.strip().lower().startswith("socks") and not _socks_available():
                return {"error": "SOCKS proxy requested but the httpx[socks] extra "
                                 "(socksio) is not installed. Use an http:// proxy, "
                                 "or `uv pip install httpx[socks]`.",
                        "proxy": proxy, "baseline_proxy": baseline_proxy}

        # Optional real-source-IP binding — honest prefix/near-IP test, no spoof.
        bind = source_bind.strip()
        if bind:
            bind_err = _check_source_bind(bind)
            if bind_err:
                return {"error": bind_err, "source_bind": bind}

        source = proxy.strip() or "direct"
        differential = bool(baseline_proxy.strip())
        spoof_probe_list = _spoof_probes(spoof_headers, spoof_value)
        ip_format_probe_list = _ip_format_probes(spoof_headers, spoof_value)

        common = dict(follow_redirects=False,
                      headers={"User-Agent": "praetor-allowlist-audit"})

        def _mk_client(proxy_url: str | None) -> httpx.AsyncClient:
            # local_address binding needs an explicit transport (also carries the
            # proxy); without it, the plain client keeps the existing behaviour.
            if bind:
                transport = httpx.AsyncHTTPTransport(
                    local_address=bind, proxy=proxy_url, verify=True)
                return httpx.AsyncClient(transport=transport, **common)
            return httpx.AsyncClient(proxy=proxy_url, verify=True, **common)

        off_client = _mk_client(proxy.strip() or None)
        on_client = _mk_client(baseline_proxy.strip()) if differential else None

        results: list[dict] = []
        header_bypasses: list[dict] = []
        ip_format_bypasses: list[dict] = []
        try:
            for surf in surface_list:
                off_status, off_body, off_err = await _probe(off_client, surf, auth_value, timeout)
                off_raw, off_note = _probe_verdict(off_status, off_body, blocked_statuses, blocked_regex)

                on_raw: str | None = None
                on_entry = None
                on_note = ""
                if on_client is not None:
                    on_status, on_body, on_err = await _probe(on_client, surf, auth_value, timeout)
                    on_raw, on_note = _probe_verdict(on_status, on_body, blocked_statuses, blocked_regex)
                    on_entry = {"status": on_status, "verdict": on_raw}

                verdict = _surface_verdict(off_raw, on_raw)
                # Evidence: bounded snippet, auth redacted.
                snippet = _redact((off_err or off_body or "").strip(), auth_value, auth_env)[:_SNIPPET]
                evidence = f"off:{off_note}"
                if on_raw is not None:
                    evidence += f" | on:{on_note}"
                if snippet:
                    evidence += f" | body:{snippet}"

                row = {
                    "label": surf["label"],
                    "url": surf["url"],
                    "method": surf.get("method", "GET"),
                    "off_list": {"status": off_status, "verdict": off_raw},
                    "verdict": verdict,
                    "evidence": _redact(evidence, auth_value)[:400],
                }
                if on_entry is not None:
                    row["on_list"] = on_entry

                # Header-trust probes (additive; does NOT change the verdict above).
                # Only when baseline (off_list) was BLOCKED — an already-ALLOWED
                # surface is a GAP already; probing it would double-count (N/A).
                if spoof_probe_list:
                    header_trust: list[dict] = []
                    if off_raw == "BLOCKED":
                        for sp in spoof_probe_list:
                            s_status, s_body, _ = await _probe_spoofed(
                                off_client, surf, auth_value, timeout,
                                sp["header"], sp["value"])
                            s_raw, _ = _probe_verdict(s_status, s_body,
                                                      blocked_statuses, blocked_regex)
                            ht = "HEADER_TRUST_BYPASS" if s_raw == "ALLOWED" else s_raw
                            header_trust.append({
                                "header": sp["header"], "position": sp["position"],
                                "status": s_status, "verdict": ht,
                            })
                            if ht == "HEADER_TRUST_BYPASS":
                                header_bypasses.append({
                                    "label": surf["label"],
                                    "header": sp["header"],
                                    "position": sp["position"],
                                })
                    row["header_trust"] = header_trust

                # IP-format normalisation probes (additive; verdict unchanged).
                # Same gate as header-trust: only a BLOCKED baseline surface is
                # worth re-probing with an alternate encoding of the trusted IP.
                if ip_format_probe_list:
                    ip_format: list[dict] = []
                    if off_raw == "BLOCKED":
                        for fp in ip_format_probe_list:
                            f_status, f_body, _ = await _probe_spoofed(
                                off_client, surf, auth_value, timeout,
                                fp["header"], fp["value"])
                            f_raw, _ = _probe_verdict(f_status, f_body,
                                                      blocked_statuses, blocked_regex)
                            fv = "IP_FORMAT_BYPASS" if f_raw == "ALLOWED" else f_raw
                            ip_format.append({
                                "header": fp["header"], "format": fp["label"],
                                "value": fp["value"], "status": f_status,
                                "verdict": fv,
                            })
                            if fv == "IP_FORMAT_BYPASS":
                                ip_format_bypasses.append({
                                    "label": surf["label"],
                                    "header": fp["header"],
                                    "format": fp["label"],
                                    "value": fp["value"],
                                })
                    row["ip_format"] = ip_format
                results.append(row)
        finally:
            await off_client.aclose()
            if on_client is not None:
                await on_client.aclose()

        gaps = [r["label"] for r in results if r["verdict"] == "GAP"]
        enforced = sum(1 for r in results if r["verdict"] == "ENFORCED")
        inconc = sum(1 for r in results if r["verdict"] == "INCONCLUSIVE")
        summary = (f"{len(results)} surface(s): {enforced} ENFORCED, {len(gaps)} GAP, "
                   f"{inconc} INCONCLUSIVE"
                   + (f". GAPS: {', '.join(gaps)}" if gaps else ""))
        if spoof_probe_list:
            summary += (f". HEADER-TRUST BYPASSES: {len(header_bypasses)}"
                        + (" (" + ", ".join(sorted({b["label"] for b in header_bypasses}))
                           + ")" if header_bypasses else ""))
        if ip_format_probe_list:
            summary += (f". IP-FORMAT BYPASSES: {len(ip_format_bypasses)}"
                        + (" (" + ", ".join(sorted({b["label"] for b in ip_format_bypasses}))
                           + ")" if ip_format_bypasses else ""))

        # Operator log — benign recon of the control. Auth REDACTED in command.
        if domain:
            spoof_note = (f"{spoof_headers.strip()}({len(spoof_probe_list)}/surface,{spoof_value.strip()})"
                          if spoof_probe_list else "off")
            fmt_note = (f"{len(ip_format_probe_list)}/surface,{spoof_value.strip()}"
                        if ip_format_probe_list else "off")
            cmd = (f"ip_allowlist_coverage surfaces={len(surface_list)} source={source} "
                   f"baseline={baseline_proxy.strip() or 'none'} "
                   f"bind={bind or 'none'} "
                   f"auth={auth_shape or 'none'} blocked_status={sorted(blocked_statuses)} "
                   f"spoof={spoof_note} ip_format={fmt_note}")
            record_action(
                domain, "ip_allowlist_coverage", _redact(cmd, auth_value),
                description=f"IP-allowlist coverage audit: {summary}",
                source=source, target=f"{len(surface_list)} surface(s)",
                output=summary, tactic="Reconnaissance", technique="T1590",
                tags=["ip-allowlist", "control-audit", "read-only"],
            )

        return {
            "source": source,
            "baseline": baseline_proxy.strip() or None,
            "source_bind": bind or None,
            "auth": auth_shape or None,
            "results": results,
            "gaps": gaps,
            "header_bypasses": header_bypasses,
            "ip_format_bypasses": ip_format_bypasses,
            "summary": summary,
        }
