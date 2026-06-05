"""probe_http3_downgrade — detect HTTP/3 reachability + downgrade differential.

HTTP/3 adoption surface (2026): Cloudflare, Cloudfront, Google, Meta, Fastly.
Servers that advertise H3 via `Alt-Svc: h3="..."` may behave differently on
H3 vs the H2 fallback path — different WAF (one is on, one isn't), different
caching layer, different header normalisation. Misconfig surfaces:

  1. **H2 enforces what H3 doesn't** — auth header / path-traversal filter
     missing on the H3 path because it's terminated by a separate proxy.
  2. **Cache key differs** — same URL returns different cached content per
     protocol; CDN smuggling.
  3. **Header de-encoding differs** — QPACK vs HPACK normalisation diverges,
     allowing request smuggling that doesn't work on H2.

This v1 probe is HTTP-layer only:
  - Parse `Alt-Svc` header for `h3=...` advertisement
  - Re-fetch with `Alt-Used: <h3-host:port>` and bypass-cache headers; compare
    response shape (status / length / headers / body hash) against the
    baseline H2 fetch
  - Flag any divergence as SUSPECTED — confirmation requires an actual H3
    client (aioquic) and an operator-controlled differential, deferred to v2

No new pip deps — uses existing curl_request path via Burp.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools._request_headers import apply_realistic_headers
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


# Alt-Svc entry: `h3=":443"; ma=86400` or `h3-29=":443"`
_ALT_SVC_H3_RE = re.compile(r'h3(?:-\d+)?\s*=\s*"([^"]+)"')


def _parse_alt_svc_for_h3(headers: list) -> list[str]:
    """Return list of host:port advertised for h3 (drafts + final)."""
    targets: list[str] = []
    for h in headers or []:
        name = h.get("name", "") if isinstance(h, dict) else ""
        if name.lower() != "alt-svc":
            continue
        val = h.get("value", "") if isinstance(h, dict) else ""
        for m in _ALT_SVC_H3_RE.finditer(val):
            ep = m.group(1).strip()
            # Alt-Svc value may be `:443` (same host, different port) or
            # `h3.example.com:443`. Caller resolves "same host" later.
            targets.append(ep)
    return targets


def _resp_fingerprint(resp: dict) -> dict[str, Any]:
    """Stable fingerprint of a response for differential comparison."""
    body = resp.get("response_body") or ""
    if isinstance(body, str):
        body_bytes = body.encode("utf-8", errors="replace")
    else:
        body_bytes = bytes(body or b"")
    # Header set — names only (values vary by request)
    header_names = sorted({
        (h.get("name", "") if isinstance(h, dict) else str(h)).lower()
        for h in resp.get("response_headers") or []
    })
    return {
        "status": resp.get("status_code", 0),
        "length": len(body_bytes),
        "body_sha256": hashlib.sha256(body_bytes).hexdigest()[:16],
        "header_names": header_names,
        "logger_index": resp.get("proxy_index", resp.get("history_index", -1)),
    }


def _diff_fingerprints(a: dict, b: dict) -> dict[str, Any]:
    """Return a diff dict highlighting divergence."""
    diffs: dict[str, Any] = {}
    if a["status"] != b["status"]:
        diffs["status"] = [a["status"], b["status"]]
    if a["length"] != b["length"] and abs(a["length"] - b["length"]) > 64:
        # Tolerate small byte-level differences (timestamps in body, etc.)
        diffs["length_delta"] = b["length"] - a["length"]
    if a["body_sha256"] != b["body_sha256"]:
        diffs["body_hash_differs"] = True
    set_a, set_b = set(a["header_names"]), set(b["header_names"])
    only_a = sorted(set_a - set_b)
    only_b = sorted(set_b - set_a)
    if only_a or only_b:
        diffs["header_diff"] = {"only_baseline": only_a, "only_h3path": only_b}
    return diffs


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_http3_downgrade(  # cost: low (2-3 requests)
        url: str,
        force_alt_used: str = "",
        bypass_cache: bool = True,
    ) -> dict:
        """Probe HTTP/3 reachability + downgrade differential.

        Two-step:
          1. Baseline GET captures Alt-Svc and the H2/H1.1 response.
          2. Re-fetch with `Alt-Used: <h3-target>` + cache-bypass headers;
             compare the fingerprint (status / length / body hash / header
             set) against baseline.

        Args:
            url: Target URL (any scheme).
            force_alt_used: Override Alt-Svc detection — operator-supplied
                Alt-Used target (e.g. 'h3.example.com:443'). Useful when the
                server doesn't advertise but a known H3 endpoint exists.
            bypass_cache: Add Cache-Control: no-cache + Pragma headers on
                the second fetch to defeat CDN caching of the baseline body.

        Returns VerdictResult. CONFIRMED when fingerprint differential
        between the H2 baseline and Alt-Used path is non-trivial (different
        body hash, different header set, or status delta). SUSPECTED on
        weak signal. FAILED when fingerprints match.
        """
        if not url:
            return error_verdict("url is required", vuln_type="http3_downgrade")

        scope_chk = await client.check_scope(url)
        if isinstance(scope_chk, dict):
            if "error" in scope_chk:
                return error_verdict(f"scope check failed: {scope_chk['error']}",
                                     vuln_type="http3_downgrade")
            if not scope_chk.get("in_scope", True):
                return error_verdict(f"{url} not in scope",
                                     vuln_type="http3_downgrade")

        # ── 1. Baseline ───
        baseline_headers = apply_realistic_headers(url, {})
        baseline = await client.post("/api/http/curl", json={
            "method": "GET", "url": url, "headers": baseline_headers,
            "follow_redirects": False,
        })
        if isinstance(baseline, dict) and "error" in baseline:
            return error_verdict(f"baseline failed: {baseline['error']}",
                                 vuln_type="http3_downgrade")

        # Find H3 advertisement
        h3_targets = _parse_alt_svc_for_h3(baseline.get("response_headers", []))
        if force_alt_used:
            h3_targets = [force_alt_used]
        if not h3_targets:
            # Server doesn't advertise H3 and operator didn't override.
            base_fp = _resp_fingerprint(baseline)
            return make_verdict(
                "FAILED", 0.10,
                "no Alt-Svc h3 advertisement found and no force_alt_used override",
                vuln_type="http3_downgrade",
                logger_indices=[base_fp["logger_index"]] if base_fp["logger_index"] >= 0 else [],
                details={"url": url, "baseline": base_fp, "h3_advertised": False},
                summary=(
                    "probe_http3_downgrade: no H3 advertisement\n"
                    f"  baseline status={base_fp['status']} len={base_fp['length']}\n"
                    f"  no Alt-Svc h3=... header — re-run with force_alt_used to probe known H3 target"
                ),
            )

        # ── 2. H3-path re-fetch ───
        # Resolve Alt-Used: ':443' → '<host>:443'; '<host>:port' → as-is.
        parsed = urlparse(url)
        host = parsed.hostname or ""
        alt_target = h3_targets[0]
        if alt_target.startswith(":"):
            alt_used = f"{host}{alt_target}"
        else:
            alt_used = alt_target

        h3_headers = apply_realistic_headers(url, {})
        h3_headers["Alt-Used"] = alt_used
        if bypass_cache:
            h3_headers["Cache-Control"] = "no-cache"
            h3_headers["Pragma"] = "no-cache"

        h3_resp = await client.post("/api/http/curl", json={
            "method": "GET", "url": url, "headers": h3_headers,
            "follow_redirects": False,
        })
        if isinstance(h3_resp, dict) and "error" in h3_resp:
            return error_verdict(f"H3-path fetch failed: {h3_resp['error']}",
                                 vuln_type="http3_downgrade")

        # ── 3. Diff ───
        base_fp = _resp_fingerprint(baseline)
        h3_fp = _resp_fingerprint(h3_resp)
        diff = _diff_fingerprints(base_fp, h3_fp)

        logger_indices = [i for i in (base_fp["logger_index"], h3_fp["logger_index"])
                          if isinstance(i, int) and i >= 0]
        details = {
            "url": url,
            "h3_targets_advertised": h3_targets,
            "alt_used": alt_used,
            "baseline": base_fp,
            "h3_path": h3_fp,
            "diff": diff,
            "bypass_cache": bypass_cache,
        }

        # Non-trivial divergence — body hash differs, or header set differs,
        # or status mismatches → SUSPECTED (operator confirms via actual H3
        # client + payload-based test).
        nontrivial = bool(
            "body_hash_differs" in diff or
            "status" in diff or
            "header_diff" in diff
        )
        # CONFIRMED only when status differs (clear evidence of divergent
        # processing paths). Body-hash + header diff alone are SUSPECTED.
        if "status" in diff:
            return make_verdict(
                "CONFIRMED", 0.80,
                f"H3-path status diverges from H2 baseline: {diff['status']} "
                f"(host={host}, alt_used={alt_used})",
                vuln_type="http3_downgrade",
                logger_indices=logger_indices,
                details=details,
                summary=(
                    f"probe_http3_downgrade: CONFIRMED divergence\n"
                    f"  baseline status={base_fp['status']} h3_path status={h3_fp['status']}\n"
                    f"  alt_used={alt_used} hash_differs={'body_hash_differs' in diff}\n"
                    f"  header_diff={diff.get('header_diff', {})}"
                ),
            )
        if nontrivial:
            return make_verdict(
                "SUSPECTED", 0.55,
                f"H3 advertised + fingerprint differs (hash/header) — "
                f"deeper test needs aioquic client",
                vuln_type="http3_downgrade",
                logger_indices=logger_indices,
                details=details,
                summary=(
                    f"probe_http3_downgrade: SUSPECTED\n"
                    f"  Alt-Svc advertised h3={h3_targets}\n"
                    f"  H3-path body/headers diverge from baseline — confirm with H3 client\n"
                    f"  diff={diff}"
                ),
            )
        return make_verdict(
            "FAILED", 0.15,
            f"H3 advertised but H2 and H3-path fingerprints match — "
            f"no downgrade differential observed",
            vuln_type="http3_downgrade",
            logger_indices=logger_indices,
            details=details,
            summary=(
                f"probe_http3_downgrade: no differential\n"
                f"  Alt-Svc advertised h3={h3_targets} but Alt-Used response matches baseline"
            ),
        )
