"""analyze_csp — Content-Security-Policy bypass analyzer (W29-f).

Parses a CSP header (from a captured response or a direct fetch) and reports
known-exploitable misconfigs. Single-source-of-truth heuristics tracked
against 2026-current bypass catalogs (CSP Evaluator, Lucas Pinheiro's
trusted-types research, jsdelivr/unpkg JSONP escapes).

Categories detected:
  1. **wildcard_in_script_src** — `script-src *` or `default-src *`
  2. **unsafe_inline_in_script_src** — allows inline `<script>` blocks
  3. **unsafe_eval_in_script_src** — allows eval/Function/setTimeout-string
  4. **missing_nonce_or_strict_dynamic** — script-src has neither nonce nor
     strict-dynamic → relies on host allowlist, prone to JSONP escapes
  5. **risky_cdn_allowlist** — common CDNs that ship JSONP endpoints or
     user-uploadable JS (jsdelivr, unpkg, googleapis, googletagmanager,
     facebook.net, cdn.ampproject.org, ajax.aspnetcdn.com, cdn.shopify.com)
  6. **object_src_not_none** — `object-src` allows Flash/PDF/Java plugins
  7. **base_uri_unrestricted** — base-uri allows attacker to relocate
     relative-script-src loads (CVE class)
  8. **frame_ancestors_unrestricted** — clickjacking enabler
  9. **report_only_mode** — CSP is Content-Security-Policy-Report-Only,
     no enforcement at all
  10. **missing_critical_directive** — no default-src, script-src,
      object-src, base-uri

Returns VerdictResult.

This tool is purely analytical — it fetches the URL once (if header_blob
isn't supplied) and parses the CSP. No payload sent at the target.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


# CDNs that ship JSONP / user-uploadable JS — script-src allowlist with these
# can typically be escaped to arbitrary JS execution.
_RISKY_CDNS = {
    "*.jsdelivr.net": "JSONP via /npm/*; arbitrary npm package fetch",
    "cdn.jsdelivr.net": "JSONP via /npm/*; arbitrary npm package fetch",
    "unpkg.com": "Arbitrary npm package CDN fetch",
    "ajax.googleapis.com": "AngularJS JSONP gadget (1.x)",
    "www.googletagmanager.com": "GTM custom-tag JS injection if attacker has GTM access",
    "googletagmanager.com": "GTM custom-tag JS injection if attacker has GTM access",
    "*.facebook.net": "FB SDK has had JSONP-like endpoints",
    "cdn.ampproject.org": "AMP scripts have eval-like behaviour",
    "ajax.aspnetcdn.com": "JSONP via older jQuery versions",
    "*.cdn.shopify.com": "User-uploadable assets",
    "code.jquery.com": "Older jQuery loads have JSONP gadgets",
    "stackpath.bootstrapcdn.com": "Older bootstrap gadgets",
    "maxcdn.bootstrapcdn.com": "Older bootstrap gadgets",
    "*.cloudfront.net": "Anyone can host on CloudFront",
    "*.amazonaws.com": "S3 bucket misconfig → JS upload",
    "*.azureedge.net": "Azure CDN — any tenant",
    "storage.googleapis.com": "GCS bucket misconfig → JS upload",
}


# Required directives — absence of these means relevant policy gaps
_REQUIRED_DIRECTIVES = ("default-src", "script-src", "object-src", "base-uri")


def _parse_csp(csp: str) -> dict[str, list[str]]:
    """Parse a CSP string into {directive: [source1, source2, ...]}."""
    out: dict[str, list[str]] = {}
    if not csp:
        return out
    for clause in csp.split(";"):
        clause = clause.strip()
        if not clause:
            continue
        parts = clause.split()
        directive = parts[0].lower()
        sources = parts[1:] if len(parts) > 1 else []
        out[directive] = sources
    return out


def _effective_script_src(parsed: dict[str, list[str]]) -> list[str]:
    """Return the effective script-src list (fallback to default-src)."""
    if "script-src" in parsed:
        return parsed["script-src"]
    if "default-src" in parsed:
        return parsed["default-src"]
    return []


def _detect_risky_cdns(sources: list[str]) -> list[tuple[str, str]]:
    """Return (cdn_host, reason) for each risky CDN allowlist entry."""
    hits = []
    for src in sources:
        src_lower = src.lower().strip("'\"")
        # Strip scheme prefix
        for prefix in ("https://", "http://", "//"):
            if src_lower.startswith(prefix):
                src_lower = src_lower[len(prefix):]
                break
        # Strip path
        src_lower = src_lower.split("/")[0]
        for risky, reason in _RISKY_CDNS.items():
            if risky == src_lower or (
                risky.startswith("*.") and src_lower.endswith(risky[1:])
            ):
                hits.append((src_lower, reason))
                break
    return hits


def _has_token(sources: list[str], token: str) -> bool:
    return any(s.lower().strip("'\"") == token.lstrip("'").rstrip("'")
               for s in sources)


def _has_nonce_or_hash(sources: list[str]) -> bool:
    return any(s.lower().startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
               for s in sources)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def analyze_csp(  # cost: 0-1 requests
        target_url: str = "",
        header_blob: str = "",
        is_report_only: bool = False,
    ) -> dict:
        """Analyze a Content-Security-Policy for known-exploitable misconfigs.

        Either supply target_url (we fetch + parse the response CSP header)
        OR supply header_blob directly (already-captured CSP string).

        VerdictResult:
          - CONFIRMED — at least one HIGH-severity bypass is present
            (wildcard in script-src, unsafe-inline + no nonce, risky CDN
            allowlist, report-only mode with sensitive content)
          - SUSPECTED — MEDIUM issues (loose CDN list, missing base-uri,
            missing object-src none)
          - FAILED — CSP is well-configured (strict-dynamic + nonce, no
            unsafe-inline, no wildcards, restricted directives)

        Args:
            target_url: URL to fetch (skip if header_blob supplied)
            header_blob: pre-captured CSP header value
            is_report_only: True if CSP is in report-only mode
        """
        csp_str = header_blob
        logger_indices: list[int] = []

        if not csp_str and target_url:
            scope = await client.check_scope(target_url)
            if not scope.get("in_scope"):
                return error_verdict("csp_misconfig", "out_of_scope",
                                     f"{target_url} not in scope")
            resp = await client.post("/api/http/curl", json={
                "method": "GET",
                "url": target_url,
                "follow_redirects": False,
                "timeout": 20,
            })
            if resp.get("error"):
                return error_verdict("csp_misconfig", "fetch_failed",
                                     resp.get("error", ""))
            if "logger_index" in resp:
                logger_indices.append(resp["logger_index"])
            hdrs = {k.lower(): v for k, v in (resp.get("response_headers") or {}).items()}
            csp_str = hdrs.get("content-security-policy", "")
            if not csp_str:
                csp_str = hdrs.get("content-security-policy-report-only", "")
                if csp_str:
                    is_report_only = True

        if not csp_str:
            return make_verdict(
                vuln_type="csp_missing",
                verdict="CONFIRMED",
                confidence=0.9,
                evidence_summary="No Content-Security-Policy header — site has no client-side XSS mitigation layer",
                logger_indices=logger_indices,
                details={"target_url": target_url},
                human_summary="CSP missing — XSS mitigation absent",
            )

        parsed = _parse_csp(csp_str)
        script_src = _effective_script_src(parsed)
        issues: list[dict] = []

        # 1. report-only mode = no enforcement
        if is_report_only:
            issues.append({
                "category": "report_only",
                "severity": "high",
                "evidence": "CSP is Content-Security-Policy-Report-Only — violations logged but not blocked",
            })

        # 2. wildcard in script-src
        if "*" in script_src or _has_token(script_src, "https:") or _has_token(script_src, "http:"):
            issues.append({
                "category": "wildcard_in_script_src",
                "severity": "critical",
                "sources": script_src,
                "evidence": "script-src allows wildcard or scheme-only — any JS host loads",
            })

        # 3. unsafe-inline
        if _has_token(script_src, "'unsafe-inline'"):
            if not _has_nonce_or_hash(script_src) and not _has_token(script_src, "'strict-dynamic'"):
                issues.append({
                    "category": "unsafe_inline_unmitigated",
                    "severity": "critical",
                    "evidence": "script-src has 'unsafe-inline' with no nonce/hash/strict-dynamic — inline scripts execute",
                })
            else:
                issues.append({
                    "category": "unsafe_inline_mitigated",
                    "severity": "low",
                    "evidence": "unsafe-inline present but mitigated by nonce/strict-dynamic (legacy browsers still affected)",
                })

        # 4. unsafe-eval
        if _has_token(script_src, "'unsafe-eval'"):
            issues.append({
                "category": "unsafe_eval",
                "severity": "high",
                "evidence": "script-src has 'unsafe-eval' — eval / new Function / setTimeout(string) execute",
            })

        # 5. Missing nonce + missing strict-dynamic + has hostnames
        has_hosts = any(not s.lower().startswith("'") and s != "*" for s in script_src)
        if (has_hosts and not _has_nonce_or_hash(script_src)
                and not _has_token(script_src, "'strict-dynamic'")):
            issues.append({
                "category": "host_allowlist_without_nonce",
                "severity": "high",
                "evidence": "script-src relies on host allowlist with no nonce/strict-dynamic — prone to JSONP/CDN escape",
            })

        # 6. risky CDN allowlist
        risky = _detect_risky_cdns(script_src)
        if risky:
            issues.append({
                "category": "risky_cdn_allowlist",
                "severity": "critical",
                "cdns": [{"host": h, "reason": r} for h, r in risky],
                "evidence": f"{len(risky)} risky CDN(s) in script-src: " + ", ".join(h for h, _ in risky),
            })

        # 7. object-src not 'none'
        object_src = parsed.get("object-src", parsed.get("default-src", []))
        if not _has_token(object_src, "'none'"):
            issues.append({
                "category": "object_src_not_none",
                "severity": "medium",
                "evidence": f"object-src not 'none' — Flash/PDF/Java plugins can load (object-src: {object_src})",
            })

        # 8. base-uri unrestricted
        base_uri = parsed.get("base-uri", [])
        if not base_uri:
            issues.append({
                "category": "base_uri_missing",
                "severity": "medium",
                "evidence": "base-uri not set — attacker can <base href='evil/'> to relocate relative script loads",
            })
        elif "*" in base_uri or _has_token(base_uri, "https:"):
            issues.append({
                "category": "base_uri_unrestricted",
                "severity": "high",
                "evidence": f"base-uri allows wildcard or scheme-only ({base_uri}) — script relocation possible",
            })

        # 9. frame-ancestors
        frame_anc = parsed.get("frame-ancestors", [])
        if not frame_anc:
            issues.append({
                "category": "frame_ancestors_missing",
                "severity": "low",
                "evidence": "frame-ancestors not set — clickjacking via iframe possible",
            })
        elif "*" in frame_anc:
            issues.append({
                "category": "frame_ancestors_wildcard",
                "severity": "medium",
                "evidence": "frame-ancestors '*' — clickjacking enabled by policy",
            })

        # 10. Required directives missing
        for d in _REQUIRED_DIRECTIVES:
            if d not in parsed:
                # default-src is a fallback for many; missing default-src is severe
                if d == "default-src" and "script-src" in parsed:
                    continue
                issues.append({
                    "category": f"missing_{d.replace('-','_')}_directive",
                    "severity": "medium" if d == "default-src" else "low",
                    "evidence": f"directive {d!r} not present",
                })

        critical_count = sum(1 for i in issues if i["severity"] == "critical")
        high_count = sum(1 for i in issues if i["severity"] == "high")
        med_count = sum(1 for i in issues if i["severity"] == "medium")

        details = {
            "csp": csp_str,
            "parsed": parsed,
            "issues": issues,
            "issue_counts": {"critical": critical_count, "high": high_count, "medium": med_count},
            "report_only": is_report_only,
        }

        if critical_count or high_count:
            return make_verdict(
                vuln_type="csp_misconfig",
                verdict="CONFIRMED",
                confidence=0.9 if critical_count else 0.8,
                evidence_summary=(
                    f"{critical_count} critical + {high_count} high CSP issues: "
                    + ", ".join(i["category"] for i in issues
                                if i["severity"] in ("critical", "high"))
                ),
                logger_indices=logger_indices,
                details=details,
                human_summary=f"CSP bypassable: {critical_count} critical + {high_count} high issues",
            )
        if med_count:
            return make_verdict(
                vuln_type="csp_misconfig",
                verdict="SUSPECTED",
                confidence=0.55,
                evidence_summary=f"{med_count} medium-severity CSP issues",
                logger_indices=logger_indices,
                details=details,
                human_summary=f"CSP issues (medium): {med_count}",
            )
        return make_verdict(
            vuln_type="csp_misconfig",
            verdict="FAILED",
            confidence=0.85,
            evidence_summary="No critical/high CSP issues found",
            logger_indices=logger_indices,
            details=details,
            human_summary="CSP is well-configured",
        )
