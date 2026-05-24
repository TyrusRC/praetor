"""shadow_repeater — background mutation pass on a captured request.

Takes a proxy_history index + target parameter, generates payload variants
via mutate_payload classes, runs them concurrently through Burp, reports
anomalies (status / length / timing delta vs baseline). Detects edge-case
WAF bypass and parser-discrepancy without manual iteration.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_DEFAULT_CLASSES = [
    "url_encode", "double_url", "case_toggle", "case_mixed",
    "sql_comment", "null_byte", "whitespace", "quote_rotate",
]


def _mutate(seed: str, classes: list[str]) -> list[str]:
    """Local payload mutator — mirrors mutate.py output without round-trip."""
    out: list[str] = []
    for cls in classes:
        if cls == "url_encode":
            out.append("".join(f"%{ord(c):02X}" for c in seed))
        elif cls == "double_url":
            once = "".join(f"%{ord(c):02X}" for c in seed)
            out.append("".join(f"%{ord(c):02X}" if c == "%" else c for c in once))
        elif cls == "case_toggle":
            out.append(seed.swapcase())
        elif cls == "case_mixed":
            out.append("".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(seed)))
        elif cls == "sql_comment":
            out.append(seed.replace(" ", "/**/"))
        elif cls == "null_byte":
            out.append(seed + "\x00.txt")
        elif cls == "whitespace":
            out.append(seed.replace(" ", "\t"))
            out.append(seed.replace(" ", "+"))
        elif cls == "quote_rotate":
            for src, dst in (("'", '"'), ('"', "'"), ("'", "`")):
                if src in seed:
                    out.append(seed.replace(src, dst))
        elif cls == "html_encode":
            out.append("".join(f"&#{ord(c)};" for c in seed))
        elif cls == "unicode_escape":
            out.append("".join(f"\\u{ord(c):04x}" for c in seed))
    seen, dedup = set(), []
    for v in out:
        if v and v not in seen and v != seed:
            seen.add(v)
            dedup.append(v)
    return dedup


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def shadow_repeater(
        index: int,
        parameter: str,
        seed: str = "",
        mutation_classes: list[str] | None = None,
        max_variants: int = 16,
        concurrency: int = 4,
    ) -> str:
        """Run a silent mutation pass against one parameter of a captured request.

        Args:
            index: proxy history index of the request to mutate.
            parameter: parameter name to fuzz (query string or body).
            seed: seed payload value (defaults to current parameter value).
            mutation_classes: subset of url_encode | double_url | case_toggle |
                case_mixed | sql_comment | null_byte | whitespace | quote_rotate |
                html_encode | unicode_escape. Default = bypass-oriented mix.
            max_variants: cap on variants sent (default 16).
            concurrency: in-flight count (default 4).
        """
        classes = mutation_classes or _DEFAULT_CLASSES
        baseline = await client.get(f"/api/proxy/{index}")
        if "error" in baseline:
            return f"Error fetching index {index}: {baseline['error']}"

        url = baseline.get("url") or ""
        method = (baseline.get("method") or "GET").upper()
        cur_value = ""
        body = baseline.get("request_body") or ""
        query = ""
        if "?" in url:
            _, query = url.split("?", 1)
        for chunk in (query.split("&") + body.split("&")):
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                if k == parameter:
                    cur_value = v
                    break
        seed_val = seed or cur_value or "praetor"
        variants = _mutate(seed_val, classes)[:max_variants]
        if not variants:
            return f"shadow_repeater: 0 variants generated for seed={seed_val!r}, classes={classes}"

        baseline_status = baseline.get("status_code", 0)
        baseline_len = len(baseline.get("response_body") or "")

        sem = asyncio.Semaphore(max(1, concurrency))
        results: list[dict[str, Any]] = [{} for _ in variants]

        async def _one(i: int, payload: str) -> None:
            async with sem:
                start = time.perf_counter()
                req = {
                    "url": url, "method": method,
                    "headers": baseline.get("request_headers", []),
                    "body": body, "follow_redirects": False,
                }
                if parameter in (query or ""):
                    new_q = "&".join(
                        f"{parameter}={payload}" if c.startswith(parameter + "=") else c
                        for c in query.split("&")
                    )
                    req["url"] = url.split("?", 1)[0] + "?" + new_q
                elif parameter in body:
                    req["body"] = "&".join(
                        f"{parameter}={payload}" if c.startswith(parameter + "=") else c
                        for c in body.split("&")
                    )
                else:
                    sep = "&" if "?" in url else "?"
                    req["url"] = f"{url}{sep}{parameter}={payload}"
                try:
                    resp = await client.post("/api/http/curl", json=req)
                except Exception as e:
                    results[i] = {"err": str(e)[:120], "payload": payload}
                    return
                elapsed = int((time.perf_counter() - start) * 1000)
                results[i] = {
                    "payload": payload,
                    "status": resp.get("status_code", 0),
                    "length": len(resp.get("response_body") or ""),
                    "elapsed_ms": elapsed,
                    "history_index": resp.get("history_index"),
                }

        await asyncio.gather(*[_one(i, v) for i, v in enumerate(variants)])

        anomalies = []
        for r in results:
            if r.get("err"):
                continue
            d_status = r["status"] != baseline_status
            d_len = abs(r["length"] - baseline_len) > 50
            d_time = r["elapsed_ms"] > 2000
            if d_status or d_len or d_time:
                anomalies.append(r)

        lines = [
            f"# shadow_repeater — index={index} param={parameter}",
            f"Seed: {seed_val!r}  | Variants: {len(variants)}  | Classes: {','.join(classes)}",
            f"Baseline: status={baseline_status} len={baseline_len}",
            "",
        ]
        if not anomalies:
            lines.append("No anomalies vs baseline (status/length/timing).")
            return "\n".join(lines)

        lines.append(f"Anomalies: {len(anomalies)}/{len(results)}")
        for r in anomalies[:25]:
            mark = []
            if r["status"] != baseline_status:
                mark.append(f"status {baseline_status}->{r['status']}")
            if abs(r["length"] - baseline_len) > 50:
                mark.append(f"len {baseline_len}->{r['length']}")
            if r["elapsed_ms"] > 2000:
                mark.append(f"timing={r['elapsed_ms']}ms")
            tag = " | ".join(mark)
            payload_clip = r["payload"][:60]
            hi = r.get("history_index")
            lines.append(f"  [{tag}]  payload={payload_clip!r}  history_index={hi}")
        lines.append("")
        lines.append("Next: send_to_repeater_tracked(history_index) on the strongest hit.")
        return "\n".join(lines)
