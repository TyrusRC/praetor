"""opengrep over JS/HTML bodies already captured in Burp proxy history.

This is the static counterpart to analyze_dom (dynamic). It runs opengrep
(Semgrep fork, MIT, no telemetry) against response bodies pulled from the
proxy. Findings include the originating logger_index + URL so the operator
can pivot back to the live request that delivered the vulnerable JS.

Bundled rulesets:
    bsk/dom-clobbering.yml      (rulesets/dom_clobbering.yml)
    bsk/prototype-pollution.yml (rulesets/prototype_pollution.yml)
    bsk/postmessage.yml         (rulesets/postmessage.yml)

Operator can pass additional remote rulesets via the `extra_configs` arg
(e.g. 'p/javascript', 'p/xss', 'p/secrets' — names resolve in the opengrep
registry).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


_RULESET_DIR = Path(__file__).resolve().parent / "rulesets"
_BUNDLED = ("dom_clobbering.yml", "prototype_pollution.yml", "postmessage.yml")
_MAX_BODY_BYTES = 256 * 1024  # 256KB per artefact — JS bundles can dwarf the bigger ones
_DEFAULT_MIMES = (
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "text/html",
    "application/json",
)


async def _proxy_bodies(domain: str, mimes: tuple[str, ...], max_bodies: int) -> list[dict]:
    """Pull recent proxy history entries with matching MIME types and bodies."""
    params: dict[str, str] = {"limit": str(max_bodies * 4)}
    if domain:
        params["host"] = domain
    history = await client.get("/api/proxy/history", params=params)
    if "error" in history:
        return []

    out: list[dict] = []
    seen_hashes: set[str] = set()
    entries = history.get("entries", history.get("history", []) or [])

    for entry in entries:
        if len(out) >= max_bodies:
            break

        idx = entry.get("index", entry.get("id", -1))
        if idx is None or int(idx) < 0:
            continue

        mime = (entry.get("mime_type") or entry.get("content_type") or "").lower()
        if not any(m in mime for m in mimes):
            # Fall back — fetch the body anyway if URL ends in .js / .html
            url = (entry.get("url") or "").lower()
            if not any(url.endswith(ext) for ext in (".js", ".mjs", ".html", ".htm", ".jsx", ".tsx")):
                continue

        detail = await client.get(
            f"/api/proxy/{int(idx)}", params={"include_body": "true"}
        )
        if "error" in detail:
            continue
        body = detail.get("response_body") or ""
        if not body or len(body) < 256:
            continue
        if len(body) > _MAX_BODY_BYTES:
            body = body[:_MAX_BODY_BYTES]

        body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
        if body_hash in seen_hashes:
            continue
        seen_hashes.add(body_hash)

        out.append(
            {
                "logger_index": int(idx),
                "url": detail.get("url") or entry.get("url") or "",
                "mime": mime or "?",
                "body": body,
                "body_hash": body_hash,
            }
        )
    return out


def _ext_for_mime(mime: str, url: str) -> str:
    if "html" in mime or url.endswith((".html", ".htm")):
        return ".html"
    if "json" in mime:
        return ".json"
    return ".js"


def _resolve_configs(rulesets: list[str], extra_configs: list[str]) -> list[str]:
    """Map operator-friendly names to opengrep --config args."""
    args: list[str] = []
    for name in rulesets:
        if name == "dom-clobbering" or name == "dom":
            args += ["--config", str(_RULESET_DIR / "dom_clobbering.yml")]
        elif name in {"prototype-pollution", "proto-pollution"}:
            args += ["--config", str(_RULESET_DIR / "prototype_pollution.yml")]
        elif name == "postmessage":
            args += ["--config", str(_RULESET_DIR / "postmessage.yml")]
        elif name in {"xss", "p/xss"}:
            args += ["--config", "p/xss"]
        elif name in {"secrets", "p/secrets"}:
            args += ["--config", "p/secrets"]
        elif name in {"javascript", "p/javascript"}:
            args += ["--config", "p/javascript"]
        elif name == "all":
            for fn in _BUNDLED:
                args += ["--config", str(_RULESET_DIR / fn)]
        else:
            # Pass through anything else as-is (registry name or path)
            args += ["--config", name]
    for c in extra_configs:
        args += ["--config", c]
    return args


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def audit_crawled_artifacts(
        domain: str = "",
        rulesets: list[str] | None = None,
        extra_configs: list[str] | None = None,
        max_bodies: int = 200,
        timeout: int = 180,
    ) -> str:
        """Run opengrep over JS/HTML bodies captured in Burp proxy history.

        Static counterpart to analyze_dom. Each finding links back to a
        logger_index so the operator can replay the request that delivered
        the vulnerable artefact.

        Args:
            domain: Optional host filter (e.g. 'example.com'). Empty = all hosts.
            rulesets: Bundled / shorthand ruleset names. Default: all bundled.
                Recognized: dom-clobbering, prototype-pollution, postmessage,
                xss, secrets, javascript, all.
            extra_configs: Additional opengrep --config values (registry names
                or local paths) passed verbatim.
            max_bodies: Cap on number of bodies scanned (after dedupe).
            timeout: Max seconds for the opengrep run.
        """
        if not _check_tool("opengrep") and not _check_tool("semgrep"):
            return (
                "Error: opengrep (or semgrep fallback) not installed.\n"
                "Install: https://github.com/opengrep/opengrep#installation"
            )
        tool = "opengrep" if _check_tool("opengrep") else "semgrep"

        rulesets = rulesets or ["all"]
        extra_configs = extra_configs or []

        bodies = await _proxy_bodies(domain, _DEFAULT_MIMES, max_bodies)
        if not bodies:
            return (
                f"audit_crawled_artifacts: no JS/HTML bodies in proxy history "
                f"for {domain or 'any host'} (need browser_crawl first)."
            )

        with tempfile.TemporaryDirectory(prefix="praetor-audit-") as tmpdir:
            tmp = Path(tmpdir)
            for body in bodies:
                fname = body["body_hash"] + _ext_for_mime(body["mime"], body["url"])
                (tmp / fname).write_text(body["body"], encoding="utf-8", errors="replace")
                (tmp / (fname + ".meta.json")).write_text(
                    json.dumps(
                        {
                            "logger_index": body["logger_index"],
                            "url": body["url"],
                            "mime": body["mime"],
                        }
                    ),
                    encoding="utf-8",
                )

            cmd = [tool, "scan"] + _resolve_configs(rulesets, extra_configs) + [
                "--json",
                "--metrics", "off",
                "--no-rewrite-rule-ids",
                str(tmp),
            ]
            stdout, stderr, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
            try:
                report = json.loads(stdout or "{}")
            except json.JSONDecodeError:
                return f"opengrep output not parseable JSON (rc={rc}):\n{stderr[:500]}"

            results = report.get("results") or []
            if not results:
                return (
                    f"audit_crawled_artifacts: 0 findings across "
                    f"{len(bodies)} artefacts."
                )

            # Map file path -> meta sidecar (URL + logger_index)
            findings: list[dict] = []
            for r in results:
                src = Path(r.get("path") or "")
                meta_p = src.parent / (src.name + ".meta.json")
                meta = {}
                try:
                    meta = json.loads(meta_p.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    pass
                findings.append(
                    {
                        "rule": r.get("check_id"),
                        "severity": (r.get("extra") or {}).get("severity"),
                        "line": (r.get("start") or {}).get("line"),
                        "snippet": ((r.get("extra") or {}).get("lines") or "")[:160],
                        "logger_index": meta.get("logger_index"),
                        "url": meta.get("url"),
                    }
                )

        # Bucket findings by rule for an at-a-glance summary
        by_rule: dict[str, int] = {}
        for f in findings:
            by_rule[f["rule"] or "?"] = by_rule.get(f["rule"] or "?", 0) + 1

        lines = [
            f"audit_crawled_artifacts: {len(findings)} findings across "
            f"{len(bodies)} artefacts via {tool}",
            "",
            "By rule:",
        ]
        for rid, count in sorted(by_rule.items(), key=lambda kv: -kv[1])[:25]:
            lines.append(f"  {count}x {rid}")
        lines.append("")
        lines.append("Sample (first 15):")
        for f in findings[:15]:
            lines.append(
                f"  [{f['severity'] or '?'}] {f['rule']}  logger_index={f['logger_index']}  "
                f"{f['url']} :{f['line']}\n    {f['snippet'][:120]}"
            )
        return "\n".join(lines)
