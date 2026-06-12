"""Batch extract_* tools — dedup across N proxy entries in one call.

Replaces the chatty per-index loop:
    for idx in indices:
        extract_js_secrets(idx)        # N calls, N response dumps
with one synthesis call that dedups by canonical key and reports sources.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_BATCH_HARD_CAP = 30


def _normalize_indices(indices: list[int]) -> tuple[list[int], str | None]:
    if not indices:
        return [], "indices required"
    seen = set()
    out: list[int] = []
    for i in indices:
        if isinstance(i, int) and i not in seen:
            seen.add(i)
            out.append(i)
            if len(out) >= _BATCH_HARD_CAP:
                break
    return out, None


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def extract_js_secrets_batch(indices: list[int]) -> dict:
        """Extract secrets across N proxy entries, dedup by (type, match[:40]).

        Args:
            indices: list of proxy history indices (cap 30 per call).
        """
        idxs, err = _normalize_indices(indices)
        if err:
            return {"error": err}

        dedup: dict[tuple[str, str], dict] = {}
        per_index_errors: dict[int, str] = {}

        for idx in idxs:
            data = await client.post("/api/analysis/js-secrets", json={"index": idx})
            if "error" in data:
                per_index_errors[idx] = data["error"]
                continue
            for s in data.get("secrets", []):
                stype = s.get("type", "Unknown")
                match = (s.get("match") or "")[:40]
                key = (stype, match)
                if key not in dedup:
                    dedup[key] = {
                        "type": stype,
                        "match": s.get("match", "")[:80],
                        "severity": s.get("severity", "?"),
                        "context": s.get("context", "")[:160],
                        "sources": [],
                    }
                dedup[key]["sources"].append(idx)

        secrets = sorted(dedup.values(), key=lambda x: (-len(x["sources"]), x["type"]))
        return {
            "indices_processed": len(idxs),
            "total_unique": len(secrets),
            "secrets": secrets,
            "errors": per_index_errors,
        }

    @mcp.tool()
    async def extract_api_endpoints_batch(indices: list[int]) -> dict:
        """Extract API endpoints / fetch calls / links across N proxy entries, dedup by URL.

        Args:
            indices: list of proxy history indices (cap 30 per call).
        """
        idxs, err = _normalize_indices(indices)
        if err:
            return {"error": err}

        buckets: dict[str, dict[str, dict]] = {
            "api_endpoints": {},
            "js_endpoints": {},
            "links": {},
            "external_urls": {},
        }
        per_index_errors: dict[int, str] = {}

        for idx in idxs:
            data = await client.post("/api/analysis/endpoints", json={"index": idx})
            if "error" in data:
                per_index_errors[idx] = data["error"]
                continue
            for key in buckets:
                for item in data.get(key, []):
                    url = item if isinstance(item, str) else (item.get("url") or "")
                    if not url:
                        continue
                    entry = buckets[key].setdefault(url, {"url": url, "sources": []})
                    entry["sources"].append(idx)

        return {
            "indices_processed": len(idxs),
            "totals": {k: len(v) for k, v in buckets.items()},
            "api_endpoints": sorted(buckets["api_endpoints"].values(), key=lambda x: -len(x["sources"])),
            "js_endpoints": sorted(buckets["js_endpoints"].values(), key=lambda x: -len(x["sources"])),
            "links": sorted(buckets["links"].values(), key=lambda x: -len(x["sources"])),
            "external_urls": sorted(buckets["external_urls"].values(), key=lambda x: -len(x["sources"])),
            "errors": per_index_errors,
        }

    @mcp.tool()
    async def extract_links_batch(
        indices: list[int],
        link_filter: str = "all",
    ) -> dict:
        """Extract links across N proxy entries, dedup by URL.

        Args:
            indices: list of proxy history indices (cap 30 per call).
            link_filter: 'all', 'internal', or 'external'.
        """
        idxs, err = _normalize_indices(indices)
        if err:
            return {"error": err}

        dedup: dict[str, dict] = {}
        per_index_errors: dict[int, str] = {}

        for idx in idxs:
            data = await client.post("/api/extract-text/links", json={
                "index": idx, "filter": link_filter,
            })
            if "error" in data:
                per_index_errors[idx] = data["error"]
                continue
            for link in data.get("links", []):
                url = link.get("url") or ""
                if not url:
                    continue
                entry = dedup.setdefault(url, {
                    "url": url,
                    "type": link.get("type", "other"),
                    "internal": bool(link.get("internal")),
                    "sources": [],
                })
                entry["sources"].append(idx)

        links = sorted(dedup.values(), key=lambda x: (-len(x["sources"]), x["url"]))
        return {
            "indices_processed": len(idxs),
            "filter": link_filter,
            "total_unique": len(links),
            "links": links,
            "errors": per_index_errors,
        }
