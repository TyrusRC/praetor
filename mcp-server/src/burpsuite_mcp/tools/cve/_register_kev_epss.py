"""Batch CISA-KEV + FIRST-EPSS enrichment — kev_epss_enrich."""

from mcp.server.fastmcp import FastMCP

from .shodan import _shodan_cve_lookup


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def kev_epss_enrich(cve_ids: list[str], max_lookups: int = 50) -> str:
        """Enrich a list of CVE IDs with CISA KEV + FIRST EPSS scores.

        Sorts by exploitation likelihood: KEV first, then descending EPSS.
        Backed by Shodan CVEDB (KEV + EPSS pre-merged, free, no key).

        Args:
            cve_ids: list of CVE IDs (e.g. ["CVE-2024-3094", "CVE-2024-4577"]).
            max_lookups: cap concurrent lookups to avoid rate-limits.
        """
        import asyncio
        ids = sorted({c.strip().upper() for c in cve_ids if c.strip()})[:max_lookups]
        if not ids:
            return "kev_epss_enrich: no CVE IDs provided."
        results = await asyncio.gather(
            *[_shodan_cve_lookup(c) for c in ids], return_exceptions=False,
        )
        rows: list[dict] = []
        for cid, r in zip(ids, results):
            if isinstance(r, dict):
                rows.append({
                    "id": cid,
                    "cvss": r.get("cvss"),
                    "epss": r.get("epss"),
                    "kev": bool(r.get("kev")),
                    "ransomware": bool(r.get("ransomware_campaign")),
                    "summary": (r.get("summary") or "")[:120],
                })
            else:
                rows.append({"id": cid, "cvss": None, "epss": None,
                             "kev": False, "ransomware": False,
                             "summary": f"lookup failed: {r}"})

        def _key(r):
            return (0 if r["kev"] else 1,
                    -(r["epss"] or 0.0),
                    -(r["cvss"] or 0.0))
        rows.sort(key=_key)

        kev_n = sum(1 for r in rows if r["kev"])
        rans_n = sum(1 for r in rows if r["ransomware"])
        high_epss = sum(1 for r in rows
                        if isinstance(r["epss"], (int, float)) and r["epss"] >= 0.5)
        lines = [
            f"kev_epss_enrich: {len(rows)} CVEs  "
            f"(KEV={kev_n}, ransomware={rans_n}, EPSS>=50%={high_epss})",
        ]
        for r in rows:
            kev = " [KEV]" if r["kev"] else ""
            rans = " [RANSOMWARE]" if r["ransomware"] else ""
            epss = (f"{r['epss'] * 100:5.2f}%"
                    if isinstance(r["epss"], (int, float)) else "  ?  ")
            cvss = r["cvss"] if r["cvss"] is not None else "?"
            lines.append(f"  {r['id']:<16}  CVSS {str(cvss):<5}  EPSS {epss}{kev}{rans}")
            if r["summary"]:
                lines.append(f"      {r['summary']}")
        return "\n".join(lines)
