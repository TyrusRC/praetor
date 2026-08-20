"""Shodan CVEDB direct lookups — lookup_cve, lookup_cpe."""

from mcp.server.fastmcp import FastMCP

from .shodan import _shodan_cve_lookup, _shodan_cves_query, _shodan_cpe_dict


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def lookup_cve(
        cve_id: str = "",
        cpe23: str = "",
        product: str = "",
        is_kev: bool = False,
        sort_by_epss: bool = False,
        start_date: str = "",
        end_date: str = "",
        max_results: int = 20,
    ) -> str:
        """Fast CVE intel via Shodan CVEDB (free, no API key, ~200ms).

        Output always includes EPSS exploitability % and CISA-KEV status — both
        absent from NVD. Pick ONE primary filter and combine with the boolean
        flags / date range:

        Args:
            cve_id: e.g. 'CVE-2021-44228'. Single rich lookup.
            cpe23:  e.g. 'cpe:2.3:a:libpng:libpng:0.8'. List CVEs for a CPE.
            product: e.g. 'php' / 'macos' / 'wordpress'. List CVEs by product
                name (no CPE needed). Use lookup_cpe(product) first if you
                want the formal CPE.
            is_kev: True -> restrict to CISA Known-Exploited Vulnerabilities.
                Combine with product/cpe23 to find KEVs in YOUR stack.
            sort_by_epss: True -> sort highest-EPSS first. Combine with
                product/cpe23 to triage which CVE in a tech to patch first.
            start_date: ISO date 'YYYY-MM-DD' lower bound (published).
            end_date:   ISO date 'YYYY-MM-DD' upper bound (published).
            max_results: Cap for list responses (default 20, max 100).

        With NO filters: returns the newest CVEs (Shodan feed).
        """
        if cve_id and (cpe23 or product):
            return "Pass cve_id alone, or use cpe23/product for list mode."
        if cpe23 and product:
            return "Pass either cpe23 OR product, not both."

        if cve_id:
            res = await _shodan_cve_lookup(cve_id)
            if isinstance(res, str):
                return f"Shodan CVEDB: {res}"
            lines = [f"{res['id']}  CVSS {res.get('cvss', '?')}  (v{res.get('cvss_version', '?')})"]
            epss = res.get("epss")
            if isinstance(epss, (int, float)):
                lines.append(f"EPSS: {epss * 100:.2f}% likelihood of exploitation in next 30d")
            flags = []
            if res.get("kev"):
                flags.append("CISA-KEV (Known Exploited)")
            if res.get("ransomware_campaign"):
                flags.append(f"Ransomware: {res['ransomware_campaign']}")
            if flags:
                lines.append("Flags: " + " | ".join(flags))
            if res.get("published"):
                lines.append(f"Published: {res['published'][:10]}")
            if res.get("propose_action"):
                lines.append(f"Action: {res['propose_action']}")
            summary = (res.get("summary") or "").replace("\n", " ").strip()
            if summary:
                lines.append("")
                lines.append(summary[:600])
            refs = res.get("references") or []
            if refs:
                lines.append("")
                lines.append(f"References ({len(refs)} total, top 3):")
                for r in refs[:3]:
                    lines.append(f"  {r}")
            return "\n".join(lines)

        params: dict[str, str] = {}
        if cpe23:
            if not cpe23.startswith("cpe:2.3:"):
                return f"Not a CPE 2.3 string: {cpe23}"
            params["cpe23"] = cpe23
        if product:
            params["product"] = product.strip()
        if is_kev:
            params["is_kev"] = "true"
        if sort_by_epss:
            params["sort_by_epss"] = "true"
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date

        limit = max(1, min(max_results, 100))
        res = await _shodan_cves_query(params, limit=limit)
        if isinstance(res, str):
            return f"Shodan CVEDB: {res}"
        if not res:
            scope = params or {"feed": "newest"}
            return f"No CVEs returned for {scope}"

        scope_bits = []
        if cpe23:
            scope_bits.append(f"cpe23={cpe23}")
        if product:
            scope_bits.append(f"product={product}")
        if is_kev:
            scope_bits.append("KEV-only")
        if sort_by_epss:
            scope_bits.append("sorted by EPSS desc")
        if start_date or end_date:
            scope_bits.append(f"date {start_date or '*'}..{end_date or '*'}")
        scope = " | ".join(scope_bits) if scope_bits else "newest"
        lines = [f"Shodan CVEDB ({scope}) — {len(res)} CVEs:"]
        for c in res:
            epss = c.get("epss")
            epss_str = f"  EPSS {epss * 100:5.2f}%" if isinstance(epss, (int, float)) else ""
            kev = " [KEV]" if c.get("kev") else ""
            ransom = " [RANSOM]" if c.get("ransomware_campaign") else ""
            cvss = c.get("cvss") if c.get("cvss") is not None else "?"
            pub = (c.get("published") or "")[:10]
            pub_str = f"  {pub}" if pub else ""
            lines.append(f"  {c['id']}{pub_str}  CVSS {cvss}{epss_str}{kev}{ransom}")
            summary = (c.get("summary") or "").replace("\n", " ").strip()
            if summary:
                lines.append(f"    {summary[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def lookup_cpe(
        product: str,
        max_results: int = 40,
    ) -> str:
        """Resolve a product name to its CPE 2.3 strings via Shodan CVEDB.

        Useful when tech-stack detection gives you 'macos' / 'libpng' / 'php'
        but you need the formal `cpe:2.3:o:apple:macos:14.5` to pivot into a
        `lookup_cve(cpe23=...)` call. Free, no key.

        Args:
            product: Product slug (e.g. 'macos', 'php', 'libpng', 'wordpress')
            max_results: Cap on returned CPEs (default 40, max 200)
        """
        limit = max(1, min(max_results, 200))
        res = await _shodan_cpe_dict(product, limit=limit)
        if isinstance(res, str):
            return f"Shodan CVEDB: {res}"
        if not res:
            return f"No CPEs returned for product={product}"
        lines = [f"Shodan CVEDB CPEs for product={product} ({len(res)}):"]
        for cpe in res:
            lines.append(f"  {cpe}")
        return "\n".join(lines)
