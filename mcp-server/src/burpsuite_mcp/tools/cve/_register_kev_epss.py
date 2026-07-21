"""Batch CISA-KEV + FIRST-EPSS enrichment — kev_epss_enrich."""

from mcp.server.fastmcp import FastMCP

from .shodan import _shodan_cve_lookup


# Curated CVE -> threat-actor / campaign attribution (Sec-Gemini-style grounding
# for business-impact framing, Rule 16a). No free actor-attribution API exists,
# so this is a hand-verified map of well-documented public attributions — heavy
# on internet-facing appliance CVEs where "who exploits this" is on record.
# Absent a match, the tool degrades to the KEV / ransomware flags. Keep entries
# factual and sourced to public reporting; do not speculate.
_ACTOR_MAP = {
    "CVE-2021-44228": "Log4Shell — mass-exploited by state actors + ransomware (Conti, Lazarus, Iranian/Chinese groups)",
    "CVE-2019-19781": "Citrix ADC — APT41 + ransomware crews (Ragnarok, REvil)",
    "CVE-2023-4966": "Citrix Bleed — LockBit, Medusa, Qilin ransomware; broad criminal use",
    "CVE-2020-5902": "F5 BIG-IP TMUI — Iranian state + commodity botnets, days after disclosure",
    "CVE-2023-46805": "Ivanti Connect Secure — UNC5221 (China-nexus espionage)",
    "CVE-2024-21887": "Ivanti Connect Secure — UNC5221 (China-nexus espionage)",
    "CVE-2025-0282": "Ivanti Connect Secure — China-nexus espionage (UNC5337/UNC5221 cluster)",
    "CVE-2024-3400": "PAN-OS GlobalProtect — UTA0218 (Operation MidnightEclipse)",
    "CVE-2023-34362": "MOVEit Transfer — Cl0p mass data-theft extortion campaign",
    "CVE-2024-5806": "MOVEit Transfer — exploited within hours of disclosure",
    "CVE-2021-26855": "Exchange ProxyLogon — HAFNIUM (China-nexus) + follow-on ransomware",
    "CVE-2021-34473": "Exchange ProxyShell — multiple ransomware crews (Conti, LockFile, BlackByte)",
    "CVE-2023-22515": "Confluence — China-nexus state actors + Cerber ransomware",
    "CVE-2023-22527": "Confluence — mass crypto-mining + espionage exploitation",
    "CVE-2024-27198": "TeamCity — APT29 (Cozy Bear) + Lazarus (DPRK)",
    "CVE-2024-53704": "SonicWall SSLVPN — Akira/Fog ransomware affiliates",
    "CVE-2025-31161": "CrushFTP — exploited in the wild shortly after disclosure",
    "CVE-2024-36401": "GeoServer — mass botnet + cryptomining exploitation (KEV-listed)",
}


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
                    "actor": _ACTOR_MAP.get(cid),
                    "summary": (r.get("summary") or "")[:120],
                })
            else:
                rows.append({"id": cid, "cvss": None, "epss": None,
                             "kev": False, "ransomware": False,
                             "actor": _ACTOR_MAP.get(cid),
                             "summary": f"lookup failed: {r}"})

        def _key(r):
            return (0 if r["kev"] else 1,
                    -(r["epss"] or 0.0),
                    -(r["cvss"] or 0.0))
        rows.sort(key=_key)

        kev_n = sum(1 for r in rows if r["kev"])
        rans_n = sum(1 for r in rows if r["ransomware"])
        actor_n = sum(1 for r in rows if r["actor"])
        high_epss = sum(1 for r in rows
                        if isinstance(r["epss"], (int, float)) and r["epss"] >= 0.5)
        lines = [
            f"kev_epss_enrich: {len(rows)} CVEs  "
            f"(KEV={kev_n}, ransomware={rans_n}, actor-attributed={actor_n}, EPSS>=50%={high_epss})",
        ]
        for r in rows:
            kev = " [KEV]" if r["kev"] else ""
            rans = " [RANSOMWARE]" if r["ransomware"] else ""
            epss = (f"{r['epss'] * 100:5.2f}%"
                    if isinstance(r["epss"], (int, float)) else "  ?  ")
            cvss = r["cvss"] if r["cvss"] is not None else "?"
            lines.append(f"  {r['id']:<16}  CVSS {str(cvss):<5}  EPSS {epss}{kev}{rans}")
            if r["actor"]:
                lines.append(f"      ACTOR: {r['actor']}")
            if r["summary"]:
                lines.append(f"      {r['summary']}")
        return "\n".join(lines)
