"""Shodan CVEDB lookups — free, no API key, ~200ms."""

import httpx

from ._common import _BROWSER_UA


_SHODAN_CVE_URL = "https://cvedb.shodan.io/cve/{cve_id}"
_SHODAN_CVES_URL = "https://cvedb.shodan.io/cves"
_SHODAN_CPES_URL = "https://cvedb.shodan.io/cpes"
# Back-compat alias for the prior single-URL constant.
_SHODAN_CPE_URL = _SHODAN_CVES_URL


async def _shodan_cve_lookup(cve_id: str) -> dict | str:
    """Look up a single CVE on Shodan CVEDB (free, no key, ~200ms).

    Returns a dict with id, cvss, epss, kev, ransomware_campaign,
    propose_action, summary, references, published — richer than NVD because
    EPSS + KEV are baked in. Returns an error string on failure.
    """
    cve = cve_id.upper().strip()
    if not cve.startswith("CVE-"):
        return f"not a CVE id: {cve_id}"
    try:
        async with httpx.AsyncClient(
            timeout=10,
            headers={"User-Agent": _BROWSER_UA},
        ) as http:
            resp = await http.get(_SHODAN_CVE_URL.format(cve_id=cve))
        if resp.status_code == 404:
            return f"not found in Shodan CVEDB: {cve}"
        if resp.status_code != 200:
            return f"HTTP {resp.status_code}"
        data = resp.json()
    except httpx.TimeoutException:
        return "timed out after 10s"
    except Exception as e:  # noqa: BLE001
        return str(e)[:150]

    return {
        "id": data.get("cve_id", cve),
        "summary": data.get("summary", ""),
        "cvss": data.get("cvss"),
        "cvss_version": data.get("cvss_version"),
        "epss": data.get("epss"),  # 0–1 probability of exploitation
        "kev": bool(data.get("kev")),  # CISA Known Exploited
        "ransomware_campaign": data.get("ransomware_campaign"),
        "propose_action": data.get("propose_action", ""),
        "references": data.get("references", [])[:10],
        "published": data.get("published_time", ""),
    }


async def _shodan_cves_query(params: dict, limit: int = 20) -> list[dict] | str:
    """Generic /cves query — accepts cpe23, product, is_kev, sort_by_epss,
    start_date, end_date. Returns a normalized list of CVE dicts.
    """
    try:
        async with httpx.AsyncClient(
            timeout=15,
            headers={"User-Agent": _BROWSER_UA},
        ) as http:
            resp = await http.get(_SHODAN_CVES_URL, params=params)
        if resp.status_code != 200:
            return f"HTTP {resp.status_code}"
        data = resp.json()
    except httpx.TimeoutException:
        return "timed out after 15s"
    except Exception as e:  # noqa: BLE001
        return str(e)[:150]

    cves = data.get("cves", []) or []
    out: list[dict] = []
    for c in cves[:limit]:
        out.append({
            "id": c.get("cve_id", "?"),
            "cvss": c.get("cvss"),
            "epss": c.get("epss"),
            "kev": bool(c.get("kev")),
            "ransomware_campaign": c.get("ransomware_campaign"),
            "summary": (c.get("summary") or "")[:240],
            "published": c.get("published_time", ""),
            "vendor": c.get("vendor"),
            "product": c.get("product"),
        })
    return out


async def _shodan_cpe_lookup(cpe23: str, limit: int = 20) -> list[dict] | str:
    """List CVEs for a CPE 2.3 string. Thin wrapper over _shodan_cves_query."""
    if not cpe23.startswith("cpe:2.3:"):
        return f"not a CPE 2.3 string: {cpe23}"
    return await _shodan_cves_query({"cpe23": cpe23}, limit=limit)


async def _shodan_cpe_dict(product: str, limit: int = 40) -> list[str] | str:
    """Resolve a product name to its CPE 2.3 strings via /cpes?product=X.

    Useful when the operator has 'macos' / 'php' / 'libpng' from tech-stack
    detection but needs the formal CPE for cpe23-based filtering.
    """
    if not product.strip():
        return "empty product"
    try:
        async with httpx.AsyncClient(
            timeout=15,
            headers={"User-Agent": _BROWSER_UA},
        ) as http:
            resp = await http.get(_SHODAN_CPES_URL, params={"product": product.strip()})
        if resp.status_code != 200:
            return f"HTTP {resp.status_code}"
        data = resp.json()
    except httpx.TimeoutException:
        return "timed out after 15s"
    except Exception as e:  # noqa: BLE001
        return str(e)[:150]

    cpes = data.get("cpes", []) or []
    return cpes[:limit]
