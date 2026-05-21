"""NVD 2.0 REST API lookup — reference intel, direct fetch (not via Burp)."""

import httpx

from ._common import _BROWSER_UA


_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def _nvd_lookup(query: str, max_results: int) -> list[dict] | str:
    """Query NVD 2.0 API. Returns a list of CVE dicts or an error string.

    Direct call — NVD is a reference/intel database, not the target. Keeping
    it out of Burp proxy history avoids polluting the hunt audit trail.
    """
    params: dict[str, str | int]
    if query.upper().startswith("CVE-"):
        params = {"cveId": query.upper()}
    else:
        params = {"keywordSearch": query, "resultsPerPage": max_results}

    try:
        async with httpx.AsyncClient(
            timeout=20,
            headers={"User-Agent": _BROWSER_UA},
        ) as http:
            resp = await http.get(_NVD_API_URL, params=params)
        if resp.status_code == 403:
            return "NVD returned 403 (rate-limited). Try again in a minute or set live_lookup=False."
        if resp.status_code != 200:
            return f"HTTP {resp.status_code}"
        data = resp.json()
    except httpx.TimeoutException:
        return "timed out after 20s"
    except Exception as e:  # noqa: BLE001 - surface any network/parse issue
        return str(e)[:150]

    vulns = data.get("vulnerabilities", [])
    results: list[dict] = []
    for item in vulns[:max_results]:
        cve = item.get("cve", {})
        desc_list = cve.get("descriptions", [])
        summary = next((d.get("value", "") for d in desc_list if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                break
        results.append({
            "id": cve.get("id", "?"),
            "published": cve.get("published", ""),
            "summary": summary,
            "cvss_score": score,
        })
    return results
