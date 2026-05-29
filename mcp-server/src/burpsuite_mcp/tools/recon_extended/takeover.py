"""test_subdomain_takeover — dangling-CNAME + body-fingerprint match."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._common import _dig
from .fingerprints import TAKEOVER_FINGERPRINTS


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def test_subdomain_takeover(subdomains: list[str]) -> str:
        """Check subdomains for potential takeover via dangling CNAME records.

        Args:
            subdomains: List of subdomains to check
        """
        if not subdomains:
            return "Error: provide at least one subdomain to check"

        if len(subdomains) > 100:
            return "Error: max 100 subdomains per check to avoid abuse"

        results: list[dict] = []
        vulnerable: list[dict] = []

        for subdomain in subdomains:
            subdomain = subdomain.strip().lower()
            if not subdomain:
                continue

            cname = await _dig(subdomain, "CNAME")
            if not cname:
                results.append({"subdomain": subdomain, "status": "no_cname"})
                continue

            cname = cname.split("\n")[0].strip().rstrip(".")

            matched_service = None
            for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
                if fingerprint["cname"] in cname:
                    matched_service = service
                    break

            if not matched_service:
                results.append({"subdomain": subdomain, "cname": cname, "status": "not_vulnerable_service"})
                continue

            fingerprint = TAKEOVER_FINGERPRINTS[matched_service]
            body_match = False
            http_error = None
            dns_only = bool(fingerprint.get("dns_only", False))

            # DNS-only signal: the takeover marker is "CNAME resolves but the
            # target hostname does not have an A record". Confirmed via second
            # `dig A` on the CNAME target. HTTP body is not consulted.
            if dns_only:
                a_record = await _dig(cname, "A")
                if not a_record or not a_record.strip():
                    entry = {
                        "subdomain": subdomain,
                        "cname": cname,
                        "service": matched_service,
                        "status": "VULNERABLE (dns-only — CNAME target has no A record)",
                        "dns_only": True,
                    }
                    vulnerable.append(entry)
                    results.append(entry)
                    continue
                else:
                    results.append({
                        "subdomain": subdomain, "cname": cname,
                        "service": matched_service,
                        "status": "cname_match_but_resolves",
                        "dns_only": True,
                    })
                    continue

            try:
                data = await client.post("/api/http/curl", json={
                    "url": f"https://{subdomain}",
                    "method": "GET",
                })
                if "error" not in data:
                    body = data.get("response_body", "")
                    body_match = fingerprint["body"].lower() in body.lower()
                else:
                    http_error = data["error"][:100]
            except Exception as e:
                http_error = str(e)[:100]

            entry = {
                "subdomain": subdomain,
                "cname": cname,
                "service": matched_service,
                "body_match": body_match,
                "http_error": http_error,
            }

            if body_match:
                entry["status"] = "VULNERABLE"
                vulnerable.append(entry)
            elif http_error:
                entry["status"] = "possible (HTTP failed)"
                vulnerable.append(entry)
            else:
                entry["status"] = "cname_match_but_active"

            results.append(entry)

        lines = [f"Subdomain takeover check ({len(subdomains)} checked):", ""]

        if vulnerable:
            lines.append(f"  POTENTIALLY VULNERABLE ({len(vulnerable)}):")
            for v in vulnerable:
                status = v["status"]
                lines.append(f"    [{status}] {v['subdomain']}")
                lines.append(f"      CNAME: {v['cname']} ({v['service']})")
                if v.get("http_error"):
                    lines.append(f"      HTTP error: {v['http_error']}")
            lines.append("")

        safe_count = len(results) - len(vulnerable)
        no_cname = sum(1 for r in results if r.get("status") == "no_cname")
        lines.append(f"  Summary: {len(vulnerable)} potentially vulnerable, {safe_count} safe, {no_cname} no CNAME")

        return "\n".join(lines)
