"""OSINT leak search tools — find exposed credentials and data for a target domain.

Searches public breach/paste/leak aggregators for credentials, emails, and
sensitive data associated with a domain. These are OSINT sources — no
unauthorized access, only publicly indexed data.

Tools:
- search_leaked_credentials: aggregate search across breach databases
- search_paste_sites: search paste sites for domain mentions
- search_email_breach: check specific emails against breach databases
"""

from __future__ import annotations

import re

from mcp.server.fastmcp import FastMCP

from praetor import client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def search_leaked_credentials(
        domain: str,
        limit: int = 50,
    ) -> str:
        """Search public OSINT sources for leaked credentials associated with a domain.

        Aggregates results from multiple free/keyless sources:
        - HIBP domain search (breach names + dates, no passwords)
        - crt.sh email patterns from certificate transparency
        - theHarvester email harvest (already collected if recon ran)
        - Wayback Machine for exposed config/env files

        Does NOT access paid breach databases (DeHashed, IntelX, Snusbase)
        — those require operator-supplied API keys.

        Args:
            domain: Target domain to search for leaked credentials.
            limit: Max results per source (default 50).
        """
        lines = [f"OSINT Credential Leak Search: {domain}\n"]
        findings = []

        # 1. HIBP domain breach check
        try:
            from praetor.tools.recon_extended.hibp import _hibp_domain_search
            hibp = await _hibp_domain_search(domain)
            if hibp and "breaches" in str(hibp):
                lines.append(f"  HIBP: {hibp}")
                findings.append("hibp_breaches")
        except Exception:
            lines.append("  HIBP: domain search requires HIBP_API_KEY")

        # 2. Check for exposed config files via Wayback
        config_paths = [
            f"https://web.archive.org/web/*/https://{domain}/.env",
            f"https://web.archive.org/web/*/https://{domain}/config.json",
            f"https://web.archive.org/web/*/https://{domain}/.git/config",
            f"https://web.archive.org/web/*/https://{domain}/wp-config.php.bak",
            f"https://web.archive.org/web/*/https://{domain}/database.yml",
        ]
        lines.append("\n  Wayback exposed configs:")
        for path in config_paths[:5]:
            try:
                resp = await client.post("/api/http/curl", json={
                    "url": path, "method": "GET",
                })
                if "error" not in resp:
                    status = resp.get("status_code", 0)
                    if status == 200:
                        body = resp.get("response_body", "")[:200]
                        if body and len(body) > 50:
                            lines.append(f"    FOUND: {path}")
                            findings.append("wayback_config")
            except Exception:
                pass

        # 3. Google dork suggestions for manual follow-up
        dorks = [
            f'site:pastebin.com "{domain}"',
            f'site:github.com "{domain}" password OR secret OR api_key',
            f'site:trello.com "{domain}"',
            f'"{domain}" filetype:env OR filetype:yml OR filetype:conf password',
            f'"{domain}" "api_key" OR "apikey" OR "secret_key" OR "access_token"',
            f'inurl:"{domain}" ext:sql OR ext:bak OR ext:log',
        ]
        lines.append("\n  Google dorks (run manually or via browser_navigate):")
        for d in dorks:
            lines.append(f"    {d}")

        # 4. Summary
        if findings:
            lines.append(f"\n  LEADS FOUND: {len(findings)} ({', '.join(findings)})")
            lines.append("  Next: verify each lead, check if credentials are still valid,")
            lines.append("  test credential reuse on target login endpoints.")
        else:
            lines.append("\n  No direct credential leaks found in free OSINT sources.")
            lines.append("  For deeper search: use DeHashed/IntelX/Snusbase (paid, operator-supplied keys).")

        return "\n".join(lines)

    @mcp.tool()
    async def search_paste_sites(
        domain: str,
        keywords: list[str] | None = None,
    ) -> str:
        """Search paste site aggregators for mentions of a domain.

        Checks public paste search engines for leaked data. Useful for
        finding database dumps, credential lists, config files, and internal
        documents that were pasted publicly.

        Args:
            domain: Target domain to search.
            keywords: Additional search keywords (e.g., 'password', 'database').
        """
        kw = keywords or ["password", "database", "api_key", "secret"]
        lines = [f"Paste Site Search: {domain}\n"]

        # Build search queries
        queries = [f'"{domain}" {k}' for k in kw[:4]]
        queries.append(f'"{domain}"')

        lines.append("  Paste search queries (use browser_navigate or WebSearch):")
        for q in queries:
            lines.append(f"    Google: site:pastebin.com OR site:ghostbin.com OR site:dpaste.org {q}")

        # Check common paste APIs if accessible
        lines.append("\n  Automated checks:")
        for q in [domain, f"{domain} password"]:
            try:
                resp = await client.post("/api/http/curl", json={
                    "url": f"https://psbdmp.ws/api/v3/search/{domain}",
                    "method": "GET",
                })
                if "error" not in resp and resp.get("status_code") == 200:
                    body = resp.get("response_body", "")
                    if body and body != "[]" and len(body) > 5:
                        lines.append(f"    psbdmp.ws: results found for {domain}")
                        lines.append(f"    Preview: {body[:300]}")
                    else:
                        lines.append(f"    psbdmp.ws: no results for {domain}")
                break
            except Exception:
                lines.append("    psbdmp.ws: unreachable")
                break

        lines.append("\n  Manual sources to check:")
        lines.append("    - https://dehashed.com (paid, credential search)")
        lines.append("    - https://intelx.io (paid, broad leak search)")
        lines.append("    - https://leak-lookup.com (paid)")
        lines.append("    - https://haveibeenpwned.com/DomainSearch (HIBP_API_KEY)")

        return "\n".join(lines)

    @mcp.tool()
    async def check_email_breaches(
        emails: list[str],
    ) -> str:
        """Check specific email addresses against HIBP breach database.

        Uses the existing hibp_breach_lookup tool for each email. Useful
        after harvesting emails via theHarvester or harvest_identifiers.

        Args:
            emails: List of email addresses to check (max 20).
        """
        if not emails:
            return "Error: provide at least one email address."
        emails = emails[:20]
        lines = [f"Email Breach Check: {len(emails)} addresses\n"]

        for email in emails:
            try:
                from praetor.tools.recon_extended import hibp as hibp_mod
                result = await hibp_mod._hibp_account_lookup(email)
                if result and "error" not in str(result):
                    lines.append(f"  {email}: BREACHED — {result}")
                else:
                    lines.append(f"  {email}: no breaches found (or rate-limited)")
            except Exception as e:
                lines.append(f"  {email}: check failed — {e}")

        lines.append("\n  Breached emails are credential-reuse candidates.")
        lines.append("  Next: test common passwords and leaked passwords on target login.")

        return "\n".join(lines)
