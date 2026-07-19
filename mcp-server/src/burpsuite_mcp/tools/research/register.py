"""research_attack_vector tool registration.

Owns the @mcp.tool decorator; pulls KB / methodology constants from
_common and URL builders from the per-backend submodules.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ._common import _METHODOLOGY_LINKS, _VECTOR_KB
from .attackerkb import _attackerkb_search
from .exploitdb import _exploitdb_search
from .github_advisory import _github_advisory_search
from .github_code import _github_code_search
from .osv import _osv_search
from .snyk import _snyk_db_search


def register(mcp: FastMCP):

    @mcp.tool()
    async def research_attack_vector(
        vuln_type: str,
        tech_stack: str = "",
        finding_summary: str = "",
        endpoint: str = "",
        target_domain: str = "",
    ) -> str:
        """Curated security-research bundle for a suspected attack vector.

        Returns four sections: (1) deep-dive prompts + chain hypotheses, (2) verified-static methodology deep-links (PortSwigger/HackTricks/PayloadsAllTheThings/WSTG) to WebFetch, (3) pre-baked WebSearch queries for JS/bot-blocked sources (H1/Bugcrowd/writeups), (4) advisory-DB URLs (Exploit-DB/OSV/GitHub Advisory/Snyk/AttackerKB). Rule 27's creative-hunting budget lives here.

        Args:
            vuln_type: Class (sqli/xss/ssrf/ssti/idor/rce/csrf/xxe/race_condition/request_smuggling/deserialization/open_redirect/prototype_pollution/auth_bypass/graphql/websocket/cors/business_logic). Free-form accepted.
            tech_stack: Comma-separated tech ("express,redis"). Narrows code + advisory-DB search.
            finding_summary: One-sentence observation; used verbatim in some queries.
            endpoint: Endpoint that triggered suspicion. Optional.
            target_domain: Bug-bounty host; adds a "priors on this target" query.
        """
        v = (vuln_type or "").lower().strip()
        kb = _VECTOR_KB.get(v)
        # Build alias mapping for free-form
        if not kb:
            aliases = {
                "sql_injection": "sqli", "sqlinjection": "sqli",
                "cross_site_scripting": "xss",
                "server_side_request_forgery": "ssrf",
                "server_side_template_injection": "ssti",
                "remote_code_execution": "rce", "command_injection": "rce",
                "cross_site_request_forgery": "csrf",
                "xml_external_entity": "xxe",
                "http_request_smuggling": "request_smuggling", "smuggling": "request_smuggling",
                "insecure_deserialization": "deserialization",
                "openredirect": "open_redirect",
                "prototypepollution": "prototype_pollution", "proto_pollution": "prototype_pollution",
                "authentication_bypass": "auth_bypass", "auth": "auth_bypass",
                "broken_access_control": "auth_bypass",
                "race": "race_condition",
            }
            if v in aliases:
                v = aliases[v]
                kb = _VECTOR_KB.get(v)

        lines: list[str] = [
            f"=== Security Research Bundle: {vuln_type or '(unspecified)'} ===",
            "",
        ]
        if finding_summary:
            lines.append(f"Finding context: {finding_summary}")
            lines.append("")

        # ── Section 1: Deep-dive checklist ──────────────────────────
        if kb:
            lines.append(f"── DEEP-DIVE QUESTIONS ({v}) ──")
            for q in kb["deep_dive"]:
                lines.append(f"  Q: {q}")
            lines.append("")
            lines.append(f"── OBSCURE VECTORS ({v}) ──  (commonly missed)")
            for o in kb["obscure"]:
                lines.append(f"  • {o}")
            lines.append("")
            lines.append(f"── CHAIN HYPOTHESES ({v}) ──  (what this bug ENABLES)")
            for c in kb["chain"]:
                lines.append(f"  → {c}")
            lines.append("")
        else:
            lines.append(f"── No structured KB for '{vuln_type}'. Falling back to URL-only research bundle. ──")
            lines.append("")

        query_base = v.replace("_", " ") if kb else (vuln_type or "")

        # ── Section 2: Methodology deep-links (verified static HTML) ─
        meth = _METHODOLOGY_LINKS.get(v)
        if meth:
            lines.append(f"── METHODOLOGY DEEP-LINKS ({v}) — WebFetch directly ──")
            if meth.get("portswigger"):
                lines.append(f"  WebFetch  {meth['portswigger']}    # PortSwigger Web Security Academy")
            if meth.get("hacktricks"):
                lines.append(f"  WebFetch  {meth['hacktricks']}    # HackTricks book")
            if meth.get("patt"):
                lines.append(f"  WebFetch  {meth['patt']}    # PayloadsAllTheThings")
            if meth.get("owasp"):
                lines.append(f"  WebFetch  {meth['owasp']}    # OWASP WSTG")
            lines.append("")

        # ── Section 3: Pre-baked WebSearch queries ──────────────────
        # Use Claude's native WebSearch for sources that are JS-SPA /
        # bot-blocked / Cloudflare'd. Search engines crawl them and
        # return excerpts. We just supply the right keywords.
        lines.append("── SUGGESTED WEB SEARCHES — pipe through WebSearch ──")
        seed_specific = finding_summary or query_base or vuln_type

        # Disclosed reports (H1, Bugcrowd, Intigriti) via site dorks
        lines.append(f'  WebSearch  "{query_base} site:hackerone.com/reports"')
        lines.append(f'  WebSearch  "{query_base} bug bounty writeup 2024 2025"')
        if target_domain:
            lines.append(f'  WebSearch  "{target_domain} hackerone disclosed report"   # priors on this target')
            lines.append(f'  WebSearch  "{target_domain} bug bounty"')

        # Writeup aggregators (Medium / Pentester Land / personal blogs)
        lines.append(f'  WebSearch  "{query_base} site:infosecwriteups.com"')
        lines.append(f'  WebSearch  "{query_base} site:pentester.land"')

        # Research-blog deep dives (PortSwigger Research, Doyensec, Assetnote)
        lines.append(f'  WebSearch  "{query_base} site:portswigger.net/research"')
        lines.append(f'  WebSearch  "{query_base} site:blog.doyensec.com OR site:blog.assetnote.io OR site:samcurry.net"')

        # Tech-specific narrowing
        if tech_stack:
            for tech in [t.strip() for t in tech_stack.split(",") if t.strip()][:3]:
                lines.append(f'  WebSearch  "{query_base} {tech} CVE exploit"')
                lines.append(f'  WebSearch  "{query_base} {tech} bypass"')

        # Use finding_summary verbatim — high-signal phrase match
        if finding_summary and finding_summary != query_base:
            lines.append(f'  WebSearch  "{seed_specific}"   # exact-phrase precedent search')

        lines.append("")

        # ── Section 4: Advisory-DB direct URLs (server-rendered) ─────
        # These all return real HTML content (verified). WebFetch directly.
        lines.append("── ADVISORY DATABASES — WebFetch directly ──")
        adv_seed = (tech_stack.split(",")[0].strip() if tech_stack else query_base).strip()
        if adv_seed:
            lines.append(f"  WebFetch  {_exploitdb_search(adv_seed)}    # Exploit-DB")
            lines.append(f"  WebFetch  {_osv_search(adv_seed)}    # OSV.dev (Google's vuln DB)")
            lines.append(f"  WebFetch  {_github_advisory_search(adv_seed)}    # GitHub Advisory Database")
            lines.append(f"  WebFetch  {_snyk_db_search(adv_seed)}    # Snyk Vulnerability DB")
            lines.append(f"  WebFetch  {_attackerkb_search(adv_seed)}    # Rapid7 AttackerKB (exploit-in-the-wild intel)")
        lines.append("")

        # ── Section 5: GitHub code-pattern search ───────────────────
        if tech_stack:
            lines.append("── GITHUB CODE SEARCH — find similar vulnerable patterns ──")
            techs = [t.strip() for t in tech_stack.split(",") if t.strip()][:3]
            code_patterns = {
                "sqli": "raw query string",
                "xss": "innerHTML req.query",
                "ssrf": "axios.get req.body",
                "ssti": "render_template_string request",
                "idor": "findByPk req.params.id",
                "rce": "exec child_process req",
                "deserialization": "ObjectInputStream readObject",
                "prototype_pollution": "Object.assign req.body",
                "open_redirect": "res.redirect req.query",
            }
            pat = code_patterns.get(v, vuln_type)
            for tech in techs:
                q = f"{pat} language:{tech}".strip()
                lines.append(f"  WebFetch  {_github_code_search(q)}")
            lines.append("")

        # ── Section 6: Complementary MCP calls ──────────────────────
        lines.append("── COMPLEMENTARY MCP CALLS ──")
        if tech_stack:
            lines.append(f"  map_tech_to_cves(target_domain={target_domain!r}, tech={tech_stack!r})")
            for tech in [t.strip() for t in tech_stack.split(",") if t.strip()][:2]:
                lines.append(f"  search_cve(product={tech!r})")
        if kb and v in ("sqli", "xss", "ssrf", "ssti", "rce", "xxe", "open_redirect", "csrf"):
            lines.append(f"  get_payloads(category={v!r})  # crafted payloads with WAF-bypass variants")
        if v in ("ssrf", "ssti", "rce", "sqli", "xxe", "request_smuggling"):
            lines.append(f"  auto_probe(endpoint={endpoint!r}, parameter='PARAM', categories=[{v!r}])")
        if v == "race_condition":
            lines.append(f"  test_race_condition(url={endpoint!r}, ...)")
        if v == "websocket":
            lines.append(f"  test_websocket(url={endpoint!r}, ...)")
        if v == "ssti":
            lines.append(f"  test_ssti(endpoint={endpoint!r}, parameter='PARAM')")
        if v == "prototype_pollution":
            lines.append(f"  test_prototype_pollution(url={endpoint!r}, ...)")
        if v == "xxe":
            lines.append(f"  test_xxe(url={endpoint!r}, ...)")
        if v == "csrf":
            lines.append(f"  test_csrf(url={endpoint!r}, ...)")
        if v == "ssrf":
            lines.append(f"  test_ssrf(url={endpoint!r}, ...)")
        lines.append("")

        # ── Section 7: Triage protocol ──────────────────────────────
        lines.append("── TRIAGE PROTOCOL ──")
        lines.append("  1. Read DEEP-DIVE + OBSCURE inline (free, no fetch). Pick ONE you haven't tested.")
        lines.append("  2. WebFetch the PortSwigger Academy + HackTricks links — class methodology.")
        lines.append("  3. Run 2-3 WebSearch queries — disclosed-report priors + tech-specific bypass.")
        lines.append("  4. WebFetch 1-2 advisory DBs (Exploit-DB / OSV / Snyk DB) when tech_stack supplied.")
        lines.append("  5. Form ONE testable hypothesis. Probe via MCP through Burp (Rule 26a).")
        lines.append("  6. PASS → assess_finding + chain via CHAIN HYPOTHESES. FAIL → cycle once, then router.")
        lines.append("  Budget: ≤6 web hits per research cycle. Over-research is the failure mode.")

        return "\n".join(lines)
