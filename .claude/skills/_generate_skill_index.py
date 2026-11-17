#!/usr/bin/env python3
"""Generate _skill_index.json from skill YAML frontmatter + content heuristics.

Reads every .md file in the skills directory, extracts frontmatter fields
(name, description), applies the SKILL_META mapping for structured metadata
(category, owasp_id, cwe_ids, chains_with, prerequisites, tech_stack), and
writes a machine-readable index for auto-selection and coverage tracking.

Run: python3 .claude/skills/_generate_skill_index.py
"""

from __future__ import annotations

import json
from pathlib import Path

SKILLS_DIR = Path(__file__).parent

# ── Structured metadata mapping ─────────────────────────────────────────────
# Maps skill filename (without .md) to metadata not derivable from frontmatter.

SKILL_META: dict[str, dict] = {
    # ── Workflow skills ──
    "hunt": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": ["chain-findings", "verify-finding"], "prerequisites": [], "tech_stack": []},
    "verify-finding": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": ["hunt"], "tech_stack": []},
    "chain-findings": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": ["verify-finding"], "tech_stack": []},
    "investigate": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": ["verify-finding"], "prerequisites": [], "tech_stack": []},
    "exploit-confirm": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": ["verify-finding"], "prerequisites": [], "tech_stack": []},
    "autopilot": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "resume": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "dispatch-agents": {"category": "agent", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "swarm-hunting": {"category": "agent", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": ["hunt"], "tech_stack": []},
    "command-engagement": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "continuous-retest-loop": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "cve-freshness-loop": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "cleanup-rollback": {"category": "utility", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "operational-discipline": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "noise-budget": {"category": "utility", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "user-override": {"category": "utility", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "verdict-tools": {"category": "utility", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "auto-trigger": {"category": "utility", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},

    # ── Recon / surface skills ──
    "recon-takeover": {"category": "recon", "owasp_id": "WSTG-INFO-01", "cwe_ids": [], "chains_with": ["hunt"], "prerequisites": [], "tech_stack": []},
    "smart-move-fresh-target": {"category": "recon", "owasp_id": "WSTG-INFO-01", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "fuzz-hidden-paths": {"category": "recon", "owasp_id": "WSTG-CONF-05", "cwe_ids": ["CWE-538"], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "ip-allowlist-coverage": {"category": "recon", "owasp_id": "WSTG-CONF-10", "cwe_ids": ["CWE-284"], "chains_with": [], "prerequisites": [], "tech_stack": []},

    # ── Vuln-class playbooks ──
    "playbook-idor-bola": {"category": "vuln-class", "owasp_id": "WSTG-ATHZ-04", "cwe_ids": ["CWE-639", "CWE-862"], "chains_with": ["chain-findings"], "prerequisites": [], "tech_stack": []},
    "playbook-business-logic": {"category": "vuln-class", "owasp_id": "WSTG-BUSL-01", "cwe_ids": ["CWE-840"], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "playbook-ssrf-deep-dive": {"category": "vuln-class", "owasp_id": "WSTG-INPV-19", "cwe_ids": ["CWE-918"], "chains_with": ["playbook-cloud-native"], "prerequisites": [], "tech_stack": []},
    "playbook-xss-delivery": {"category": "vuln-class", "owasp_id": "WSTG-INPV-01", "cwe_ids": ["CWE-79"], "chains_with": ["chain-findings"], "prerequisites": [], "tech_stack": []},
    "playbook-jwt-deep-dive": {"category": "vuln-class", "owasp_id": "WSTG-SESS-01", "cwe_ids": ["CWE-347", "CWE-345"], "chains_with": ["playbook-oauth-flow-attacks"], "prerequisites": [], "tech_stack": []},
    "playbook-oauth-flow-attacks": {"category": "vuln-class", "owasp_id": "WSTG-ATHN-07", "cwe_ids": ["CWE-287", "CWE-601"], "chains_with": ["playbook-jwt-deep-dive"], "prerequisites": [], "tech_stack": ["oauth"]},
    "playbook-otp-mfa-bypass": {"category": "vuln-class", "owasp_id": "WSTG-ATHN-09", "cwe_ids": ["CWE-308", "CWE-287"], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "playbook-request-smuggling": {"category": "vuln-class", "owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-444"], "chains_with": ["playbook-cache-deception"], "prerequisites": [], "tech_stack": []},
    "playbook-cache-deception": {"category": "vuln-class", "owasp_id": "WSTG-ATHN-06", "cwe_ids": ["CWE-524"], "chains_with": ["playbook-request-smuggling"], "prerequisites": [], "tech_stack": []},
    "playbook-deserialization": {"category": "vuln-class", "owasp_id": "WSTG-INPV-14", "cwe_ids": ["CWE-502"], "chains_with": [], "prerequisites": [], "tech_stack": ["java", ".net", "php", "python"]},
    "playbook-prototype-pollution": {"category": "vuln-class", "owasp_id": "WSTG-INPV-01", "cwe_ids": ["CWE-1321"], "chains_with": ["playbook-xss-delivery"], "prerequisites": [], "tech_stack": ["node.js", "javascript"]},
    "playbook-pollution": {"category": "vuln-class", "owasp_id": "WSTG-INPV-04", "cwe_ids": ["CWE-235"], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "playbook-graphql-deep": {"category": "vuln-class", "owasp_id": "WSTG-APIT-01", "cwe_ids": ["CWE-200", "CWE-862"], "chains_with": ["playbook-idor-bola"], "prerequisites": [], "tech_stack": ["graphql"]},
    "playbook-websocket-attacks": {"category": "vuln-class", "owasp_id": "WSTG-CLNT-10", "cwe_ids": ["CWE-1385"], "chains_with": [], "prerequisites": [], "tech_stack": ["websocket"]},
    "playbook-saml-xsw": {"category": "vuln-class", "owasp_id": "WSTG-ATHN-07", "cwe_ids": ["CWE-347"], "chains_with": [], "prerequisites": [], "tech_stack": ["saml"]},
    "playbook-server-action-rsc": {"category": "vuln-class", "owasp_id": "WSTG-INPV-01", "cwe_ids": ["CWE-502"], "chains_with": [], "prerequisites": [], "tech_stack": ["react", "next.js"]},
    "playbook-payment-and-auth": {"category": "vuln-class", "owasp_id": "WSTG-BUSL-09", "cwe_ids": ["CWE-840", "CWE-287"], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "playbook-api-advanced": {"category": "vuln-class", "owasp_id": "WSTG-APIT-01", "cwe_ids": ["CWE-285", "CWE-862"], "chains_with": ["playbook-idor-bola"], "prerequisites": [], "tech_stack": []},
    "playbook-cve-research": {"category": "vuln-class", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "playbook-router": {"category": "vuln-class", "owasp_id": "WSTG-CONF-05", "cwe_ids": ["CWE-284"], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "playbook-source-review": {"category": "vuln-class", "owasp_id": "WSTG-INFO-05", "cwe_ids": ["CWE-540"], "chains_with": [], "prerequisites": [], "tech_stack": []},

    # ── LLM / AI skills ──
    "playbook-llm-security": {"category": "vuln-class", "owasp_id": "", "cwe_ids": ["CWE-77"], "chains_with": [], "prerequisites": [], "tech_stack": ["llm", "ai"]},

    # ── Cloud / Infra skills ──
    "playbook-cloud-native": {"category": "infrastructure", "owasp_id": "", "cwe_ids": ["CWE-284"], "chains_with": ["playbook-ssrf-deep-dive"], "prerequisites": [], "tech_stack": ["aws", "azure", "gcp", "kubernetes"]},

    # ── Network / Red-team skills ──
    "playbook-pivoting": {"category": "redteam", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "playbook-ad-lateral-delegation": {"category": "redteam", "owasp_id": "", "cwe_ids": ["CWE-284"], "chains_with": ["playbook-pivoting"], "prerequisites": [], "tech_stack": ["active-directory"]},
    "playbook-linux-privesc": {"category": "redteam", "owasp_id": "", "cwe_ids": ["CWE-269"], "chains_with": [], "prerequisites": [], "tech_stack": ["linux"]},
    "playbook-windows-privesc": {"category": "redteam", "owasp_id": "", "cwe_ids": ["CWE-269"], "chains_with": [], "prerequisites": [], "tech_stack": ["windows"]},
    "playbook-c2-sliver": {"category": "redteam", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "playbook-red-team-web": {"category": "redteam", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "msf-quickwin": {"category": "redteam", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "network-scan-techniques": {"category": "infrastructure", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "non-http-protocol-testing": {"category": "infrastructure", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},

    # ── Mobile skills ──
    "mobile-mastg": {"category": "mobile", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": ["android", "ios"]},
    "playbook-mobile-backend": {"category": "mobile", "owasp_id": "", "cwe_ids": [], "chains_with": ["playbook-mobile-dynamic"], "prerequisites": [], "tech_stack": ["android", "ios"]},
    "playbook-mobile-dynamic": {"category": "mobile", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": ["android", "ios"]},
    "phone-control": {"category": "mobile", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": ["android"]},

    # ── Browser / Desktop skills ──
    "browser-backends": {"category": "utility", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "desktop-electron": {"category": "vuln-class", "owasp_id": "", "cwe_ids": ["CWE-829"], "chains_with": [], "prerequisites": [], "tech_stack": ["electron"]},
    "cua-hunt": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},

    # ── Analysis / Smart-move skills ──
    "smart-move-captured-something-weird": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": ["investigate"], "prerequisites": [], "tech_stack": []},
    "smart-move-chain-low-findings": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": ["chain-findings"], "prerequisites": [], "tech_stack": []},
    "smart-move-found-js-bundle": {"category": "recon", "owasp_id": "WSTG-INFO-05", "cwe_ids": ["CWE-540"], "chains_with": [], "prerequisites": [], "tech_stack": ["javascript"]},
    "smart-move-known-cve-poc-fails": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "static-dynamic-analysis": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "craft-payload": {"category": "utility", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "fuzz-upload": {"category": "vuln-class", "owasp_id": "WSTG-BUSL-08", "cwe_ids": ["CWE-434"], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "security-research": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "offline-hunt": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},

    # ── Reporting skills ──
    "report-templates": {"category": "reporting", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": ["verify-finding"], "tech_stack": []},
    "evidence-and-tabs": {"category": "reporting", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "screenshot-token-economy": {"category": "utility", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "burp-workflow": {"category": "utility", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "handle-docx": {"category": "utility", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
    "lab-solve": {"category": "workflow", "owasp_id": "", "cwe_ids": [], "chains_with": [], "prerequisites": [], "tech_stack": []},
}


def _parse_frontmatter(text: str) -> dict:
    """Extract YAML frontmatter fields from a markdown file."""
    if not text.startswith("---"):
        return {}
    end = text.find("---", 3)
    if end < 0:
        return {}
    block = text[3:end].strip()
    result: dict = {}
    for line in block.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            result[key.strip()] = val.strip()
    return result


def generate_index() -> list[dict]:
    """Generate the skill index from all .md files in the skills directory."""
    entries: list[dict] = []
    for path in sorted(SKILLS_DIR.glob("*.md")):
        if path.name.startswith("_"):
            continue
        slug = path.stem
        text = path.read_text(encoding="utf-8", errors="replace")
        fm = _parse_frontmatter(text)

        meta = SKILL_META.get(slug, {})
        entry = {
            "name": fm.get("name", slug),
            "file": path.name,
            "description": fm.get("description", ""),
            "category": meta.get("category", "uncategorized"),
            "owasp_id": meta.get("owasp_id", ""),
            "cwe_ids": meta.get("cwe_ids", []),
            "chains_with": meta.get("chains_with", []),
            "prerequisites": meta.get("prerequisites", []),
            "tech_stack": meta.get("tech_stack", []),
        }
        entries.append(entry)
    return entries


def main() -> None:
    entries = generate_index()
    out_path = SKILLS_DIR / "_skill_index.json"
    out_path.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    cats: dict[str, int] = {}
    for e in entries:
        c = e["category"]
        cats[c] = cats.get(c, 0) + 1
    print(f"Generated {len(entries)} skill entries -> {out_path}")
    for c, n in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"  {c}: {n}")
    wstg = sum(1 for e in entries if e["owasp_id"])
    cwe = sum(1 for e in entries if e["cwe_ids"])
    print(f"  with WSTG ID: {wstg}, with CWE: {cwe}")


if __name__ == "__main__":
    main()
