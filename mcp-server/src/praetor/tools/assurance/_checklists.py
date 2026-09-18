"""Detailed per-test-case checklists for the OWASP standards.

`_standards.py` tracks coverage at the CATEGORY level (what did we NOT test).
This adds the test-case granularity the operator asked for: every individual
test in a guide, its parent category, and the Praetor tool/approach that runs
it — so a checklist can be walked item by item and each confirmed.

A checklist entry: {id, category, name, tool}. `category` matches a key in the
corresponding `_standards.STANDARDS[<std>]["categories"]` so a per-item status
can roll up to the category heatmap. `tool` is the suggested Praetor entry point
an auto-test driver would invoke for that item (advisory, not executed here).

Seeded: `ai_testing` (OWASP AI Testing Guide, 32 tests, complete). WSTG and MASTG
catalogs plug into the same shape.
"""

from __future__ import annotations

from typing import Any

# OWASP AI Testing Guide — 4 domains, 32 tests (mas.owasp.org / AI Testing Guide).
_AI_CHECKLIST: list[dict[str, str]] = [
    # AI Application Testing (14)
    {"id": "AITG-APP-01", "category": "APP", "name": "Prompt injection", "tool": "run_web_llm_owasp_top10 / probe_sse_injection"},
    {"id": "AITG-APP-02", "category": "APP", "name": "Indirect prompt injection", "tool": "inspect_for_prompt_injection"},
    {"id": "AITG-APP-03", "category": "APP", "name": "Sensitive data leakage", "tool": "run_web_llm_owasp_top10"},
    {"id": "AITG-APP-04", "category": "APP", "name": "Input leakage", "tool": "run_garak"},
    {"id": "AITG-APP-05", "category": "APP", "name": "Unsafe outputs (output handling into a sink)", "tool": "probe_xss_executed"},
    {"id": "AITG-APP-06", "category": "APP", "name": "Agentic behavior limits / excessive agency", "tool": "probe_cua_injection_surface"},
    {"id": "AITG-APP-07", "category": "APP", "name": "System-prompt disclosure", "tool": "run_garak"},
    {"id": "AITG-APP-08", "category": "APP", "name": "Embedding manipulation", "tool": "run_pyrit_orchestrator"},
    {"id": "AITG-APP-09", "category": "APP", "name": "Model extraction (via app)", "tool": "run_garak"},
    {"id": "AITG-APP-10", "category": "APP", "name": "Content bias", "tool": "run_garak"},
    {"id": "AITG-APP-11", "category": "APP", "name": "Hallucinations", "tool": "run_garak"},
    {"id": "AITG-APP-12", "category": "APP", "name": "Toxic outputs", "tool": "run_garak"},
    {"id": "AITG-APP-13", "category": "APP", "name": "Over-reliance", "tool": "manual / run_owasp_asi_top10"},
    {"id": "AITG-APP-14", "category": "APP", "name": "Explainability", "tool": "manual"},
    # AI Model Testing (7)
    {"id": "AITG-MOD-01", "category": "MODEL", "name": "Evasion attacks", "tool": "run_pyrit_orchestrator"},
    {"id": "AITG-MOD-02", "category": "MODEL", "name": "Runtime model poisoning", "tool": "run_garak"},
    {"id": "AITG-MOD-03", "category": "MODEL", "name": "Poisoned training sets", "tool": "manual / data review"},
    {"id": "AITG-MOD-04", "category": "MODEL", "name": "Membership inference", "tool": "run_pyrit_orchestrator"},
    {"id": "AITG-MOD-05", "category": "MODEL", "name": "Inversion attacks", "tool": "run_pyrit_orchestrator"},
    {"id": "AITG-MOD-06", "category": "MODEL", "name": "Robustness evaluation", "tool": "run_garak"},
    {"id": "AITG-MOD-07", "category": "MODEL", "name": "Goal alignment", "tool": "run_owasp_asi_top10"},
    # AI Infrastructure Testing (6)
    {"id": "AITG-INF-01", "category": "INFRA", "name": "Supply-chain tampering", "tool": "run_trivy / run_syft"},
    {"id": "AITG-INF-02", "category": "INFRA", "name": "Resource exhaustion", "tool": "test_rate_limit"},
    {"id": "AITG-INF-03", "category": "INFRA", "name": "Plugin boundary violations", "tool": "probe_mcp_server_attacks"},
    {"id": "AITG-INF-04", "category": "INFRA", "name": "Capability misuse", "tool": "run_owasp_asi_top10"},
    {"id": "AITG-INF-05", "category": "INFRA", "name": "Fine-tuning poisoning", "tool": "manual / data review"},
    {"id": "AITG-INF-06", "category": "INFRA", "name": "Development-time model theft", "tool": "manual / access review"},
    # AI Data Testing (5)
    {"id": "AITG-DAT-01", "category": "DATA", "name": "Training-data exposure", "tool": "run_web_llm_owasp_top10"},
    {"id": "AITG-DAT-02", "category": "DATA", "name": "Runtime data exfiltration", "tool": "run_garak"},
    {"id": "AITG-DAT-03", "category": "DATA", "name": "Dataset diversity / coverage", "tool": "manual / data review"},
    {"id": "AITG-DAT-04", "category": "DATA", "name": "Harmful content in datasets", "tool": "manual / data review"},
    {"id": "AITG-DAT-05", "category": "DATA", "name": "Data minimization / consent", "tool": "manual / privacy review"},
]

# OWASP WSTG v4.2 — (id, name). The checklist uses INJT for injection; the
# standard category id for those is INPV, mapped below.
_WSTG_TESTS: list[tuple[str, str]] = [
    ("WSTG-INFO-01", "Search Engine Reconnaissance for Information Leakage"),
    ("WSTG-INFO-02", "Fingerprint Web Server"),
    ("WSTG-INFO-03", "Review Webserver Metafiles for Information Leakage"),
    ("WSTG-INFO-04", "Attack Surface Identification"),
    ("WSTG-INFO-05", "Review Web Page Content for Information Leakage"),
    ("WSTG-INFO-06", "Identify Application Entry Points"),
    ("WSTG-INFO-07", "Map Execution Paths Through Application"),
    ("WSTG-INFO-08", "Fingerprint Web Application Framework"),
    ("WSTG-INFO-09", "Fingerprint Web Application"),
    ("WSTG-INFO-10", "Map Application Architecture"),
    ("WSTG-CONF-01", "Network Infrastructure Configuration"),
    ("WSTG-CONF-02", "Application Platform Configuration"),
    ("WSTG-CONF-03", "File Extensions Handling for Sensitive Information"),
    ("WSTG-CONF-04", "Review Old Backup and Unreferenced Files"),
    ("WSTG-CONF-05", "Enumerate Infrastructure and Application Admin Interfaces"),
    ("WSTG-CONF-06", "HTTP Methods"),
    ("WSTG-CONF-07", "HTTP Strict Transport Security"),
    ("WSTG-CONF-09", "File Permission"),
    ("WSTG-CONF-10", "Subdomain Takeover"),
    ("WSTG-CONF-11", "Cloud Storage"),
    ("WSTG-CONF-12", "Content Security Policy"),
    ("WSTG-CONF-13", "Path Confusion"),
    ("WSTG-CONF-14", "Other HTTP Security Header Misconfigurations"),
    ("WSTG-IDNT-01", "Role Definitions"),
    ("WSTG-IDNT-02", "User Registration Process"),
    ("WSTG-IDNT-03", "Account Provisioning Process"),
    ("WSTG-IDNT-04", "Account Enumeration and Guessable User Account"),
    ("WSTG-IDNT-05", "Weak or Unenforced Username Policy"),
    ("WSTG-ATHN-01", "Credentials Transported over an Encrypted Channel"),
    ("WSTG-ATHN-02", "Default Credentials"),
    ("WSTG-ATHN-03", "Weak Lock Out Mechanism"),
    ("WSTG-ATHN-04", "Bypassing Authentication Schema"),
    ("WSTG-ATHN-05", "Vulnerable Remember Password"),
    ("WSTG-ATHN-06", "Browser Cache Weaknesses"),
    ("WSTG-ATHN-07", "Weak Authentication Methods"),
    ("WSTG-ATHN-08", "Weak Security Question Answer"),
    ("WSTG-ATHN-09", "Weak Password Change or Reset Functionalities"),
    ("WSTG-ATHN-10", "Weaker Authentication in Alternative Channel"),
    ("WSTG-ATHN-11", "Multi-Factor Authentication (MFA)"),
    ("WSTG-ATHZ-01", "Directory Traversal File Include"),
    ("WSTG-ATHZ-02", "Bypassing Authorization Schema"),
    ("WSTG-ATHZ-03", "Privilege Escalation"),
    ("WSTG-ATHZ-04", "Insecure Direct Object References"),
    ("WSTG-ATHZ-05", "OAuth Weaknesses"),
    ("WSTG-SESS-01", "Session Management Schema"),
    ("WSTG-SESS-02", "Cookies Attributes"),
    ("WSTG-SESS-03", "Session Fixation"),
    ("WSTG-SESS-04", "Exposed Session Variables"),
    ("WSTG-SESS-05", "Cross Site Request Forgery"),
    ("WSTG-SESS-06", "Logout Functionality"),
    ("WSTG-SESS-07", "Session Timeout"),
    ("WSTG-SESS-08", "Session Puzzling"),
    ("WSTG-SESS-09", "Session Hijacking"),
    ("WSTG-SESS-10", "JSON Web Tokens"),
    ("WSTG-SESS-11", "Concurrent Sessions"),
    ("WSTG-INJT-01", "Reflected Cross Site Scripting"),
    ("WSTG-INJT-02", "Stored Cross Site Scripting"),
    ("WSTG-INJT-03", "HTTP Verb Tampering"),
    ("WSTG-INJT-04", "HTTP Parameter Pollution"),
    ("WSTG-INJT-05", "SQL Injection"),
    ("WSTG-INJT-06", "LDAP Injection"),
    ("WSTG-INJT-07", "XML Injection"),
    ("WSTG-INJT-08", "SSI Injection"),
    ("WSTG-INJT-09", "XPath Injection"),
    ("WSTG-INJT-10", "IMAP SMTP Injection"),
    ("WSTG-INJT-11", "Code Injection"),
    ("WSTG-INJT-12", "Command Injection"),
    ("WSTG-INJT-13", "Format String Injection"),
    ("WSTG-INJT-14", "Incubated Vulnerability"),
    ("WSTG-INJT-15", "HTTP Response Splitting"),
    ("WSTG-INJT-16", "HTTP Request Smuggling"),
    ("WSTG-INJT-17", "Host Header Injection"),
    ("WSTG-INJT-18", "Server-side Template Injection"),
    ("WSTG-INJT-19", "Server-Side Request Forgery"),
    ("WSTG-INJT-20", "Mass Assignment"),
    ("WSTG-INJT-21", "CSV Injection"),
    ("WSTG-INJT-22", "Prototype Pollution"),
    ("WSTG-INJT-23", "Insecure Deserialization"),
    ("WSTG-ERRH-01", "Improper Error Handling"),
    ("WSTG-ERRH-02", "Stack Traces"),
    ("WSTG-CRYP-01", "Weak Transport Layer Security"),
    ("WSTG-CRYP-02", "Padding Oracle"),
    ("WSTG-CRYP-03", "Sensitive Information Sent via Unencrypted Channels"),
    ("WSTG-CRYP-04", "Weak Cryptographic Primitives"),
    ("WSTG-BUSL-01", "Business Logic Data Validation"),
    ("WSTG-BUSL-02", "Ability to Forge Requests"),
    ("WSTG-BUSL-03", "Integrity Checks"),
    ("WSTG-BUSL-04", "Process Timing"),
    ("WSTG-BUSL-05", "Number of Times a Function Can Be Used Limits"),
    ("WSTG-BUSL-06", "Circumvention of Work Flows"),
    ("WSTG-BUSL-07", "Defenses Against Application Misuse"),
    ("WSTG-BUSL-08", "Upload of Unexpected File Types"),
    ("WSTG-BUSL-09", "Upload of Malicious Files"),
    ("WSTG-BUSL-10", "Payment Functionality"),
    ("WSTG-CLNT-01", "DOM-Based Cross Site Scripting"),
    ("WSTG-CLNT-02", "JavaScript Execution"),
    ("WSTG-CLNT-03", "HTML Injection"),
    ("WSTG-CLNT-04", "Client-side URL Redirect"),
    ("WSTG-CLNT-05", "CSS Injection"),
    ("WSTG-CLNT-06", "Client-side Resource Manipulation"),
    ("WSTG-CLNT-07", "Cross Origin Resource Sharing"),
    ("WSTG-CLNT-09", "Clickjacking"),
    ("WSTG-CLNT-10", "WebSockets"),
    ("WSTG-CLNT-11", "Web Messaging"),
    ("WSTG-CLNT-12", "Browser Storage"),
    ("WSTG-CLNT-13", "Cross Site Script Inclusion"),
    ("WSTG-CLNT-14", "Reverse Tabnabbing"),
    ("WSTG-CLNT-15", "Client-side Template Injection"),
    ("WSTG-APIT-01", "API Reconnaissance"),
    ("WSTG-APIT-02", "API Broken Object Level Authorization"),
    ("WSTG-APIT-03", "Excessive Data Exposure"),
    ("WSTG-APIT-04", "API Broken Function Level Authorization"),
    ("WSTG-APIT-99", "GraphQL"),
]
# INJT test ids roll up to the INPV standard category.
_WSTG_PREFIX_TO_CAT = {"INJT": "INPV"}
_WSTG_TOOL_BY_CAT = {
    "INFO": "browser_crawl / run_katana / discover_attack_surface / detect_tech_stack",
    "CONF": "run_nuclei / discover_common_files / test_host_header",
    "IDNT": "test_login_bypass / discover_hidden_parameters",
    "ATHN": "test_login_bypass / test_rate_limit / test_mfa_bypass",
    "ATHZ": "test_auth_matrix / compare_auth_states",
    "SESS": "test_session_lifecycle / test_jwt / test_csrf",
    "INPV": "auto_probe / fuzz_parameter",
    "ERRH": "auto_probe / smart_analyze",
    "CRYP": "run_tlsx",
    "BUSL": "test_business_logic / test_race_condition / run_flow",
    "CLNT": "test_dom_sinks / probe_postmessage_listeners / test_cors",
    "APIT": "parse_api_schema / test_graphql / probe_bopla",
}
_WSTG_TOOL_OVERRIDE = {
    "WSTG-CONF-06": "probe_40x_bypass / run_nomore403", "WSTG-CONF-10": "test_subdomain_takeover",
    "WSTG-CONF-12": "analyze_csp", "WSTG-ATHN-03": "test_rate_limit / test_login_bypass",
    "WSTG-ATHN-11": "test_mfa_bypass", "WSTG-ATHZ-01": "test_lfi", "WSTG-ATHZ-04": "test_auth_matrix",
    "WSTG-ATHZ-05": "oauth_flow_simulator", "WSTG-SESS-05": "test_csrf", "WSTG-SESS-10": "test_jwt",
    "WSTG-INJT-01": "auto_probe(xss) / run_dalfox / probe_xss_executed",
    "WSTG-INJT-02": "auto_probe(xss) / probe_xss_executed", "WSTG-INJT-04": "test_parameter_pollution",
    "WSTG-INJT-05": "auto_probe(sqli) / run_sqlmap / confirm_sqli", "WSTG-INJT-12": "run_commix / confirm_rce",
    "WSTG-INJT-16": "test_request_smuggling / send_raw_request", "WSTG-INJT-17": "test_host_header",
    "WSTG-INJT-18": "test_ssti / confirm_ssti", "WSTG-INJT-19": "test_ssrf / confirm_ssrf",
    "WSTG-INJT-20": "test_mass_assignment", "WSTG-INJT-21": "auto_probe(csv_injection)",
    "WSTG-INJT-22": "test_prototype_pollution", "WSTG-INJT-23": "generate_deserialization_gadget",
    "WSTG-INJT-07": "test_xxe / confirm_xxe", "WSTG-CRYP-01": "run_tlsx", "WSTG-CRYP-02": "auto_probe",
    "WSTG-BUSL-08": "test_file_upload", "WSTG-BUSL-09": "test_file_upload",
    "WSTG-CLNT-01": "test_dom_sinks", "WSTG-CLNT-04": "test_open_redirect", "WSTG-CLNT-05": "auto_probe",
    "WSTG-CLNT-07": "test_cors", "WSTG-CLNT-09": "test_clickjacking", "WSTG-CLNT-10": "test_websocket",
    "WSTG-CLNT-11": "probe_postmessage_listeners", "WSTG-APIT-02": "probe_bopla / test_auth_matrix",
    "WSTG-APIT-04": "probe_bopla / test_auth_matrix", "WSTG-APIT-99": "test_graphql",
}


def _build_wstg() -> list[dict[str, str]]:
    out = []
    for tid, name in _WSTG_TESTS:
        prefix = tid.split("-")[1]
        cat = _WSTG_PREFIX_TO_CAT.get(prefix, prefix)
        tool = _WSTG_TOOL_OVERRIDE.get(tid) or _WSTG_TOOL_BY_CAT.get(cat, "auto_probe")
        out.append({"id": tid, "category": cat, "name": name, "tool": tool})
    return out


CHECKLISTS: dict[str, list[dict[str, str]]] = {
    "ai_testing": _AI_CHECKLIST,
    "wstg": _build_wstg(),
    # "mastg": _MASTG_CHECKLIST, # follows (MASTG-TEST-NNNN -> MASVS cat)
}


def checklist_for(standard: str) -> list[dict[str, str]]:
    return CHECKLISTS.get(standard, [])


# Per-item status the operator confirms, persisted in .burp-intel/<domain>/checklist.json.
# {standard}:{item_id} -> {status, note, at}. Auto (coverage) is overlaid at render.
_ITEM_STATES = {"confirmed", "finding", "not_applicable", "open"}
_ITEM_BOX = {"confirmed": "[x]", "finding": "[!]", "not_applicable": "[-]", "open": "[ ]"}


def _load_status(domain: str) -> dict[str, dict[str, str]]:
    if not domain:
        return {}
    from praetor.tools.report.lifecycle import load_intel
    return load_intel(domain, "checklist").get("items", {}) or {}


def _save_status(domain: str, items: dict[str, dict[str, str]]) -> None:
    from praetor.tools.intel import _intel_path
    from praetor.tools.notes._findings_io import atomic_write_json
    d = _intel_path(domain)
    d.mkdir(parents=True, exist_ok=True)
    atomic_write_json(d / "checklist.json", {"items": items})


def render_checklist(standard: str, standard_name: str, cases: list[dict[str, str]],
                     tested_categories: set[str] | None = None,
                     item_status: dict[str, dict[str, str]] | None = None) -> str:
    """Render the detailed per-test-case checklist. Pure.

    Status precedence per item: an explicit operator status in `item_status`
    (confirmed / finding / not_applicable) wins; else [~] if the item's category
    was touched by coverage (`tested_categories`); else [ ] open (Rule 19a).
    """
    touched = tested_categories or set()
    status = item_status or {}
    lines = [f"# {standard_name} — detailed checklist ({len(cases)} tests)", ""]
    by_cat: dict[str, list[dict[str, str]]] = {}
    for c in cases:
        by_cat.setdefault(c["category"], []).append(c)
    open_n = done_n = 0
    for cat, items in by_cat.items():
        lines.append(f"## {cat}")
        for it in items:
            st = status.get(f"{standard}:{it['id']}", {})
            explicit = st.get("status")
            if explicit in ("confirmed", "finding", "not_applicable"):
                box = _ITEM_BOX[explicit]
                done_n += 1
                note = f"  ({st.get('note')})" if st.get("note") else ""
            elif it["category"] in touched:
                box = "[~]"  # category touched, item not individually confirmed
                note = ""
            else:
                box = "[ ]"
                open_n += 1
                note = ""
            lines.append(f"  {box} {it['id']}  {it['name']}  -> {it['tool']}{note}")
        lines.append("")
    lines.append(f"{done_n} confirmed/NA, {len(cases) - done_n - open_n} category-touched, "
                 f"{open_n} OPEN of {len(cases)}. "
                 f"[x]=confirmed [!]=finding [-]=N/A [~]=category touched [ ]=untested (Rule 19a).")
    return "\n".join(lines)


# Rule-29 high-value categories, per standard, for the high-impact ordering.
_HIGH_VALUE = {
    "wstg": ("ATHZ", "ATHN", "INPV", "BUSL", "APIT", "SESS"),
    "owasp_top10": ("A01", "A05", "A07", "A06"),
    "api_top10": ("API1", "API5", "API3", "API2"),
    "ai_testing": ("APP", "MODEL"),
    "mastg": ("AUTH", "STORAGE", "PLATFORM"),
}


def next_open_items(standard: str, cases: list[dict[str, str]],
                    item_status: dict[str, dict[str, str]],
                    touched: set[str], mode: str = "full_coverage") -> list[dict[str, str]]:
    """Pure: the OPEN test cases to run next, ordered by engagement mode.

    An item is OPEN unless it has an explicit confirmed/finding/not_applicable
    status. `full_coverage`/`checklist` -> catalog order; `high_impact` ->
    Rule-29 high-value categories first (and drops pure-manual items).
    """
    done = {k.split(":", 1)[1] for k, v in item_status.items()
            if v.get("status") in ("confirmed", "finding", "not_applicable")}
    open_items = [c for c in cases if c["id"] not in done]
    if mode == "high_impact":
        hv = _HIGH_VALUE.get(standard, ())
        open_items = [c for c in open_items if "manual" not in c["tool"].lower()]
        open_items.sort(key=lambda c: hv.index(c["category"]) if c["category"] in hv else len(hv))
    return open_items


def register(mcp: Any) -> None:
    from .coverage_map import _tested_classes
    from ._standards import STANDARDS, category_of

    @mcp.tool()
    async def checklist(standard: str = "ai_testing", domain: str = "") -> str:
        """Detailed per-test-case checklist for an OWASP standard.

        Walks every individual test in the guide (id, name, and the Praetor tool
        that runs it), grouped by category. With `domain`, marks each item's
        category as touched/open from coverage.json so the operator sees exactly
        which test cases remain. Standards with a detailed catalog: ai_testing
        (32 tests); others fall back to their category list.

        Args:
            standard: ai_testing (detailed) | owasp_top10 | api_top10 | wstg | mastg.
            domain: optional target for tested/untested marking.
        """
        cases = checklist_for(standard)
        if standard not in STANDARDS:
            return (f"unknown standard '{standard}'; "
                    f"valid: {sorted(STANDARDS.keys())}")
        name = STANDARDS[standard]["name"]
        if not cases:
            cats = STANDARDS[standard]["categories"]
            return (f"# {name} — no per-test-case catalog yet; "
                    f"{len(cats)} categories tracked. Use coverage_status(domain) "
                    f"for the category heatmap.")
        touched: set[str] = set()
        if domain:
            for cls in _tested_classes(domain):
                cat = category_of(standard, cls)
                if cat:
                    touched.add(cat)
        return render_checklist(standard, name, cases, touched, _load_status(domain))

    @mcp.tool()
    async def checklist_update(domain: str, standard: str, item_id: str,
                               status: str, note: str = "") -> str:
        """Confirm/complete one checklist test case (operator-owned status).

        Walk the checklist item by item: run each item's mapped tool, then record
        the operator-confirmed result here so it sticks (auto coverage marks a
        category touched; this marks the SPECIFIC test case done). Use this in the
        confirm loop — present the item + evidence, ask the operator, then set it.

        Args:
            domain: target.
            standard: ai_testing / owasp_top10 / api_top10 / wstg / mastg.
            item_id: the test-case id, e.g. AITG-APP-01.
            status: confirmed | finding | not_applicable | open.
            note: short evidence / reason (required for not_applicable).
        """
        if status not in _ITEM_STATES:
            return f"status must be one of {sorted(_ITEM_STATES)}"
        if status == "not_applicable" and not note.strip():
            return "not_applicable requires a note (why it doesn't apply) — Rule 19a."
        from datetime import datetime, timezone
        items = _load_status(domain)
        key = f"{standard}:{item_id}"
        if status == "open":
            items.pop(key, None)
        else:
            items[key] = {"status": status, "note": note.strip(),
                          "at": datetime.now(timezone.utc).isoformat()}
        _save_status(domain, items)
        return f"checklist {key} -> {status}" + (f" ({note.strip()})" if note.strip() else "")

    @mcp.tool()
    async def checklist_autotest(domain: str, standard: str = "wstg",
                                 mode: str = "full_coverage", limit: int = 25) -> str:
        """Drive the checklist: the ordered run-plan of OPEN test cases to execute.

        Walks the catalog and returns the next OPEN items (skipping confirmed /
        finding / not_applicable), each with the Praetor tool to run — so the
        orchestrator executes each, then records the result via
        `checklist_update`. This is the "test every case" loop.

        Ordering follows the Phase-0 engagement mode: `high_impact` puts the
        Rule-29 high-value categories first (and drops pure-manual items);
        `full_coverage` / `checklist` walk in catalog order.

        Args:
            domain: target.
            standard: wstg / ai_testing / owasp_top10 / api_top10 / mastg.
            mode: full_coverage | high_impact | checklist.
            limit: max items in this plan (page through the rest as they close).
        """
        cases = checklist_for(standard)
        if standard not in STANDARDS:
            return f"unknown standard '{standard}'; valid: {sorted(STANDARDS.keys())}"
        if not cases:
            return (f"{STANDARDS[standard]['name']} has no per-test-case catalog; "
                    f"use coverage_status(domain) for the category heatmap.")
        status = _load_status(domain)
        touched: set[str] = set()
        if domain:
            for cls in _tested_classes(domain):
                cat = category_of(standard, cls)
                if cat:
                    touched.add(cat)
        plan = next_open_items(standard, cases, status, touched, mode)
        total_open = len(plan)
        plan = plan[:max(1, limit)]
        lines = [f"# Auto-test plan — {STANDARDS[standard]['name']} ({mode})",
                 f"{total_open} OPEN test cases; next {len(plan)}:"]
        for it in plan:
            lines.append(f"  {it['id']} [{it['category']}]  {it['name']}  -> RUN {it['tool']}")
        lines.append("")
        lines.append("For each: run the tool, grade on the response BODY (Rule 13a), then "
                     "checklist_update(domain, standard, item_id, status=confirmed|finding|"
                     "not_applicable, note=...). A blocker is an ASK, not a skip (Rule 32a).")
        return "\n".join(lines)
