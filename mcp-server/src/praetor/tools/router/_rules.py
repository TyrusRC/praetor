"""Declarative signal->action routing table + safety constants.
Rules are data; the engine (_engine.py) evaluates them. The router never
executes — it selects and ranks."""

ALWAYS_ASK_TOOLS = {
    # red-team / AD
    "run_network_tool", "run_network_recon", "run_nmap", "ingest_bloodhound",
    "crack_hashes",
    # cloud
    "run_prowler", "run_scout_suite", "run_cloudsploit", "run_pacu",
    # exploit
    "msf_search", "msf_check", "msf_exploit", "msfrpc_module_execute",
    # expensive active scan
    "scan_url",
    # azure AD collector (needs creds; red-team)
    "run_azurehound",
}

HARD_DENY = ["DROP TABLE", "rm -rf", "shutdown", "format ", "DELETE FROM",
             "TRUNCATE"]

IMPACT_WEIGHT = {
    "run_sqlmap": 90, "test_ssti": 90, "run_commix": 88, "run_dalfox": 70,
    "run_wpscan": 60, "run_nuclei": 55, "crack_jwt_secret": 50,
    "auto_probe": 40, "scan_url": 80, "run_network_tool": 85,
    "run_prowler": 80, "run_scout_suite": 75, "run_azurehound": 82,
}

# nuclei tag mapping by detected tech (targeted, not all templates)
_NUCLEI_TAGS = {
    "wordpress": "wordpress,wp-plugin", "php": "php", "asp.net": "aspx,iis",
    "java": "java,spring", "nginx": "nginx", "apache": "apache",
    "nodejs": "nodejs,express", "django": "django", "laravel": "laravel",
}


def _tech(sigs, value):
    return [s for s in sigs if s["type"] == "tech" and s["value"].lower() == value]


def _type(sigs, t):
    return [s for s in sigs if s["type"] == t]


def _baseline_when(sigs):
    covered = {s.get("target") for s in sigs if s["type"] == "covered"}
    return [s for s in sigs if s["type"] == "params_present"
            and s.get("target") not in covered]


def _nuclei_when(sigs):
    return [s for s in sigs if s["type"] == "tech"
            and s["value"].lower() in _NUCLEI_TAGS]


ROUTING_TABLE = [
    {"id": "baseline_coverage", "policy": "auto",
     "rationale": "params present, tuple uncovered -> full WSTG/Top-10 sweep",
     "when": _baseline_when,
     "fire": lambda s: [{"tool": "auto_probe",
                         "args": {"targets": [{"url": s.get("target", "")}]}}]},
    {"id": "tech_wordpress", "policy": "auto",
     "rationale": "WordPress detected -> wpscan",
     "when": lambda s: _tech(s, "wordpress"),
     "fire": lambda s: [{"tool": "run_wpscan", "args": {"url": s.get("target", "")}}]},
    {"id": "tech_nuclei", "policy": "auto",
     "rationale": "tech-targeted nuclei tags (not all templates)",
     "when": _nuclei_when,
     "fire": lambda s: [{"tool": "run_nuclei",
                         "args": {"target": s.get("target", ""),
                                  "tags": _NUCLEI_TAGS[s["value"].lower()]}}]},
    {"id": "reflection_xss", "policy": "auto",
     "rationale": "reflection -> dalfox on the param",
     "when": lambda s: _type(s, "reflection"),
     "fire": lambda s: [{"tool": "run_dalfox",
                         "args": {"url": s.get("target", ""), "param": s.get("value", "")}}]},
    {"id": "sql_error", "policy": "auto",
     "rationale": "SQL error signal -> sqlmap on that request (safe technique)",
     "when": lambda s: _type(s, "sql_error"),
     "fire": lambda s: [{"tool": "run_sqlmap",
                         "args": {"target": s.get("target", ""),
                                  "technique": "BEU", "level": 2, "risk": 1}}]},
    {"id": "cmdi", "policy": "auto",
     "rationale": "cmdi marker -> commix detect-only",
     "when": lambda s: _type(s, "cmdi_marker"),
     "fire": lambda s: [{"tool": "run_commix",
                         "args": {"url": s.get("target", ""), "detect_only": True}}]},
    {"id": "ssti", "policy": "auto",
     "rationale": "ssti marker -> test_ssti",
     "when": lambda s: _type(s, "ssti_marker"),
     "fire": lambda s: [{"tool": "test_ssti",
                         "args": {"url": s.get("target", ""), "parameter": s.get("value", "")}}]},
    {"id": "jwt", "policy": "auto",
     "rationale": "JWT present -> attempt secret crack (local)",
     "when": lambda s: _type(s, "jwt_present"),
     "fire": lambda s: [{"tool": "crack_jwt_secret", "args": {"token": s.get("value", "")}}]},
    {"id": "ad_host", "policy": "ask",
     "rationale": "live SMB/LDAP/Kerberos host -> netexec enum (RED-TEAM: approve)",
     "when": lambda s: [x for x in s if x["type"] == "service"
                        and x["value"] in ("smb", "ldap", "kerberos")],
     "fire": lambda s: [{"tool": "run_network_tool",
                         "args": {"tool": "netexec", "target": s.get("target", "")}}]},
    {"id": "cloud_creds", "policy": "ask",
     "rationale": "cloud creds -> prowler/scoutsuite (CLOUD: approve)",
     "when": lambda s: [x for x in s if x["type"] == "creds" and x["value"] == "cloud"],
     "fire": lambda s: [{"tool": "run_prowler", "args": {}}]},
    {"id": "azure_ad_creds", "policy": "ask",
     "rationale": "Azure AD creds -> azurehound collection for BloodHound (RED-TEAM: approve)",
     "when": lambda s: [x for x in s if x["type"] == "creds" and x["value"] == "azure_ad"],
     "fire": lambda s: [{"tool": "run_azurehound", "args": {"tenant": s.get("target", "")}}]},
    {"id": "burp_active", "policy": "ask",
     "rationale": "specific suspicious request -> targeted Burp active audit (per-request, not mass crawl; EXPENSIVE: approve)",
     "when": lambda s: [x for x in s if x["type"] == "scan_candidate"],
     "fire": lambda s: [{"tool": "scan_url", "args": {"index": s.get("value", "")}}]},
]
