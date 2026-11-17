"""WSTG / CWE / chain / prerequisite mappings for Praetor knowledge-base categories.

Each KB category is mapped to its closest OWASP WSTG 4.2 test ID, primary CWE
entries, escalation chains, and testing prerequisites. Categories that span
multiple WSTG tests list the most specific one; split files (sqli_blind,
ssti_python, ...) inherit the parent mapping and are merged at index-generation
time.

Mapping conventions:
- owasp_id: single WSTG test ID or "" when no WSTG test maps cleanly.
- cwe_ids: 1-3 most relevant CWEs, ordered by relevance.
- chains_with: categories whose findings combine for severity escalation.
  Supplements (does not replace) any chain_with already in the KB JSON.
- prerequisites: categories that should run BEFORE this one for best results.
"""

from __future__ import annotations

from typing import TypedDict


class KBMapping(TypedDict, total=False):
    owasp_id: str
    cwe_ids: list[str]
    chains_with: list[str]
    prerequisites: list[str]


# fmt: off
WSTG_CWE_MAP: dict[str, KBMapping] = {

    # ── Injection (server-side) ──────────────────────────────────────────────
    "sqli":                     {"owasp_id": "WSTG-INPV-05", "cwe_ids": ["CWE-89"],            "chains_with": ["auth_bypass", "idor", "info_disclosure"],                   "prerequisites": []},
    "sqli_blind":               {"owasp_id": "WSTG-INPV-05", "cwe_ids": ["CWE-89"],            "chains_with": ["auth_bypass", "idor"],                                      "prerequisites": []},
    "sqli_engines":             {"owasp_id": "WSTG-INPV-05", "cwe_ids": ["CWE-89"],            "chains_with": ["auth_bypass", "idor"],                                      "prerequisites": []},
    "ssti":                     {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-1336"],          "chains_with": ["rce_detection", "command_injection"],                        "prerequisites": []},
    "ssti_python":              {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-1336"],          "chains_with": ["rce_detection", "command_injection"],                        "prerequisites": []},
    "ssti_java":                {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-1336"],          "chains_with": ["rce_detection", "command_injection"],                        "prerequisites": []},
    "ssti_js":                  {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-1336"],          "chains_with": ["rce_detection", "command_injection"],                        "prerequisites": []},
    "ssti_php":                 {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-1336"],          "chains_with": ["rce_detection", "command_injection"],                        "prerequisites": []},
    "ssti_elixir":              {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-1336"],          "chains_with": ["rce_detection", "command_injection"],                        "prerequisites": []},
    "command_injection":        {"owasp_id": "WSTG-INPV-12", "cwe_ids": ["CWE-78"],            "chains_with": ["rce_detection", "ssrf"],                                    "prerequisites": []},
    "xxe":                      {"owasp_id": "WSTG-INPV-07", "cwe_ids": ["CWE-611"],           "chains_with": ["ssrf", "path_traversal", "info_disclosure"],                "prerequisites": []},
    "ldap_injection":           {"owasp_id": "WSTG-INPV-06", "cwe_ids": ["CWE-90"],            "chains_with": ["auth_bypass", "info_disclosure"],                           "prerequisites": []},
    "xpath_injection":          {"owasp_id": "WSTG-INPV-09", "cwe_ids": ["CWE-643"],           "chains_with": ["auth_bypass", "info_disclosure"],                           "prerequisites": []},
    "nosql":                    {"owasp_id": "WSTG-INPV-05", "cwe_ids": ["CWE-943"],           "chains_with": ["auth_bypass", "idor"],                                      "prerequisites": []},
    "xml_injection":            {"owasp_id": "WSTG-INPV-07", "cwe_ids": ["CWE-91"],            "chains_with": ["xxe", "ssrf"],                                              "prerequisites": []},
    "json_injection":           {"owasp_id": "WSTG-INPV-16", "cwe_ids": ["CWE-74"],            "chains_with": ["auth_bypass", "mass_assignment"],                           "prerequisites": []},
    "email_injection":          {"owasp_id": "WSTG-INPV-11", "cwe_ids": ["CWE-93"],            "chains_with": ["host_header", "crlf_injection"],                            "prerequisites": []},
    "crlf_injection":           {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-93"],            "chains_with": ["xss", "cache_poisoning", "open_redirect"],                  "prerequisites": []},
    "ssi_injection":            {"owasp_id": "WSTG-INPV-08", "cwe_ids": ["CWE-97"],            "chains_with": ["rce_detection", "info_disclosure"],                         "prerequisites": []},
    "latex_injection":          {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-74"],            "chains_with": ["rce_detection", "path_traversal"],                          "prerequisites": []},
    "expression_language_injection": {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-917"],      "chains_with": ["rce_detection", "ssti"],                                    "prerequisites": []},
    "log4shell":                {"owasp_id": "WSTG-INPV-11", "cwe_ids": ["CWE-917", "CWE-502"],"chains_with": ["rce_detection", "ssrf"],                                   "prerequisites": []},
    "deserialization":          {"owasp_id": "WSTG-INPV-14", "cwe_ids": ["CWE-502"],           "chains_with": ["rce_detection", "auth_bypass"],                             "prerequisites": []},
    "grpc_injection":           {"owasp_id": "WSTG-INPV-05", "cwe_ids": ["CWE-74"],            "chains_with": ["sqli", "command_injection"],                                "prerequisites": ["api_inventory"]},
    "argv_injection":           {"owasp_id": "WSTG-INPV-12", "cwe_ids": ["CWE-88"],            "chains_with": ["command_injection", "rce_detection"],                       "prerequisites": []},
    "rce_detection":            {"owasp_id": "WSTG-INPV-12", "cwe_ids": ["CWE-78", "CWE-94"], "chains_with": [],                                                           "prerequisites": []},
    "second_order":             {"owasp_id": "WSTG-INPV-05", "cwe_ids": ["CWE-74"],            "chains_with": ["sqli", "xss", "ssti"],                                     "prerequisites": ["sqli", "xss"]},

    # ── XSS / Client-side injection ──────────────────────────────────────────
    "xss":                      {"owasp_id": "WSTG-INPV-01", "cwe_ids": ["CWE-79"],            "chains_with": ["csrf", "session_security", "open_redirect"],                "prerequisites": []},
    "dom_xss":                  {"owasp_id": "WSTG-INPV-02", "cwe_ids": ["CWE-79"],            "chains_with": ["oauth", "csrf", "session_security"],                        "prerequisites": []},
    "dom_clobbering":           {"owasp_id": "WSTG-CLNT-11", "cwe_ids": ["CWE-79"],            "chains_with": ["dom_xss", "xss"],                                          "prerequisites": []},
    "dom_clobbering_2024":      {"owasp_id": "WSTG-CLNT-11", "cwe_ids": ["CWE-79"],            "chains_with": ["dom_xss", "xss"],                                          "prerequisites": []},
    "css_injection":            {"owasp_id": "WSTG-CLNT-05", "cwe_ids": ["CWE-79"],            "chains_with": ["xss", "info_disclosure"],                                   "prerequisites": []},
    "dangling_markup":          {"owasp_id": "WSTG-CLNT-12", "cwe_ids": ["CWE-79"],            "chains_with": ["dom_xss", "xss", "info_disclosure"],                       "prerequisites": []},
    "prototype_pollution":      {"owasp_id": "WSTG-CLNT-13", "cwe_ids": ["CWE-1321"],          "chains_with": ["dom_xss", "xss", "auth_bypass"],                           "prerequisites": []},
    "client_side_messaging":    {"owasp_id": "WSTG-CLNT-11", "cwe_ids": ["CWE-345"],           "chains_with": ["dom_xss", "xss"],                                          "prerequisites": []},
    "client_side_path_traversal": {"owasp_id": "WSTG-CLNT-13", "cwe_ids": ["CWE-22"],          "chains_with": ["ssrf", "idor"],                                             "prerequisites": []},
    "client_side_request":      {"owasp_id": "WSTG-CLNT-13", "cwe_ids": ["CWE-918"],           "chains_with": ["ssrf", "cors"],                                             "prerequisites": []},
    "pdf_injection":            {"owasp_id": "WSTG-INPV-01", "cwe_ids": ["CWE-79"],            "chains_with": ["xss", "ssrf"],                                              "prerequisites": []},
    "esi_injection":            {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-74"],            "chains_with": ["xss", "ssrf", "cache_poisoning"],                          "prerequisites": []},
    "sse_injection":            {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-74"],            "chains_with": ["xss", "info_disclosure"],                                   "prerequisites": []},
    "relative_path_overwrite":  {"owasp_id": "WSTG-CLNT-13", "cwe_ids": ["CWE-79"],            "chains_with": ["xss", "css_injection"],                                    "prerequisites": []},
    "reflected_file_download":  {"owasp_id": "WSTG-CLNT-13", "cwe_ids": ["CWE-74"],            "chains_with": ["xss", "command_injection"],                                "prerequisites": []},
    "service_worker_attacks":   {"owasp_id": "WSTG-CLNT-13", "cwe_ids": ["CWE-349"],           "chains_with": ["xss", "dom_xss"],                                          "prerequisites": []},

    # ── SSRF ─────────────────────────────────────────────────────────────────
    "ssrf":                     {"owasp_id": "WSTG-INPV-19", "cwe_ids": ["CWE-918"],           "chains_with": ["cloud_webapp", "info_disclosure", "rce_detection"],         "prerequisites": []},
    "ssrf_bypass":              {"owasp_id": "WSTG-INPV-19", "cwe_ids": ["CWE-918"],           "chains_with": ["ssrf", "cloud_webapp"],                                     "prerequisites": ["ssrf"]},
    "ssrf_protocol":            {"owasp_id": "WSTG-INPV-19", "cwe_ids": ["CWE-918"],           "chains_with": ["ssrf", "rce_detection"],                                    "prerequisites": ["ssrf"]},
    "edge_worker_ssrf":         {"owasp_id": "WSTG-INPV-19", "cwe_ids": ["CWE-918"],           "chains_with": ["ssrf", "cloud_webapp"],                                     "prerequisites": []},
    "dns_rebinding":            {"owasp_id": "WSTG-INPV-19", "cwe_ids": ["CWE-350"],           "chains_with": ["ssrf", "ssrf_bypass", "cloud_webapp"],                     "prerequisites": []},

    # ── Authentication ───────────────────────────────────────────────────────
    "auth_bypass":              {"owasp_id": "WSTG-ATHN-04", "cwe_ids": ["CWE-287"],           "chains_with": ["idor", "access_control"],                                   "prerequisites": ["authentication"]},
    "authentication":           {"owasp_id": "WSTG-ATHN-01", "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "mfa_bypass"],                                "prerequisites": []},
    "default_credentials":      {"owasp_id": "WSTG-ATHN-02", "cwe_ids": ["CWE-798"],           "chains_with": ["auth_bypass"],                                              "prerequisites": []},
    "mfa_bypass":               {"owasp_id": "WSTG-ATHN-11", "cwe_ids": ["CWE-308"],           "chains_with": ["auth_bypass", "oauth"],                                     "prerequisites": ["authentication"]},
    "webauthn_passkey":         {"owasp_id": "WSTG-ATHN-11", "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "mfa_bypass"],                                "prerequisites": ["authentication"]},
    "jwt":                      {"owasp_id": "WSTG-ATHN-10", "cwe_ids": ["CWE-347"],           "chains_with": ["idor", "auth_bypass", "info_disclosure"],                   "prerequisites": []},
    "oauth":                    {"owasp_id": "WSTG-ATHN-05", "cwe_ids": ["CWE-287"],           "chains_with": ["open_redirect", "csrf", "subdomain_takeover"],              "prerequisites": []},
    "oauth_device_flow":        {"owasp_id": "WSTG-ATHN-05", "cwe_ids": ["CWE-287"],           "chains_with": ["oauth", "csrf"],                                            "prerequisites": ["oauth"]},
    "oauth_dpop_confused_deputy": {"owasp_id": "WSTG-ATHN-05", "cwe_ids": ["CWE-441"],         "chains_with": ["oauth"],                                                    "prerequisites": ["oauth"]},
    "saml":                     {"owasp_id": "WSTG-ATHN-05", "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "xxe"],                                       "prerequisites": []},
    "php_type_juggling":        {"owasp_id": "WSTG-ATHN-04", "cwe_ids": ["CWE-843"],           "chains_with": ["auth_bypass"],                                              "prerequisites": []},
    "captcha_bypass":           {"owasp_id": "WSTG-ATHN-03", "cwe_ids": ["CWE-804"],           "chains_with": ["auth_bypass"],                                              "prerequisites": ["authentication"]},

    # ── Authorization ────────────────────────────────────────────────────────
    "access_control":           {"owasp_id": "WSTG-ATHZ-02", "cwe_ids": ["CWE-285"],           "chains_with": ["idor", "auth_bypass"],                                      "prerequisites": ["authentication"]},
    "idor":                     {"owasp_id": "WSTG-ATHZ-04", "cwe_ids": ["CWE-639"],           "chains_with": ["mass_assignment", "business_logic", "info_disclosure"],     "prerequisites": ["authentication"]},
    "mass_assignment":          {"owasp_id": "WSTG-ATHZ-03", "cwe_ids": ["CWE-915"],           "chains_with": ["idor", "auth_bypass"],                                      "prerequisites": ["api_inventory"]},

    # ── Session management ───────────────────────────────────────────────────
    "session_security":         {"owasp_id": "WSTG-SESS-01", "cwe_ids": ["CWE-613"],           "chains_with": ["xss", "csrf"],                                              "prerequisites": ["authentication"]},
    "session_fixation":         {"owasp_id": "WSTG-SESS-03", "cwe_ids": ["CWE-384"],           "chains_with": ["xss", "auth_bypass"],                                       "prerequisites": ["authentication"]},
    "session_puzzling":         {"owasp_id": "WSTG-SESS-08", "cwe_ids": ["CWE-384"],           "chains_with": ["auth_bypass", "idor"],                                      "prerequisites": ["authentication"]},
    "csrf":                     {"owasp_id": "WSTG-SESS-05", "cwe_ids": ["CWE-352"],           "chains_with": ["xss", "oauth", "mfa_bypass"],                               "prerequisites": []},
    "cookie_tossing":           {"owasp_id": "WSTG-SESS-02", "cwe_ids": ["CWE-565"],           "chains_with": ["csrf", "session_security", "xss"],                         "prerequisites": []},

    # ── Business logic ───────────────────────────────────────────────────────
    "business_logic":           {"owasp_id": "WSTG-BUSL-01", "cwe_ids": ["CWE-840"],           "chains_with": ["race_condition", "idor", "payment_flow"],                   "prerequisites": ["authentication"]},
    "race_condition":           {"owasp_id": "WSTG-BUSL-07", "cwe_ids": ["CWE-362"],           "chains_with": ["business_logic", "payment_flow"],                           "prerequisites": []},
    "state_machine_race":       {"owasp_id": "WSTG-BUSL-07", "cwe_ids": ["CWE-362"],           "chains_with": ["race_condition", "business_logic"],                         "prerequisites": []},
    "payment_flow":             {"owasp_id": "WSTG-BUSL-09", "cwe_ids": ["CWE-840"],           "chains_with": ["business_logic", "race_condition", "idor"],                 "prerequisites": ["authentication"]},
    "banking_finance":          {"owasp_id": "WSTG-BUSL-09", "cwe_ids": ["CWE-840"],           "chains_with": ["payment_flow", "idor", "race_condition"],                   "prerequisites": ["authentication"]},

    # ── File / path ──────────────────────────────────────────────────────────
    "path_traversal":           {"owasp_id": "WSTG-INPV-10", "cwe_ids": ["CWE-22"],            "chains_with": ["info_disclosure", "rce_detection"],                         "prerequisites": []},
    "file_upload":              {"owasp_id": "WSTG-INPV-13", "cwe_ids": ["CWE-434"],           "chains_with": ["rce_detection", "xss"],                                     "prerequisites": []},
    "zip_slip":                 {"owasp_id": "WSTG-INPV-13", "cwe_ids": ["CWE-22"],            "chains_with": ["file_upload", "path_traversal"],                            "prerequisites": ["file_upload"]},

    # ── Config / info disclosure ─────────────────────────────────────────────
    "info_disclosure":          {"owasp_id": "WSTG-INFO-02", "cwe_ids": ["CWE-200"],           "chains_with": ["jwt", "ssrf", "idor", "auth_bypass"],                       "prerequisites": []},
    "error_handling_misuse":    {"owasp_id": "WSTG-ERRH-01", "cwe_ids": ["CWE-209"],           "chains_with": ["info_disclosure", "idor", "auth_bypass"],                   "prerequisites": []},
    "exposed_panels":           {"owasp_id": "WSTG-INFO-05", "cwe_ids": ["CWE-200"],           "chains_with": ["default_credentials", "auth_bypass"],                       "prerequisites": []},
    "source_code_exposure":     {"owasp_id": "WSTG-INFO-05", "cwe_ids": ["CWE-540"],           "chains_with": ["info_disclosure", "auth_bypass"],                           "prerequisites": []},
    "excessive_data_exposure":  {"owasp_id": "WSTG-INFO-02", "cwe_ids": ["CWE-200"],           "chains_with": ["idor", "info_disclosure"],                                  "prerequisites": []},
    "exposure_osint":           {"owasp_id": "WSTG-INFO-01", "cwe_ids": ["CWE-200"],           "chains_with": ["info_disclosure", "subdomain_takeover"],                    "prerequisites": []},
    "browser_storage":          {"owasp_id": "WSTG-CLNT-12", "cwe_ids": ["CWE-922"],           "chains_with": ["xss", "info_disclosure"],                                   "prerequisites": []},

    # ── HTTP transport / smuggling ───────────────────────────────────────────
    "request_smuggling":        {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-444"],           "chains_with": ["cache_poisoning", "auth_bypass", "xss"],                    "prerequisites": []},
    "http_desync":              {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-444"],           "chains_with": ["request_smuggling", "cache_poisoning"],                     "prerequisites": []},
    "http_response_smuggling":  {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-444"],           "chains_with": ["request_smuggling", "xss"],                                 "prerequisites": []},
    "request_splitting":        {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-113"],           "chains_with": ["request_smuggling", "cache_poisoning"],                     "prerequisites": []},
    "h2c_smuggling":            {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-444"],           "chains_with": ["request_smuggling", "auth_bypass"],                         "prerequisites": []},
    "h2_continuation_flood":    {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-400"],           "chains_with": ["resource_exhaustion"],                                      "prerequisites": []},
    "http2_connect_portscan":   {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-918"],           "chains_with": ["ssrf"],                                                     "prerequisites": []},
    "http3_quic":               {"owasp_id": "WSTG-CONF-10", "cwe_ids": ["CWE-757"],           "chains_with": [],                                                           "prerequisites": []},
    "http_methods_enum":        {"owasp_id": "WSTG-CONF-06", "cwe_ids": ["CWE-749"],           "chains_with": ["cors", "host_header", "xss"],                               "prerequisites": []},

    # ── Cache attacks ────────────────────────────────────────────────────────
    "cache_poisoning":          {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-349"],           "chains_with": ["host_header", "request_smuggling", "xss"],                  "prerequisites": []},
    "web_cache_deception":      {"owasp_id": "WSTG-ATHN-06", "cwe_ids": ["CWE-525"],           "chains_with": ["idor", "info_disclosure", "auth_bypass"],                   "prerequisites": []},
    "web_cache_poisoning_dos":  {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-349"],           "chains_with": ["cache_poisoning", "host_header"],                           "prerequisites": []},
    "nextjs_cache_poisoning":   {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-349"],           "chains_with": ["cache_poisoning", "info_disclosure"],                       "prerequisites": []},

    # ── CORS / headers ───────────────────────────────────────────────────────
    "cors":                     {"owasp_id": "WSTG-CLNT-07", "cwe_ids": ["CWE-942"],           "chains_with": ["csrf", "idor", "info_disclosure"],                          "prerequisites": []},
    "host_header":              {"owasp_id": "WSTG-INPV-17", "cwe_ids": ["CWE-644"],           "chains_with": ["cache_poisoning", "ssrf", "open_redirect"],                "prerequisites": []},
    "response_header_injection": {"owasp_id": "WSTG-INPV-15", "cwe_ids": ["CWE-113"],          "chains_with": ["crlf_injection", "xss", "cache_poisoning"],                "prerequisites": []},
    "hpp":                      {"owasp_id": "WSTG-INPV-04", "cwe_ids": ["CWE-235"],           "chains_with": ["auth_bypass", "sqli", "xss"],                               "prerequisites": []},
    "content_type_confusion":   {"owasp_id": "WSTG-INPV-16", "cwe_ids": ["CWE-436"],           "chains_with": ["xss", "deserialization"],                                   "prerequisites": []},

    # ── Redirect ─────────────────────────────────────────────────────────────
    "open_redirect":            {"owasp_id": "WSTG-CLNT-04", "cwe_ids": ["CWE-601"],           "chains_with": ["oauth", "xss", "info_disclosure"],                          "prerequisites": []},

    # ── Clickjacking ─────────────────────────────────────────────────────────
    "clickjacking":             {"owasp_id": "WSTG-CLNT-09", "cwe_ids": ["CWE-1021"],          "chains_with": ["csrf"],                                                     "prerequisites": []},

    # ── Crypto ───────────────────────────────────────────────────────────────
    "crypto_weakness":          {"owasp_id": "WSTG-CRYP-04", "cwe_ids": ["CWE-327"],           "chains_with": ["jwt", "oauth", "info_disclosure"],                          "prerequisites": []},
    "insecure_randomness":      {"owasp_id": "WSTG-CRYP-04", "cwe_ids": ["CWE-330"],           "chains_with": ["session_security", "auth_bypass"],                          "prerequisites": []},

    # ── API-specific ─────────────────────────────────────────────────────────
    "api_abuse":                {"owasp_id": "WSTG-APIT-01", "cwe_ids": ["CWE-285"],           "chains_with": ["idor", "auth_bypass", "mass_assignment"],                   "prerequisites": ["api_inventory"]},
    "api_inventory":            {"owasp_id": "WSTG-APIT-01", "cwe_ids": ["CWE-200"],           "chains_with": ["info_disclosure"],                                          "prerequisites": []},
    "graphql":                  {"owasp_id": "WSTG-APIT-01", "cwe_ids": ["CWE-200"],           "chains_with": ["sqli", "idor", "info_disclosure"],                          "prerequisites": []},
    "graphql_engines":          {"owasp_id": "WSTG-APIT-01", "cwe_ids": ["CWE-200"],           "chains_with": ["graphql", "sqli"],                                          "prerequisites": ["graphql"]},
    "websocket":                {"owasp_id": "WSTG-APIT-02", "cwe_ids": ["CWE-345"],           "chains_with": ["xss", "sqli", "idor"],                                      "prerequisites": []},
    "orm_leak":                 {"owasp_id": "WSTG-INPV-05", "cwe_ids": ["CWE-89"],            "chains_with": ["sqli", "idor", "mass_assignment"],                          "prerequisites": []},
    "trpc_sspp":                {"owasp_id": "WSTG-APIT-01", "cwe_ids": ["CWE-74"],            "chains_with": ["prototype_pollution", "sqli"],                              "prerequisites": []},
    "scim_provisioning":        {"owasp_id": "WSTG-APIT-01", "cwe_ids": ["CWE-285"],           "chains_with": ["idor", "mass_assignment"],                                   "prerequisites": ["authentication"]},

    # ── Cloud ────────────────────────────────────────────────────────────────
    "cloud_webapp":             {"owasp_id": "",              "cwe_ids": ["CWE-16"],            "chains_with": ["ssrf", "info_disclosure"],                                  "prerequisites": []},
    "cloud_storage_misconfig":  {"owasp_id": "",              "cwe_ids": ["CWE-284"],           "chains_with": ["info_disclosure"],                                          "prerequisites": []},
    "cloud_function_url":       {"owasp_id": "",              "cwe_ids": ["CWE-284"],           "chains_with": ["ssrf", "auth_bypass"],                                      "prerequisites": []},
    "cloud_api_gateway":        {"owasp_id": "",              "cwe_ids": ["CWE-284"],           "chains_with": ["auth_bypass", "info_disclosure"],                           "prerequisites": []},
    "anon_cloud_expansion":     {"owasp_id": "",              "cwe_ids": ["CWE-284"],           "chains_with": ["cloud_storage_misconfig", "info_disclosure"],               "prerequisites": []},

    # ── LLM / AI ─────────────────────────────────────────────────────────────
    "ai_prompt_injection":      {"owasp_id": "",              "cwe_ids": ["CWE-74"],            "chains_with": ["llm_tool_abuse", "info_disclosure"],                        "prerequisites": []},
    "web_llm":                  {"owasp_id": "",              "cwe_ids": ["CWE-74"],            "chains_with": ["ai_prompt_injection", "ssrf"],                              "prerequisites": []},
    "llm_fingerprinting":       {"owasp_id": "",              "cwe_ids": ["CWE-200"],           "chains_with": ["ai_prompt_injection", "web_llm"],                           "prerequisites": []},
    "llm_tool_abuse":           {"owasp_id": "",              "cwe_ids": ["CWE-285"],           "chains_with": ["ai_prompt_injection", "mcp_tool_poisoning"],                "prerequisites": []},
    "rag_injection":            {"owasp_id": "",              "cwe_ids": ["CWE-74"],            "chains_with": ["ai_prompt_injection", "info_disclosure"],                   "prerequisites": []},
    "vector_db_injection":      {"owasp_id": "",              "cwe_ids": ["CWE-74"],            "chains_with": ["rag_injection", "ai_prompt_injection"],                     "prerequisites": []},
    "echoleak":                 {"owasp_id": "",              "cwe_ids": ["CWE-200"],           "chains_with": ["ai_prompt_injection", "info_disclosure"],                   "prerequisites": []},

    # ── MCP / A2A ────────────────────────────────────────────────────────────
    "mcp_server_attacks":       {"owasp_id": "",              "cwe_ids": ["CWE-74"],            "chains_with": ["ai_prompt_injection", "ssrf"],                              "prerequisites": []},
    "mcp_tool_poisoning":       {"owasp_id": "",              "cwe_ids": ["CWE-74"],            "chains_with": ["mcp_server_attacks", "ai_prompt_injection"],                "prerequisites": []},
    "a2a_protocol":             {"owasp_id": "",              "cwe_ids": ["CWE-74"],            "chains_with": ["mcp_server_attacks", "ai_prompt_injection", "ssrf"],        "prerequisites": []},

    # ── DoS / resource ───────────────────────────────────────────────────────
    "resource_exhaustion":      {"owasp_id": "WSTG-BUSL-06", "cwe_ids": ["CWE-400"],           "chains_with": ["redos"],                                                    "prerequisites": []},
    "redos":                    {"owasp_id": "WSTG-BUSL-06", "cwe_ids": ["CWE-1333"],          "chains_with": ["resource_exhaustion"],                                      "prerequisites": []},

    # ── Infrastructure config ────────────────────────────────────────────────
    "reverse_proxy_misconfig":  {"owasp_id": "WSTG-CONF-05", "cwe_ids": ["CWE-16"],            "chains_with": ["auth_bypass", "ssrf", "path_traversal"],                    "prerequisites": []},
    "webdav_misconfig":         {"owasp_id": "WSTG-CONF-06", "cwe_ids": ["CWE-16"],            "chains_with": ["file_upload", "path_traversal"],                            "prerequisites": []},
    "waf_bypass_40x":           {"owasp_id": "WSTG-CONF-05", "cwe_ids": ["CWE-693"],           "chains_with": ["path_traversal", "auth_bypass"],                            "prerequisites": []},
    "parser_differential":      {"owasp_id": "WSTG-CONF-05", "cwe_ids": ["CWE-436"],           "chains_with": ["auth_bypass", "path_traversal"],                            "prerequisites": []},
    "unicode_normalization":    {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-176"],           "chains_with": ["auth_bypass", "xss", "path_traversal"],                    "prerequisites": []},

    # ── Subdomain / DNS ──────────────────────────────────────────────────────
    "subdomain_takeover":       {"owasp_id": "WSTG-CONF-10", "cwe_ids": ["CWE-284"],           "chains_with": ["oauth", "xss", "cors"],                                     "prerequisites": []},

    # ── Supply chain / dependency ────────────────────────────────────────────
    "dependency_confusion":     {"owasp_id": "",              "cwe_ids": ["CWE-427"],           "chains_with": ["rce_detection"],                                            "prerequisites": []},
    "unsafe_consumption":       {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-829"],           "chains_with": ["ssrf", "deserialization"],                                  "prerequisites": []},

    # ── CI/CD ────────────────────────────────────────────────────────────────
    "ci_actions_injection":     {"owasp_id": "",              "cwe_ids": ["CWE-78"],            "chains_with": ["rce_detection"],                                            "prerequisites": []},
    "cicd_exposure":            {"owasp_id": "",              "cwe_ids": ["CWE-200"],           "chains_with": ["ci_actions_injection", "info_disclosure"],                  "prerequisites": []},

    # ── Mobile ───────────────────────────────────────────────────────────────
    "mobile_api":               {"owasp_id": "",              "cwe_ids": ["CWE-285"],           "chains_with": ["idor", "auth_bypass"],                                      "prerequisites": []},
    "mobile_deeplink":          {"owasp_id": "",              "cwe_ids": ["CWE-939"],           "chains_with": ["open_redirect", "auth_bypass"],                             "prerequisites": []},
    "webview_injection":        {"owasp_id": "",              "cwe_ids": ["CWE-79"],            "chains_with": ["dom_xss", "xss"],                                           "prerequisites": []},
    "push_notification":        {"owasp_id": "",              "cwe_ids": ["CWE-345"],           "chains_with": ["info_disclosure"],                                          "prerequisites": []},

    # ── Desktop ──────────────────────────────────────────────────────────────
    "desktop_electron":         {"owasp_id": "",              "cwe_ids": ["CWE-829"],           "chains_with": ["xss", "rce_detection"],                                     "prerequisites": []},

    # ── Kubernetes / container ───────────────────────────────────────────────
    "kubernetes_exposed":       {"owasp_id": "",              "cwe_ids": ["CWE-284"],           "chains_with": ["cloud_webapp", "rce_detection"],                            "prerequisites": []},

    # ── Webhook / callback ───────────────────────────────────────────────────
    "webhook_replay":           {"owasp_id": "WSTG-BUSL-01", "cwe_ids": ["CWE-345"],           "chains_with": ["business_logic", "race_condition"],                         "prerequisites": []},

    # ── CSV injection ────────────────────────────────────────────────────────
    "csv_injection":            {"owasp_id": "WSTG-INPV-01", "cwe_ids": ["CWE-1236"],          "chains_with": ["file_upload", "command_injection"],                         "prerequisites": []},

    # ── Vendor-specific ──────────────────────────────────────────────────────
    "wordpress":                {"owasp_id": "WSTG-CONF-11", "cwe_ids": ["CWE-16"],            "chains_with": ["auth_bypass", "file_upload", "sqli"],                       "prerequisites": []},
    "atlassian_confluence":     {"owasp_id": "",              "cwe_ids": ["CWE-74"],            "chains_with": ["rce_detection", "auth_bypass"],                             "prerequisites": []},
    "citrix_netscaler":         {"owasp_id": "",              "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "rce_detection"],                             "prerequisites": []},
    "crushftp":                 {"owasp_id": "",              "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "path_traversal"],                            "prerequisites": []},
    "exchange_owa":             {"owasp_id": "",              "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "ssrf"],                                      "prerequisites": []},
    "f5_bigip":                 {"owasp_id": "",              "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "rce_detection"],                             "prerequisites": []},
    "geoserver":                {"owasp_id": "",              "cwe_ids": ["CWE-89"],            "chains_with": ["sqli", "rce_detection"],                                    "prerequisites": []},
    "ivanti":                   {"owasp_id": "",              "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "rce_detection"],                             "prerequisites": []},
    "log4shell":                {"owasp_id": "WSTG-INPV-11", "cwe_ids": ["CWE-917", "CWE-502"],"chains_with": ["rce_detection", "ssrf"],                                   "prerequisites": []},
    "moveit_transfer":          {"owasp_id": "",              "cwe_ids": ["CWE-89"],            "chains_with": ["sqli", "auth_bypass"],                                      "prerequisites": []},
    "panos_globalprotect":      {"owasp_id": "",              "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "command_injection"],                         "prerequisites": []},
    "smartermail":              {"owasp_id": "",              "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "xss"],                                       "prerequisites": []},
    "sonicwall_sslvpn":         {"owasp_id": "",              "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "rce_detection"],                             "prerequisites": []},
    "teamcity":                 {"owasp_id": "",              "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass", "rce_detection"],                             "prerequisites": []},
    "windows_admin_center":     {"owasp_id": "",              "cwe_ids": ["CWE-287"],           "chains_with": ["auth_bypass"],                                              "prerequisites": []},
    "tech_vulns":               {"owasp_id": "WSTG-INFO-08", "cwe_ids": ["CWE-16"],            "chains_with": ["info_disclosure"],                                          "prerequisites": []},
    "soapwn":                   {"owasp_id": "",              "cwe_ids": ["CWE-502"],           "chains_with": ["rce_detection", "deserialization"],                         "prerequisites": []},

    # ── Framework-specific ───────────────────────────────────────────────────
    "react_server_components":  {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-74"],            "chains_with": ["ssrf", "info_disclosure"],                                  "prerequisites": []},
    "sveltekit":                {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-74"],            "chains_with": ["dom_xss", "ssrf", "csrf"],                                 "prerequisites": []},
    "nuxt":                     {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-74"],            "chains_with": ["ssrf", "idor", "dom_xss"],                                 "prerequisites": []},
    # ── XS-Leak family ───────────────────────────────────────────────────────
    "xs_leak":                  {"owasp_id": "WSTG-CLNT-13", "cwe_ids": ["CWE-203"],           "chains_with": ["info_disclosure", "idor"],                                  "prerequisites": []},
    "xsleak_redirect":          {"owasp_id": "WSTG-CLNT-13", "cwe_ids": ["CWE-203"],           "chains_with": ["xs_leak", "open_redirect"],                                 "prerequisites": []},
    "etag_xsleak":              {"owasp_id": "WSTG-CLNT-13", "cwe_ids": ["CWE-203"],           "chains_with": ["xs_leak", "info_disclosure"],                               "prerequisites": []},

    # ── XSLT ─────────────────────────────────────────────────────────────────
    "xslt_injection":           {"owasp_id": "WSTG-INPV-18", "cwe_ids": ["CWE-74"],            "chains_with": ["xxe", "rce_detection"],                                     "prerequisites": []},

    # ── CSPP ─────────────────────────────────────────────────────────────────
    "cspp":                     {"owasp_id": "WSTG-CLNT-13", "cwe_ids": ["CWE-74"],            "chains_with": ["dom_xss", "prototype_pollution"],                           "prerequisites": []},
}

# Categories that may appear in KB files but are not in the map (child variants,
# aliases). The generator falls back to the parent mapping by prefix.
# Example: struts2_ognl → try "struts2_ognl", if missing try removing trailing
# segments until a match is found, or flag as unmapped.

# fmt: on
