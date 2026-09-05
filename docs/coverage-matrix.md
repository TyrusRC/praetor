# Praetor Coverage Matrix (WSTG v4.2 × OWASP Top 10)

Generated 2026-09-05. Method: cross-reference of `knowledge/_INDEX.md` (153 KB
categories), the `@mcp.tool()` inventory (`grep -rhoP 'async def \K\w+'
mcp-server/src/praetor/tools`), and `.claude/skills/playbook-*.md`. Regenerate
after KB or tool changes. "Gap/Thin" flags a category with no dedicated
probe/tool/playbook.

KB files live under `mcp-server/src/praetor/knowledge/`. Tools are MCP tool
names. Playbooks are `.claude/skills/playbook-<name>.md`.

## OWASP WSTG v4.2

| WSTG category | KB file(s) | Native tool(s) | Playbook(s) | Gap/Thin |
|---|---|---|---|---|
| INFO — Information Gathering | `info_disclosure`, `source_code_exposure`, `api_inventory`, `http_methods_enum` | `discover_attack_surface`, `detect_tech_stack`, `extract_js_secrets`, `analyze_dns`, `analyze_artifact` (offline) | `smart-move-fresh-target`, `recon-takeover` | — |
| CONF — Configuration & Deploy | `webdav_misconfig`, `cors`, `host_header`, `http_methods_enum`, `error_handling_misuse` | `test_host_header`, `discover_common_files` | `playbook-router` | — |
| IDNT — Identity Management | `authentication`, `api_inventory` | `test_auth_matrix`, `parse_api_schema` | `playbook-idor-bola` | — |
| ATHN — Authentication | `auth_bypass`, `jwt`, `oauth`, `oauth_device_flow`, `oauth_dpop_confused_deputy`, `saml`, `webauthn_passkey` | `test_login_bypass`, `test_mfa_bypass`, `forge_jwt`, `crack_jwt_secret`, `analyze_reset_tokens`, `oauth_flow_simulator`, `oauth_device_flow_simulator`, `oauth_hybrid_flow_simulator`, `oauth_dpop_audit`, `probe_passkey_stepup_bypass` | `playbook-oauth-flow-attacks`, `playbook-jwt-deep-dive`, `playbook-saml-xsw`, `playbook-payment-and-auth` | — |
| ATHZ — Authorization | `access_control`, `idor`, `mass_assignment` | `test_auth_matrix`, `test_mass_assignment`, `probe_cross_transport_idor`, `probe_id_monotonic` | `playbook-idor-bola` | — |
| SESS — Session Management | `session_security`, `session_puzzling`, `csrf` | `test_session_lifecycle`, `test_csrf` | `playbook-idor-bola` (BOLA/session) | — |
| INPV — Input Validation | `sqli`(+`_blind`,`_engines`), `xss`, `dom_xss`, `xxe`, `ssti`(6 langs), `command_injection`, `ldap_injection`, `xpath_injection`, `xslt_injection`, `ssi_injection`, `nosql`, `crlf_injection`, `host_header`, `hpp`, `open_redirect`, `path_traversal`, `orm_leak`, `email_injection`, `json_injection`, `xml_injection` | `auto_probe`, `test_ssti`, `test_xxe`, `test_ssrf`, `test_crlf_injection`, `test_parameter_pollution`, `confirm_sqli`, `confirm_ssrf`, `confirm_ssti`, `confirm_rce`, `confirm_xxe`, `fuzz_parameter` | `playbook-ssrf-deep-dive`, `playbook-pollution` | — |
| ERRH — Error Handling | `error_handling_misuse`, `info_disclosure` | (`auto_probe` matchers) | — | — |
| CRYP — Cryptography | `crypto_weakness`, `insecure_randomness` | `analyze_reset_tokens` (entropy) | — | — |
| BUSL — Business Logic | `business_logic`, `payment_flow`, `race_condition`, `state_machine_race` | `test_business_logic`, `test_race_condition`, `infer_business_invariants`, `probe_line_item_mutation`, `probe_idempotency_key`, `probe_quota_window_edge`, `probe_float_decimal_rounding`, `probe_workflow_reorder`, `probe_cron_backfill`, `probe_role_state_cleanup` | `playbook-business-logic`, `playbook-payment-and-auth` | — |
| CLNT — Client-Side | `dom_xss`, `cspp`, `dom_clobbering`(+`_2024`), `client_side_path_traversal`, `client_side_messaging`, `dangling_markup`, `relative_path_overwrite`, `browser_storage`, `service_worker_attacks`, `clickjacking` | `test_prototype_pollution`, `analyze_dom`, `audit_crawled_artifacts` | `playbook-prototype-pollution`, `playbook-pollution` | — |
| APIT — API Testing | `api_abuse`, `api_inventory`, `excessive_data_exposure`, `graphql`(+`_engines`), `grpc_injection`, `mobile_api`, `scim_provisioning`, `webhook_replay` | `parse_api_schema`, `test_mass_assignment`, `batch_probe`, `probe_apollo_sdl_leak`, `probe_graphql_csrf` | `playbook-api-advanced`, `playbook-graphql-deep`, `playbook-mobile-backend` | — |

## OWASP Web Top 10 (2021)

| Item | Coverage |
|---|---|
| A01 Broken Access Control | `access_control`, `idor`, `mass_assignment`; `test_auth_matrix`; `playbook-idor-bola` |
| A02 Cryptographic Failures | `crypto_weakness`, `insecure_randomness` |
| A03 Injection | full INPV row above |
| A04 Insecure Design | `business_logic`, `state_machine_race`; `playbook-business-logic` |
| A05 Security Misconfiguration | `cors`, `host_header`, `webdav_misconfig`, `http_methods_enum` |
| A06 Vulnerable Components | `tech_vulns`, product CVEs (`log4shell`, `citrix_netscaler`, `f5_bigip`, `ivanti`, `moveit_transfer`, `exchange_owa`, `panos_globalprotect`, `sonicwall_sslvpn`, `crushftp`, `geoserver`, `teamcity`, `atlassian_confluence`); `lookup_cve`, `probe_cve_with_variants`; `playbook-cve-research` |
| A07 Auth Failures | full ATHN row above |
| A08 Integrity Failures | `deserialization`, `insecure_deserialization`, `dependency_confusion`, `ci_actions_injection`; `playbook-deserialization` |
| A09 Logging/Monitoring | out of DAST scope (recorded, not probed) |
| A10 SSRF | `ssrf`(+`_bypass`,`_protocol`), `edge_worker_ssrf`; `test_ssrf`, `confirm_ssrf`; `playbook-ssrf-deep-dive` |

## OWASP API Top 10 (2023)

| Item | Coverage |
|---|---|
| API1 BOLA | `idor`; `test_auth_matrix`, `probe_cross_transport_idor` |
| API2 Broken Auth | ATHN row |
| API3 BOPLA | `mass_assignment`, `excessive_data_exposure`; `test_mass_assignment`, `probe_bopla` |
| API4 Resource Consumption | `resource_exhaustion`, `redos`; `test_rate_limit` |
| API5 BFLA | `access_control`; `test_auth_matrix` |
| API6 Sensitive Business Flows | `business_logic`; `test_business_logic` |
| API7 SSRF | A10 above |
| API8 Misconfiguration | CONF row |
| API9 Inventory | `api_inventory`; `parse_api_schema`, `analyze_artifact` |
| API10 Unsafe Consumption | `unsafe_consumption` |

## OWASP LLM Top 10 (2025) + MCP

| Item | Coverage |
|---|---|
| LLM01 Prompt Injection | `ai_prompt_injection`, `web_llm`; `inspect_for_prompt_injection` |
| LLM/RAG | `rag_injection`, `vector_db_injection` |
| MCP attack surface | `mcp_server_attacks`, `mcp_tool_poisoning`; `probe_mcp_server_attacks`, `enumerate_mcp_server`, `detect_mcp_schema_drift`, `claude_code_hook_scanner` |
| Agent protocols | `a2a_protocol`; `a2a_agent_card_probe` |
| Data exfil (CVE) | `echoleak` (CVE-2025-32711) |

## PortSwigger Top 10 of 2025 (W7 additions)

| Item | KB | Status |
|---|---|---|
| HTTP/2 CONNECT port scan | `http2_connect_portscan` | ref-only (raw H2) |
| ETag XS-Leak | `etag_xsleak` | active |
| XS-Leak redirect | `xsleak_redirect` | active |
| Parser differential | `parser_differential` | active |
| SOAP client RCE | `soapwn` | ref-only (attacker WSDL) |

## Notes

- **No missing mainstream web vuln class** was found in this audit. The gaps
  addressed in the 2026-09-05 enhancement were workflow rigor (autopilot
  validation gate / impact-first ordering) and offline artifact ingestion
  (`analyze_artifact`), not vuln-class coverage.
- A09 (logging/monitoring) is intentionally out of DAST scope — observable from
  the outside only indirectly; recorded, not hunted (Rule 29).
- Product-CVE KB files (Citrix/F5/Ivanti/MOVEit/Exchange/PAN-OS/SonicWall/
  CrushFTP/GeoServer/TeamCity/Confluence) back A06; extend via `lookup_cve` +
  `probe_cve_with_variants` (`playbook-cve-research`).
