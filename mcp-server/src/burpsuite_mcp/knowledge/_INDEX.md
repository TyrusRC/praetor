# Knowledge Base Index

**137 knowledge files** under `mcp-server/src/burpsuite_mcp/knowledge/`. Each is a JSON file with probe contexts loadable via `auto_probe(categories=[...])`.

## Prefix-matching loader

`auto_probe(categories=['ssti'])` loads `ssti.json` AND any `ssti_*.json` split file. This lets large categories live in multiple smaller files without changing the caller API.

Split categories:
- `ssti` → `ssti.json` + `ssti_python.json`, `ssti_java.json`, `ssti_js.json`, `ssti_php.json`
- `sqli` → `sqli.json` + `sqli_blind.json`, `sqli_engines.json`
- `ssrf` → `ssrf.json` + `ssrf_bypass.json`, `ssrf_protocol.json`
- `graphql` → `graphql.json` + `graphql_engines.json`
- `cloud` → `cloud_webapp.json` + `cloud_storage_misconfig.json`, `cloud_function_url.json`, `cloud_api_gateway.json`

**Reference-only (manual tooling, not auto-probed):** captcha_bypass, ci_actions_injection, clickjacking, csv_injection, dependency_confusion, h2_continuation_flood, http2_connect_portscan, http3_quic, insecure_randomness, kubernetes_exposed, mcp_server_attacks (promoted), mobile_deeplink, race_condition, rag_injection (promoted), request_smuggling, saml_xsw, soapwn, source_code_exposure, tech_vulns, web_cache_deception, web_cache_poisoning_dos, webview_injection, xs_leak, zip_slip

## 2026-05-29 W7 additions (PortSwigger Top 10 of 2025)

| Category | Source | Status | Notes |
|---|---|---|---|
| `http2_connect_portscan` | Top10 / 2025 #9 (flomb) | ref-only | Needs raw H2 CONNECT — use `send_raw_request`. |
| `etag_xsleak` | Top10 / 2025 #6 (Kaneko) | active | Length / hash / If-None-Match oracles. |
| `xsleak_redirect` | Top10 / 2025 #8 (Abello) | active | Connection-pool oracle on cross-origin redirects. |
| `parser_differential` | Top10 / 2025 #10 (joernchen) | active | URL/header/JSON parser disagreement → ACL bypass + privesc. |
| `soapwn` | Top10 / 2025 #5 (Bazydlo) | ref-only | .NET SOAP client + hostile WSDL → RCE; needs attacker-hosted WSDL. |

## How to query

```python
# Load all SSTI knowledge (entry + python + java + js + php):
auto_probe(session, targets, categories=['ssti'])

# Load only Python engines:
auto_probe(session, targets, categories=['ssti_python'])

# Inspect probes for a category:
# Read knowledge/<category>.json directly
```

Top severity = highest probe severity in the category. Tech tags = top auto-trigger keywords.

## Injection (server-side) (23)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `sqli` | error_based, union_detect, generic, waf_bypass | high | apache, asp.net, iis, mssql, mysql |
| `sqli_blind` | blind_boolean, blind_time, oob_exfil | high | mssql, mysql, oracle |
| `sqli_engines` | mysql, postgresql, mssql, oracle, sqlite, nosql | critical | apache, asp.net, django, express, flask |
| `ssti` | detection, generic, golang | high | echo, gin, go, golang |
| `ssti_python` | jinja2, mako | critical | django, flask, pyramid, python, turbogears |
| `ssti_java` | freemarker, thymeleaf, pebble | critical | java, spring, tomcat |
| `ssti_js` | handlebars, nunjucks | critical | express, node.js |
| `ssti_php` | smarty, twig | critical | laravel, php |
| `command_injection` | bash, windows_cmd, blind_oob, filter_bypass | critical | apache, asp.net, flask, iis, nginx |
| `xxe` | file_read, ssrf_via_xxe, blind_oob, error_based, parameter_entity, xinclude (+2) | critical | .net, java, php, soap, wcf |
| `ldap_injection` | auth_bypass, data_extraction, blind_boolean | critical | .net, active directory, java, ldap, openldap |
| `xpath_injection` | auth_bypass, error_based, data_extraction | critical | .net, java, php, soap, xml |
| `xslt_injection` | information_disclosure, rce, ssrf | critical | .net, java, libxslt, php, xml |
| `ssi_injection` | command_execution | critical | apache, iis, nginx |
| `css_injection` | data_exfiltration, attribute_selector_exfil | high | css, html |
| `csv_injection` *(ref-only)* | formula_injection | high | - |
| `latex_injection` | file_read, command_execution, detection | critical | latex, pdf, pdflatex, xelatex |
| `pdf_injection` | ssrf_via_pdf, xss_via_pdf, lfi_via_pdf | critical | dompdf, mpdf, phantomjs, prince, puppeteer |
| `xml_injection` | xpath_via_xml, soap_injection, cdata_breakout, attribute_injection | high | .net, java, php, python, soap |
| `json_injection` | prototype_key_injection, interoperability, json_to_sql | high | deno, express, fastify, java, koa |
| `email_injection` | header_injection, content_injection | high | java, node.js, php, python, ruby |
| `nosql` | mongodb, redis, mongodb_blind, mongodb_auth_bypass, couchdb, cassandra (+1) | critical | cassandra, couchdb, express, java, mean |
| `orm_leak` | django_filter, rails_arel, sequelize_injection | high | django, express, node.js, python, rails |

## Injection (client-side) (9)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `xss` | html, attribute, angular, javascript_context, dom_based, stored_indicator (+4) | critical | angularjs |
| `dom_xss` | hash_injection, postmessage_sink, url_source, jquery_sink, open_redirect_dom, document_domain (+3) | critical | angular, csp, dompurify, javascript, jquery |
| `dom_clobbering` | form_clobbering, iframe_srcdoc_clobber | critical | - |
| `dom_clobbering_2024` | id_name_property_clobber, htmlcollection_clobber | high | - |
| `cspp` | custom_property_injection, style_attribute_injection | high | - |
| `client_side_request` | postmessage_origin_bypass, window_opener_attack, wildcard_postmessage_send, broadcast_channel_leak | high | - |
| `client_side_path_traversal` | fetch_path_injection, router_manipulation, postmessage_cspt | high | angular, next.js, nuxt, react, sveltekit |
| `dangling_markup` | token_theft, csp_bypass_dangling | high | - |
| `relative_path_overwrite` | css_injection_rpo, css_exfiltration | medium | apache, asp.net, iis, nginx, php |

## Authentication / Auth (14)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `auth_bypass` | default_credentials, header_bypass, method_override, path_normalization | critical | - |
| `access_control` | forced_browsing, method_based_bypass, parameter_based_access, referer_based, multitenancy, insecure_direct_object | critical | - |
| `authentication` | password_reset_flaws, two_factor_bypass, session_fixation, account_enumeration, insecure_remember_me, default_credentials (+2) | critical | asp.net, java, php, ruby |
| `session_security` | credentials_over_cleartext, auth_response_browser_cacheable, session_cookie_missing_secure_flag, logout_does_not_invalidate_session, concurrent_sessions_not_invalidated, session_token_in_url | high | - |
| `jwt` | alg_none, alg_confusion, kid_injection, jku_injection, weak_secret, embedded_jwk (+9) | critical | - |
| `oauth` | redirect_uri_bypass, state_bypass, scope_escalation, pkce_downgrade, oauth_mixup_attack, oauth_audience_confusion, jwks_kid_swap, redirect_uri_parser_quirks, par_request_uri_attacker_controlled_2025, dpop_nonce_binding_skipped_2025, passkey_stepup_no_assertion_2026 (CVE-2026-32879), webauthn_api_hijack_jsinjection_2026 (DEF CON 33) (+13) | critical | auth0, backchannel_authentication, ciba, dpop, fapi, oidc, jwt, passkey, pkce, webauthn |
| `oauth_device_flow` | device_code_phishing, user_code_brute_force | critical | device_grant, oauth |
| `oauth_dpop_confused_deputy` | rs_audience_missing, jti_replay | high | dpop, oauth, rfc9449 |
| `saml` | signature_bypass, xxe_in_saml, assertion_replay, attribute_injection, recipient_mismatch, xml_signature_wrapping (+2) | critical | .net, adfs, java, okta, onelogin |
| `saml_xsw` *(ref-only)* | saml_response_endpoint_detect, xsw_signature_wrap, xsw_comment_injection_nameid, saml_signature_exclusion, saml_keyinfo_swap | critical | saml, shibboleth, okta, onelogin, adfs, auth0, ping |
| `scim_provisioning` | endpoint_discovery, filter_injection, mass_user_create, group_patch_escalation, shadow_admin_username, put_attribute_clear | critical | azure_ad, jumpcloud, okta, onelogin, scim |
| `webauthn_passkey` | attestation_none_acceptance, challenge_replay, rp_id_origin_mismatch, recovery_code_weakness, passkey_to_password_downgrade, conditional_ui_user_enum (+5) | critical | cable, credential_manager, fido2, google_password_manager, hybrid |
| `webauthn_passkey_attacks` | origin_validation_weak, cross_device_misbinding | high | fido2, passkey, webauthn |
| `session_puzzling` | variable_overwrite, session_race, session_fixation_variant | high | asp.net, django, flask, java, node.js |

## Authorization / IDOR (5)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `idor` | numeric_id, uuid_id, sequential_enum, param_pollution, method_override, composite_key (+2) | critical | - |
| `mass_assignment` | role_escalation, price_manipulation, hidden_field_tampering, nested_object_assignment, graphql_input_overreach | critical | express, graphql, mongoose, node, rails |
| `excessive_data_exposure` | admin_fields_leaked_to_user, pii_overfetch_in_listing, internal_field_in_public_response, field_filter_bypass_via_fields_param, graphql_introspection_full_schema, response_overshare_after_filter_mismatch | critical | apollo, django, express, graphql, mongoose, rails |
| `hpp` | query_duplicate, array_notation, json_body_pollution | high | node.js, php, ruby |
| `csrf` | missing_token, token_reuse, method_override, content_type_bypass, referer_bypass, token_manipulation (+3) | high | - |

## Network / Smuggling (7)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `request_smuggling` *(ref-only)* | cl_te, te_cl, te_te, te_zero, cl_zero, h2_cl (+2) | critical | apache, envoy, h2, h2c, haproxy |
| `http_desync` | cl_zero, client_side_desync, pause_based, h2_desync, zero_cl_desync, visible_te_desync, expect_100_desync, rqp_request_queue_poison, double_desync_amplification, browser_powered_csd_intranet, browser_powered_csd_internal (+1) | critical | apache, haproxy, envoy, nginx, cloudfront, cloudflare, fastly, aws alb |
| `http3_quic` *(ref-only)* | zero_rtt_replay, stream_reset_poisoning, connection_migration_auth, alt_svc_downgrade | critical | http3, quic |
| `host_header` | password_reset_poison, routing_abuse, ssrf_via_host, cache_poison_via_host, duplicate_host | high | akamai, apache, cloudflare, cloudfront, fastly |
| `crlf_injection` | header_injection, log_injection | critical | - |
| `request_splitting` | response_splitting, http_09_response, header_injection | critical | apache, java, nginx, node.js, php |
| `waf_bypass_40x` | header_origin_spoof, path_normalisation_tricks, method_override | critical | nginx, apache, haproxy, envoy, cloudflare, akamai, aws alb, f5, imperva |

## Cache / Proxy (5)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `cache_poisoning` | unkeyed_headers, cache_deception, cloudflare_cache_bypass, fastly_normalization, akamai_param_order, head_request_caching (+2) | high | akamai, cf-cache-status, cf-ray, cloudflare, cloudfront |
| `cache_deception_v2` | semicolon_path_param, encoded_slash_split, fragment_split_parser_discrepancy, double_extension_parser_split, normalised_path_traversal_split | high | akamai, cloudflare, fastly |
| `nextjs_cache_poisoning` | rsc_cache_key_manipulation, isr_revalidate_poison, server_action_body_confusion | high | next, next.js, vercel |
| `web_cache_deception` *(ref-only)* | path_confusion, delimiter_confusion, normalization_discrepancy, method_based | high | akamai, apache, cdn, cloudflare, cloudfront |
| `web_cache_poisoning_dos` *(ref-only)* | header_oversize, cache_key_normalization, vary_header_abuse, large_response_caching | medium | akamai, apache, cloudflare, cloudfront, fastly |

## SSRF / Cloud (6)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `ssrf` | cloud_metadata, internal, url_bypass, redirect_based | critical | aws, azure, gcp |
| `ssrf_bypass` | localhost_bypass, ipv6_bypass, dns_rebinding, dns_rebinding_advanced | critical | - |
| `ssrf_protocol` | protocol_smuggling, protocol_variant, k8s_in_cluster_pivot | critical | curl, java, k8s, kubernetes, php |
| `edge_worker_ssrf` | internal_header_trust, same_zone_metadata, opennext_cloudflare_cdn_cgi_backslash_norm_2026 (CVE-2026-3125) | critical | cloudflare-worker, fastly-compute, opennext, vercel-edge |
| `cloud_webapp` | aws_metadata_imdsv1, gcp_metadata, azure_imds, s3_public_bucket, azure_sas_token_leak, firebase_open_db (+3) | ? | - |
| `anon_cloud_expansion` | etcd_v2_v3_open, kubelet_unauth_api, docker_daemon_remote_api, consul_open_api, vault_unsealed_anon, firebase_rtdb_open_rules, firestore_open_rules, terraform_state_exposed, nomad_open_api, spinnaker_ui_open | critical | etcd, kubelet, docker, consul, vault, nomad, spinnaker, firebase, firestore, terraform |

## Path / File (3)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `path_traversal` | linux, windows, encoding_bypass, null_byte, windows_specific | critical | apache, asp.net, django, flask, iis |
| `file_upload` | php_upload, jsp_upload, asp_upload, general, polyglot_files | critical | apache, asp.net, drupal, iis, java |
| `source_code_exposure` *(ref-only)* | git_exposure, svn_exposure, env_file_exposure, debug_endpoints | critical | apache, django, laravel, php, rails |

## Deserialization (4)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `deserialization` | java, php, python, dotnet_viewstate, ruby, log4shell (+6) | critical | .net, asp.net, django, express, fastjson |
| `insecure_deserialization` | java_gadgets, php_unserialize, ruby_yaml, python_unsafe_deser | critical | django, drupal, fastapi, flask, java |
| `prototype_pollution` | server_side, client_side, detection, ejs_template_gadget, pug_compile_options_gadget, express_default_property_pollution, fastify_ajv_pollution, exec_argv_rce_chain, hapi_event_pollution, side_channel_status_delta, axios_rce_gadget_2026 (CVE-2026-40175), n8n_node_pp_rce_2026 (CVE-2026-44789/90/91) (+4) | critical | angularjs, axios, ejs, express, express-fileupload, fastify, hapi, koa, n8n, nestjs, node.js |
| `trpc_sspp` | trpc_form_data_proto, trpc_batch_input_proto, next_app_dir_caller_sniff | high | trpc, @trpc/server, next |

## API / Protocol (9)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `graphql` | introspection, depth_attack, field_suggestion, injection, mutation_injection, directive_overloading (+9) | critical | apollo, express, federation, graphql, node.js |
| `grpc_injection` | reflection_enumeration, message_manipulation, auth_bypass, field_type_injection, stream_cancellation_race, transcoding_open_redirect (+1) | high | envoy, go, grpc, grpc-gateway, grpc-web |
| `api_abuse` | graphql_batching, rest_parameter_pollution, api_rate_limit_bypass, broken_pagination, http2_smuggling | high | apache, apollo, aws alb, cloudflare, graphql |
| `api_inventory` | old_api_version_still_live, shadow_internal_endpoint, swagger_openapi_leak_on_prod, actuator_management_endpoint, dev_staging_hostname_leak, method_override_reaches_hidden_verb | critical | fastapi, micronaut, openapi, quarkus, spring-boot, swagger |
| `http_methods_enum` | trace_method_enabled, options_reveals_dangerous_verbs, put_writes_arbitrary_file, delete_method_succeeds_anonymously, verb_tampering_bypass_acl | critical | apache, iis, nginx, spring-security, tomcat |
| `unsafe_consumption` | open_webhook_url_attacker_controlled, third_party_response_trust_no_validation, oauth_callback_origin_trust, partner_redirect_chain_ssrf, saml_idp_trust_no_signature_check, rss_atom_feed_xxe, webhook_signature_trust_no_origin_check, json_response_field_injection_via_upstream | critical | oauth, oidc, passport, saml, stripe, twilio |
| `websocket` | cswsh, auth_bypass, injection, message_smuggling, proto_pollution, ws_auth_pre_handshake_send (+5) | high | express, nginx, node.js, permessage-deflate, socket.io |
| `sse_injection` | event_injection, stream_hijacking | high | django, express, flask, go, java |
| `webhook_replay` | stripe_replay, signature_strip, alg_downgrade, idempotency_reuse | critical | idempotency, stripe, stripe-signature, webhook |

## Mobile (2)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `mobile_api` | broken_object_level_auth, excessive_data_exposure, broken_function_level_auth, mass_assignment, api_versioning, certificate_pinning_context (+6) | critical | android, android_keystore, app_attest, ascredentialidentitystore, biometric |
| `push_notification` | fcm_server_key_in_bundle, fcm_unauth_send_proxy, silent_push_exfil, topic_subscribe_unauth, notification_deep_link_injection, cross_account_token_reuse | critical | apns, fcm, firebase, mobile, push |

## Payment / FIDO (1)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `payment_flow` | intent_id_cross_account, capture_refund_race, webhook_secret_rotation_race, setup_intent_reuse_no_3ds, idempotency_key_cross_customer, currency_confusion (+6) | critical | 3ds, account_links, apple_pay, apple_wallet, checkout |

## Browser / Web (11)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `cors` | origin_reflect, null_origin, credentials_wildcard, subdomain_wildcard, pre_domain, post_domain (+2) | critical | cors |
| `clickjacking` *(ref-only)* | missing_frameguard, frameable_state_change, double_frame_bypass | medium | - |
| `open_redirect` | url_param | high | - |
| `browser_storage` | service_worker_hijack, localstorage_xss_persistence, indexeddb_tampering, bfcache_auth_bypass, cache_storage_poisoning, storage_event_cross_tab (+1) | critical | offline, pwa, service_worker, spa |
| `service_worker_attacks` | offline_cache_poison, scope_hijack | critical | offline, pwa, push, service_worker |
| `react_server_components` | rsc_flight_fingerprint, server_action_invocation_anomaly, rsc_form_state_pollution, rsc_action_id_enumeration | critical | next, next.js, react-server, rsc, vercel |
| `xs_leak` *(ref-only)* | frame_counting, timing_leak, error_event | medium | javascript |
| `content_type_confusion` | mime_sniffing, content_type_mismatch, polyglot | medium | apache, express, iis, nginx, node.js |
| `unicode_normalization` | auth_bypass, filter_bypass, case_mapping | high | django, java, node.js, python, ruby |
| `error_handling_misuse` | empty_body_default_allow, missing_required_field_default, null_value_bypass, type_coercion_confusion, content_type_parser_fallback, oversized_payload_stacktrace, trailing_nullbyte_identifier_bypass, boolean_coercion, array_vs_string_confusion, charset_mismatch_filter_bypass, fail_open_on_parser_error, default_role_on_register | critical | express, node.js, rails, spring, django, asp.net |
| `client_side_messaging` | postmessage_no_origin_check, postmessage_data_into_sink, xssi_json_array_callable, xssi_jsonp_callback_unfiltered, xssi_secrets_in_script_includable | high | - |

## Race / Logic (4)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `race_condition` *(ref-only)* | double_spend, limit_bypass, signup_race | critical | - |
| `state_machine_race` | limit_overrun, two_window_edge | high | - |
| `business_logic` | price_manipulation, coupon_abuse, workflow_bypass, rate_limit_bypass, privilege_escalation, type_juggling (+5) | critical | javascript, node.js, php, ruby |
| `second_order` | stored_sqli, stored_xss, stored_ssti, stored_header_injection | critical | asp.net, erb, freemarker, handlebars, java |

## Recon / Disclosure (5)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `info_disclosure` | stack_trace, debug_info, version_leak, sensitive_files | critical | - |
| `subdomain_takeover` | dangling_cname | high | aws s3, azure, fastly, fly.io, ghost |
| `tech_vulns` *(ref-only)* |  | ? | - |
| `dependency_confusion` *(ref-only)* | npm_confusion, pypi_confusion | critical | django, fastapi, flask, node.js, npm |
| `captcha_bypass` *(ref-only)* | implementation_flaws, rate_limit_bypass | medium | asp.net, java, node.js, php, python |

## RCE Detection (1)

Detection-only KB — confirms RCE preconditions (FILE priv, vulnerable parser version, reachable internal service, eval sink). **Does NOT auto-exploit.** Real exploitation step is operator-supervised (Copilot mode). See `chain-findings.md` "RCE Escalation Reference" table.

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `rce_detection` | sqli_mysql_file_priv_present, sqli_pg_superuser_or_copy_priv, sqli_mssql_xpcmdshell_state, sqli_oracle_dbms_scheduler_priv, sqli_sqlite_load_extension, ssrf_redis_reachable, ssrf_memcached_reachable, ssrf_elasticsearch_dynamic_scripting, ssrf_jolokia_runtime_mbean, spring_actuator_env_mutable, spring4shell_classloader_reachable, spring_cloud_function_routing_expression, spring_cloud_gateway_spel, confluence_ognl_eval, imagemagick_mvg_parser_active, libwebp_version_disclosure, ghostscript_pdf_eval_active, exiftool_djvu_parser_active, jndi_jdbc_h2_console, node_vm2_or_eval_sink_in_js, json_parse_reviver_sink, ofbiz_groovy_eval, joomla_template_php_write_detection, drupal_phpmodule_or_php_filter_enabled, wordpress_theme_editor_writable | critical | apache-ofbiz, confluence, drupal, elasticsearch, h2, imagemagick, jolokia, joomla, mssql, mysql, oracle, postgresql, redis, spring, spring-cloud-function, spring-cloud-gateway, wordpress |

## DoS / Misc (5)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `redos` | catastrophic_backtracking | medium | java, javascript, node.js, php, python |
| `insecure_randomness` *(ref-only)* | predictable_tokens, weak_session_id, uuid_v1_leak | high | asp.net, custom, java, node.js, php |
| `h2_continuation_flood` *(ref-only)* | continuation_unbounded | high | apache, envoy, h2, nginx, node.js |
| `resource_exhaustion` | sms_pump_no_ratelimit, email_pump_no_ratelimit, otp_brute_no_lockout, expensive_query_no_limit, graphql_alias_DoS, file_upload_no_size_limit, biometric_or_paid_provider_call, zip_bomb_decompression | critical | apollo, aws-sns, graphql, mailgun, sendgrid, twilio |
| `crypto_weakness` | padding_oracle_cbc, weak_hash_in_token, weak_jwt_alg_hs256_with_predictable_secret, des_3des_rc4_in_response, encrypted_blob_without_integrity | critical | asp.net, java, jwt, php, ruby |

## AI / LLM (4)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `ai_prompt_injection` | direct_injection, indirect_xpi, tool_call_hijack, exfil_via_markdown, langchain_lc_marker_injection_2025 (CVE-2025-68664), cua_dom_hidden_instruction_2026, cua_multistep_persistence_2026, cua_data_attribute_pii_2026, mcp_resource_theft_hidden_directive_2026 (Unit 42), mcp_conversation_hijack_persistent_2026 (Unit 42), mcp_covert_tool_invocation_2026 (Unit 42), idpi_visual_concealment_2026 (Unit 42), idpi_invisible_unicode_jailbreak_2026 (Unit 42), idpi_payload_splitting_2026 (Unit 42) | critical | anthropic, anthropic-tools, chatbot, claude, cua, function-calling, langchain, mcp-server, model-context-protocol |
| `web_llm` | prompt_injection_via_web, llm_ssrf, llm_data_exfil, llm_tool_abuse, stored_injection | critical | ai, assistant, chatbot, claude, embedding |
| `mcp_server_attacks` | tool_description_prompt_injection, mcp_rug_pull, claude_code_path_prefix_match_traversal_2025 (CVE-2025-54794), claude_code_tool_arg_shell_injection_2025 (CVE-2025-54795), claude_code_settings_json_hook_preconsent_rce_2025 (CVE-2025-59536), mcp_atlassian_path_traversal_rce_2026 (CVE-2026-27825), mcp_atlassian_header_ssrf_2026 (CVE-2026-27826) | critical | claude-code, claude-desktop, cursor, mcp, mcp-atlassian, model-context-protocol |
| `mcp_tool_poisoning` | tool_description_prompt_injection, parasitic_tool_chaining, server_identity_spoofing, rug_pull_post_install, indirect_resource_injection | high | mcp, claude-desktop, cursor, fastmcp |
| `rag_injection` | stored_content_rag_poison, vector_metadata_injection | high | chromadb, faiss, pinecone, rag, weaviate |
| `echoleak` | markdown_image_exfil, css_class_leak, hidden_html_directive, data_uri_smuggling | critical | copilot, m365, rag, llm, anthropic, openai |
| `vector_db_injection` | chroma_anonymous_api, pinecone_index_enumeration, weaviate_graphql_unauth, qdrant_anonymous_api, metadata_filter_injection, embedding_extraction_via_query | high | chroma, pinecone, weaviate, qdrant, pgvector |

## 2026-05-21 additions

10 novel KB entries added — see categories above. Auto-probe enabled: `state_machine_race`, `oauth_dpop_confused_deputy`, `edge_worker_ssrf`, `webauthn_passkey_attacks`, `cache_deception_v2`, `dom_clobbering_2024`, `service_worker_attacks`. Reference-only: `h2_continuation_flood` (CVE-2024-27316, Rule 5 DoS), `mcp_server_attacks`, `rag_injection`.

## 2026-05-22 additions — Coverage pass (cloud + mobile + archive + DAV + GraphQL engines)

10 KBs added to close gaps surfaced by mapping current coverage against OWASP Top 10 (Web/API/LLM/Mobile), WSTG, PayloadsAllTheThings, HackTricks Web, and HackTricks Cloud. Operator-anonymous detection only — no provider credentials required.

### Cloud (anonymous detection — HackTricks Cloud first-phase)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `cloud_storage_misconfig` | s3_anonymous_list, s3_anonymous_write, gcs_anonymous_list, azure_blob_anonymous_list, r2_anonymous_access, do_spaces_anonymous, b2_anonymous_access, oci_anonymous_access, minio_anonymous, signed_url_leak | critical | aws, azure, b2, digitalocean, gcp, minio, oracle, r2, s3 |
| `cloud_function_url` | lambda_function_url_anon, cloud_run_unauthenticated, cloud_functions_http_anon, azure_functions_anonymous, openfaas_gateway, vercel_netlify_functions, knative_unauth | high | aws, azure, cloud-run, gcp, knative, lambda, netlify, openfaas, vercel |
| `cloud_api_gateway` | aws_apigw_stage_leak, aws_apigw_auth_disabled_method, aws_apigw_test_invoke, gcp_api_gateway_endpoints, azure_apim_default_routes, kong_admin_exposed, krakend_anonymous, tyk_dashboard | critical | apim, aws, azure, gcp, kong, krakend, tyk |
| `kubernetes_exposed` *(ref-only)* | kubelet_read_only_port, kubelet_secure_port_anon, kube_apiserver_anonymous, etcd_exposed, kubernetes_dashboard, argocd_anonymous, tekton_dashboard, rancher_unauth, portainer_unauth, container_registry_anonymous, service_mesh_metrics | critical | argocd, dashboard, dgraph, docker-registry, etcd, harbor, kubelet, kubernetes, portainer, prometheus, rancher, tekton |

### Web (gap-fill)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `zip_slip` *(ref-only)* | zip_traversal_classic, zip_overwrite_critical_files, tar_extraction_traversal, rar_seven_z_traversal, symlink_in_archive, jar_zip_polyglot, post_extract_observability | critical | java, tomcat, jetty, weblogic |
| `webdav_misconfig` | options_dav_header, propfind_directory_listing, put_arbitrary_file, mkcol_create_collection, copy_move_to_extension, lock_token_exhaustion, sharepoint_webdav_quirks, iis_short_filename_8_3 | critical | apache, dav, iis, lighttpd, nginx, sharepoint, tomcat, webdav, windows |
| `argv_injection` | curl_upload_file, wget_argv_smuggle, find_exec_smuggle, openssl_config_load, ssh_proxycommand, tar_dash_dash_to_command, rsync_e_flag, git_clone_upload_pack, imagemagick_argv, argv_zero_smuggle | critical | git, imagemagick, ssh |
| `graphql_engines` | hasura_admin_secret_check, hasura_role_header_escalation, hasura_remote_schema_ssrf, apollo_persisted_query_poisoning, apollo_federation_internals, dgraph_admin_unauth, postgraphile_underscore_bypass, graphql_field_suggestion_oracle, graphql_alias_amplification_dos, strawberry_python_specifics | critical | apollo, dgraph, federation, hasura, postgraphile, strawberry, strawberry-graphql |

### Mobile (gap-fill — OWASP Mobile Top 10 2024 M4)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `mobile_deeplink` *(ref-only)* | android_implicit_intent_redirect, android_exported_activity_takeover, android_custom_scheme_takeover, ios_universal_link_misconfig, ios_custom_url_scheme, android_app_links_signature_required, rn_flutter_deeplink_router, deeplink_dangerous_intent_actions | critical | android, apple, expo, flutter, ios, react-native |
| `webview_injection` *(ref-only)* | addjavascriptinterface_rce, webview_file_url_access, wkwebview_message_handler, wkwebview_universal_xss, cordova_ionic_plugin_abuse, capacitor_plugin_default, webview_mixed_content_load, webview_screenshot_token_capture | critical | android, capacitor, cordova, ionic, ios, phonegap, webview, wkwebview |

### Coverage framework mapping

| Framework | KB categories |
|---|---|
| OWASP Web Top 10 2021 | All 10 covered — A01 access_control/idor/mass_assignment, A02 crypto_weakness, A03 sqli+xss+command_injection+ssti+nosql+xpath/etc., A04 business_logic/state_machine_race, A05 info_disclosure/http_methods_enum, A06 tech_vulns/dependency_confusion, A07 authentication/jwt/oauth, A08 deserialization/prototype_pollution, A09 crlf_injection (log injection), A10 ssrf+ssrf_bypass+edge_worker_ssrf+cloud_webapp |
| OWASP API Top 10 2023 | All 10 — API1 idor, API2 authentication+jwt, API3 excessive_data_exposure+mass_assignment, API4 resource_exhaustion, API5 access_control, API6 business_logic+state_machine_race, API7 ssrf*, API8 info_disclosure, API9 api_inventory, API10 unsafe_consumption |
| OWASP LLM Top 10 2025 | 9/10 — ai_prompt_injection, web_llm, mcp_server_attacks, rag_injection, resource_exhaustion (LLM10). LLM09 misinformation out-of-scope for active testing. |
| OWASP Mobile Top 10 2024 | mobile_api + mobile_deeplink + webview_injection + push_notification + crypto_weakness. M5 (insecure comm) addressed by mobile-dynamic-agent (tool-side TLS pinning bypass), not KB. M7 (binary protections) out-of-scope. |
| OWASP WSTG (web) | All sections — 4.1 info_disclosure/source_code_exposure/api_inventory, 4.2 http_methods_enum/webdav_misconfig/error_handling_misuse, 4.3-4.5 authentication/access_control/idor, 4.6 session_security/csrf, 4.7 all injection KBs + zip_slip + argv_injection, 4.8 error_handling_misuse, 4.9 crypto_weakness, 4.10 business_logic, 4.11 dom_xss/cspp/client_side_*, 4.12 graphql/graphql_engines/grpc_injection/websocket |
| PayloadsAllTheThings | Every named injection class mapped. ZIP Slip, ARGV Injection, GraphQL engines added in 2026-05-22 pass. |
| HackTricks Web | All major sections (path traversal, SSRF, SSTI, deserialization, prototype pollution, request smuggling, cache poisoning, CSPP, OAuth, SAML, file upload, WebDAV) covered. |
| HackTricks Cloud (anonymous-only) | First-phase external enum covered: cloud_storage_misconfig + cloud_function_url + cloud_api_gateway + kubernetes_exposed + anon_cloud_expansion (etcd/kubelet/Docker/Consul/Vault/Nomad/Spinnaker/Firebase/Firestore/Terraform) + ssrf cloud_metadata. Credentialed audit and active post-exploit added in W6: `run_prowler` / `run_scout_suite` / `run_cloudsploit` (audit); `run_pacu` (post-exploit, Rule 5 destructive denylist enforced). |

## 2026-05-24 W6 additions — Cloud / IaC / CI / Visual EASM / K8s active

| Category | Contexts | Top severity | Backed by tool |
|---|---|---|---|
| `ci_actions_injection` *(ref-only)* | expression_injection, pwn_request, untrusted_checkout, unpinned_third_party_action, self_hosted_runner_takeover, secret_exfil_via_log | critical | `run_poutine`, `run_octoscan` |

Active-only surfaces (probes run via binary tools, no KB matchers):

- Cloud config posture: `run_prowler` (AWS/Azure/GCP/K8s), `run_scout_suite` (AWS/Azure/GCP/Aliyun/OCI), `run_cloudsploit` (Aqua), `run_pacu` (AWS post-exploit, Rule 5 denylist).
- IaC + Dockerfile: `run_checkov`, `run_tfsec`, `run_terrascan`, `run_hadolint`.
- SBOM + sign: `run_syft` (CycloneDX/SPDX), `run_cosign_verify` (Sigstore keyless + keyed).
- K8s active: `run_peirates`, `run_kdigger`, `run_kubeletctl`.
- CVE prioritisation: `kev_epss_enrich(cve_ids)` — CISA KEV + FIRST EPSS sort.
- Subdomain perm: `run_chaos`, `run_dnsgen`, `run_shuffledns`.
- Visual EASM: `visual_easm_diff` — gowitness screenshot + per-host PNG-hash delta.