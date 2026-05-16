# Knowledge Base Index

**92 knowledge files** under `mcp-server/src/burpsuite_mcp/knowledge/`. Each is a JSON file with probe contexts loadable via `auto_probe(categories=[...])`.

## Prefix-matching loader

`auto_probe(categories=['ssti'])` loads `ssti.json` AND any `ssti_*.json` split file. This lets large categories live in multiple smaller files without changing the caller API.

Split categories:
- `ssti` → `ssti.json` + `ssti_python.json`, `ssti_java.json`, `ssti_js.json`, `ssti_php.json`
- `sqli` → `sqli.json` + `sqli_blind.json`, `sqli_engines.json`
- `ssrf` → `ssrf.json` + `ssrf_bypass.json`, `ssrf_protocol.json`

**Reference-only (manual tooling, not auto-probed):** captcha_bypass, clickjacking, csv_injection, dependency_confusion, http3_quic, insecure_randomness, race_condition, request_smuggling, source_code_exposure, tech_vulns, web_cache_deception, web_cache_poisoning_dos, xs_leak

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

## Injection (client-side) (8)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `xss` | html, attribute, angular, javascript_context, dom_based, stored_indicator (+4) | critical | angularjs |
| `dom_xss` | hash_injection, postmessage_sink, url_source, jquery_sink, open_redirect_dom, document_domain (+3) | critical | angular, csp, dompurify, javascript, jquery |
| `dom_clobbering` | form_clobbering, iframe_srcdoc_clobber | critical | - |
| `cspp` | custom_property_injection, style_attribute_injection | high | - |
| `client_side_request` | postmessage_origin_bypass, window_opener_attack, wildcard_postmessage_send, broadcast_channel_leak | high | - |
| `client_side_path_traversal` | fetch_path_injection, router_manipulation, postmessage_cspt | high | angular, next.js, nuxt, react, sveltekit |
| `dangling_markup` | token_theft, csp_bypass_dangling | high | - |
| `relative_path_overwrite` | css_injection_rpo, css_exfiltration | medium | apache, asp.net, iis, nginx, php |

## Authentication / Auth (11)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `auth_bypass` | default_credentials, header_bypass, method_override, path_normalization | critical | - |
| `access_control` | forced_browsing, method_based_bypass, parameter_based_access, referer_based, multitenancy, insecure_direct_object | critical | - |
| `authentication` | password_reset_flaws, two_factor_bypass, session_fixation, account_enumeration, insecure_remember_me, default_credentials (+2) | critical | asp.net, java, php, ruby |
| `session_security` | credentials_over_cleartext, auth_response_browser_cacheable, session_cookie_missing_secure_flag, logout_does_not_invalidate_session, concurrent_sessions_not_invalidated, session_token_in_url | high | - |
| `jwt` | alg_none, alg_confusion, kid_injection, jku_injection, weak_secret, embedded_jwk (+9) | critical | - |
| `oauth` | redirect_uri_bypass, state_bypass, scope_escalation, pkce_downgrade, pkce_reuse_after_capture, oidc_nonce_validation (+11) | critical | auth0, backchannel_authentication, ciba, dpop, fapi |
| `oauth_device_flow` | device_code_phishing, user_code_brute_force | critical | device_grant, oauth |
| `saml` | signature_bypass, xxe_in_saml, assertion_replay, attribute_injection, recipient_mismatch, xml_signature_wrapping (+2) | critical | .net, adfs, java, okta, onelogin |
| `scim_provisioning` | endpoint_discovery, filter_injection, mass_user_create, group_patch_escalation, shadow_admin_username, put_attribute_clear | critical | azure_ad, jumpcloud, okta, onelogin, scim |
| `webauthn_passkey` | attestation_none_acceptance, challenge_replay, rp_id_origin_mismatch, recovery_code_weakness, passkey_to_password_downgrade, conditional_ui_user_enum (+5) | critical | cable, credential_manager, fido2, google_password_manager, hybrid |
| `session_puzzling` | variable_overwrite, session_race, session_fixation_variant | high | asp.net, django, flask, java, node.js |

## Authorization / IDOR (5)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `idor` | numeric_id, uuid_id, sequential_enum, param_pollution, method_override, composite_key (+2) | critical | - |
| `mass_assignment` | role_escalation, price_manipulation, hidden_field_tampering, nested_object_assignment, graphql_input_overreach | critical | express, graphql, mongoose, node, rails |
| `excessive_data_exposure` | admin_fields_leaked_to_user, pii_overfetch_in_listing, internal_field_in_public_response, field_filter_bypass_via_fields_param, graphql_introspection_full_schema, response_overshare_after_filter_mismatch | critical | apollo, django, express, graphql, mongoose, rails |
| `hpp` | query_duplicate, array_notation, json_body_pollution | high | node.js, php, ruby |
| `csrf` | missing_token, token_reuse, method_override, content_type_bypass, referer_bypass, token_manipulation (+3) | high | - |

## Network / Smuggling (6)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `request_smuggling` *(ref-only)* | cl_te, te_cl, te_te, te_zero, cl_zero, h2_cl (+2) | critical | apache, envoy, h2, h2c, haproxy |
| `http_desync` | cl_zero, client_side_desync, pause_based, h2_desync | high | apache, aws alb, cloudfront, express, haproxy |
| `http3_quic` *(ref-only)* | zero_rtt_replay, stream_reset_poisoning, connection_migration_auth, alt_svc_downgrade | critical | http3, quic |
| `host_header` | password_reset_poison, routing_abuse, ssrf_via_host, cache_poison_via_host, duplicate_host | high | akamai, apache, cloudflare, cloudfront, fastly |
| `crlf_injection` | header_injection, log_injection | critical | - |
| `request_splitting` | response_splitting, http_09_response, header_injection | critical | apache, java, nginx, node.js, php |

## Cache / Proxy (3)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `cache_poisoning` | unkeyed_headers, cache_deception, cloudflare_cache_bypass, fastly_normalization, akamai_param_order, head_request_caching (+2) | high | akamai, cf-cache-status, cf-ray, cloudflare, cloudfront |
| `web_cache_deception` *(ref-only)* | path_confusion, delimiter_confusion, normalization_discrepancy, method_based | high | akamai, apache, cdn, cloudflare, cloudfront |
| `web_cache_poisoning_dos` *(ref-only)* | header_oversize, cache_key_normalization, vary_header_abuse, large_response_caching | medium | akamai, apache, cloudflare, cloudfront, fastly |

## SSRF / Cloud (4)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `ssrf` | cloud_metadata, internal, url_bypass, redirect_based | critical | aws, azure, gcp |
| `ssrf_bypass` | localhost_bypass, ipv6_bypass, dns_rebinding, dns_rebinding_advanced | critical | - |
| `ssrf_protocol` | protocol_smuggling, protocol_variant, k8s_in_cluster_pivot | critical | curl, java, k8s, kubernetes, php |
| `cloud_webapp` | aws_metadata_imdsv1, gcp_metadata, azure_imds, s3_public_bucket, azure_sas_token_leak, firebase_open_db (+3) | ? | - |

## Path / File (3)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `path_traversal` | linux, windows, encoding_bypass, null_byte, windows_specific | critical | apache, asp.net, django, flask, iis |
| `file_upload` | php_upload, jsp_upload, asp_upload, general, polyglot_files | critical | apache, asp.net, drupal, iis, java |
| `source_code_exposure` *(ref-only)* | git_exposure, svn_exposure, env_file_exposure, debug_endpoints | critical | apache, django, laravel, php, rails |

## Deserialization (3)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `deserialization` | java, php, python, dotnet_viewstate, ruby, log4shell (+6) | critical | .net, asp.net, django, express, fastjson |
| `insecure_deserialization` | java_gadgets, php_unserialize, ruby_yaml, python_unsafe_deser | critical | django, drupal, fastapi, flask, java |
| `prototype_pollution` | server_side, client_side, detection, ejs_template_gadget, pug_compile_options_gadget, express_fileupload_rename_gadget (+2) | critical | angularjs, ejs, express, express-fileupload, fastify |

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

## Browser / Web (9)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `cors` | origin_reflect, null_origin, credentials_wildcard, subdomain_wildcard, pre_domain, post_domain (+2) | critical | cors |
| `clickjacking` *(ref-only)* | missing_frameguard, frameable_state_change, double_frame_bypass | medium | - |
| `open_redirect` | url_param | high | - |
| `browser_storage` | service_worker_hijack, localstorage_xss_persistence, indexeddb_tampering, bfcache_auth_bypass, cache_storage_poisoning, storage_event_cross_tab (+1) | critical | offline, pwa, service_worker, spa |
| `xs_leak` *(ref-only)* | frame_counting, timing_leak, error_event | medium | javascript |
| `content_type_confusion` | mime_sniffing, content_type_mismatch, polyglot | medium | apache, express, iis, nginx, node.js |
| `unicode_normalization` | auth_bypass, filter_bypass, case_mapping | high | django, java, node.js, python, ruby |
| `error_handling_misuse` | empty_body_default_allow, missing_required_field_default, null_value_bypass, type_coercion_confusion, content_type_parser_fallback, oversized_payload_stacktrace, trailing_nullbyte_identifier_bypass, boolean_coercion, array_vs_string_confusion, charset_mismatch_filter_bypass, fail_open_on_parser_error, default_role_on_register | critical | express, node.js, rails, spring, django, asp.net |
| `client_side_messaging` | postmessage_no_origin_check, postmessage_data_into_sink, xssi_json_array_callable, xssi_jsonp_callback_unfiltered, xssi_secrets_in_script_includable | high | - |

## Race / Logic (3)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `race_condition` *(ref-only)* | double_spend, limit_bypass, signup_race | critical | - |
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

## DoS / Misc (4)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `redos` | catastrophic_backtracking | medium | java, javascript, node.js, php, python |
| `insecure_randomness` *(ref-only)* | predictable_tokens, weak_session_id, uuid_v1_leak | high | asp.net, custom, java, node.js, php |
| `resource_exhaustion` | sms_pump_no_ratelimit, email_pump_no_ratelimit, otp_brute_no_lockout, expensive_query_no_limit, graphql_alias_DoS, file_upload_no_size_limit, biometric_or_paid_provider_call, zip_bomb_decompression | critical | apollo, aws-sns, graphql, mailgun, sendgrid, twilio |
| `crypto_weakness` | padding_oracle_cbc, weak_hash_in_token, weak_jwt_alg_hs256_with_predictable_secret, des_3des_rc4_in_response, encrypted_blob_without_integrity | critical | asp.net, java, jwt, php, ruby |

## AI / LLM (2)

| Category | Contexts | Top severity | Tech tags |
|---|---|---|---|
| `ai_prompt_injection` | direct_injection, indirect_xpi, tool_call_hijack, exfil_via_markdown | critical | anthropic, anthropic-tools, chatbot, claude, function-calling |
| `web_llm` | prompt_injection_via_web, llm_ssrf, llm_data_exfil, llm_tool_abuse, stored_injection | critical | ai, assistant, chatbot, claude, embedding |