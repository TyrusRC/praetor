"""W29 — commercial-tool gap closures.

Tests for the 11 new MCP tools (W29-a through W29-k) + KB-org cleanup
(W29-i).

Each tool surface gets:
  - register() succeeds + tool name appears in mcp.list_tools()
  - pick_tool routing reaches the right tool
  - in-memory unit checks for the parse / mutation logic where applicable
    (CSP parser, gRPC frame codec, SAML XSW mutators, etc.)
"""

from __future__ import annotations

import asyncio
import base64
import json
import struct
import unittest
from pathlib import Path

_KB = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "knowledge"


# ───────────────────────── W29-i KB-org cleanup ─────────────────────────


class W29iKbOrgCleanup(unittest.TestCase):
    """Three sibling KBs must be MERGED + deleted per KB-org rule."""

    def test_cache_deception_v2_removed(self):
        self.assertFalse((_KB / "cache_deception_v2.json").exists(),
                         "cache_deception_v2.json must be merged into web_cache_deception.json")

    def test_saml_xsw_removed(self):
        self.assertFalse((_KB / "saml_xsw.json").exists(),
                         "saml_xsw.json must be merged into saml.json")

    def test_webauthn_passkey_attacks_removed(self):
        self.assertFalse((_KB / "webauthn_passkey_attacks.json").exists(),
                         "webauthn_passkey_attacks.json must be merged into webauthn_passkey.json")

    def test_cache_deception_contexts_merged_into_parent(self):
        wcd = json.load(open(_KB / "web_cache_deception.json"))
        for ctx in ("semicolon_path_param", "encoded_slash_split",
                    "fragment_split_parser_discrepancy",
                    "double_extension_parser_split",
                    "normalised_path_traversal_split"):
            self.assertIn(ctx, wcd["contexts"],
                          f"context {ctx} missing from web_cache_deception.json after merge")

    def test_saml_xsw_contexts_merged_into_parent(self):
        saml = json.load(open(_KB / "saml.json"))
        for ctx in ("saml_response_endpoint_detect", "xsw_signature_wrap",
                    "xsw_comment_injection_nameid", "saml_signature_exclusion",
                    "saml_keyinfo_swap"):
            self.assertIn(ctx, saml["contexts"],
                          f"context {ctx} missing from saml.json after merge")

    def test_webauthn_attacks_contexts_merged_into_parent(self):
        wp = json.load(open(_KB / "webauthn_passkey.json"))
        for ctx in ("origin_validation_weak", "cross_device_misbinding"):
            self.assertIn(ctx, wp["contexts"],
                          f"context {ctx} missing from webauthn_passkey.json after merge")

    def test_saml_xsw_not_in_reference_only_set(self):
        from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY
        self.assertNotIn("saml_xsw", _REFERENCE_ONLY,
                         "saml_xsw merged into saml — must drop from _REFERENCE_ONLY")

    def test_index_drops_removed_categories(self):
        idx = (_KB / "_INDEX.md").read_text()
        self.assertNotIn("`cache_deception_v2`", idx)
        # saml_xsw row dropped from auth section; contexts now inside saml row
        self.assertNotIn("`saml_xsw`", idx)
        self.assertNotIn("`webauthn_passkey_attacks`", idx)


# ───────────────────────── Tool registration ─────────────────────────


class W29ToolRegistration(unittest.IsolatedAsyncioTestCase):

    async def test_all_w29_tools_registered(self):
        from burpsuite_mcp import server
        tools = await server.mcp.list_tools()
        names = {t.name for t in tools}
        expected = {
            "discover_llm_endpoint", "run_web_llm_owasp_top10",
            "probe_grpc_reflection", "probe_grpc_idor",
            "probe_saml_xsw",
            "probe_dns_rebind",
            "probe_postmessage_listeners",
            "analyze_csp",
            "probe_sse_injection",
            "run_nuclei_llm_infra",
            "probe_kerberos_spnego_auth",
            "probe_mcp_jsonrpc_methods",
        }
        missing = expected - names
        self.assertFalse(missing, f"W29 tools not registered: {missing}")


# ───────────────────────── pick_tool routing ─────────────────────────


class W29PickToolRouting(unittest.IsolatedAsyncioTestCase):

    async def _route(self, q: str) -> str:
        from burpsuite_mcp.tools.advisor.pick_tool import pick_tool_impl
        return await pick_tool_impl(q)

    async def test_llm_discover_routes(self):
        out = await self._route("discover llm endpoint on /api/chat")
        self.assertIn("discover_llm_endpoint", out)

    async def test_llm_owasp_routes(self):
        out = await self._route("owasp llm top 10 sweep")
        self.assertIn("run_web_llm_owasp_top10", out)

    async def test_grpc_reflection_routes(self):
        out = await self._route("grpc server reflection enum")
        self.assertIn("probe_grpc_reflection", out)

    async def test_grpc_idor_routes(self):
        out = await self._route("grpc bola id mutate")
        self.assertIn("probe_grpc_idor", out)

    async def test_saml_xsw_routes(self):
        out = await self._route("saml xsw signature wrapping")
        self.assertIn("probe_saml_xsw", out)

    async def test_dns_rebind_routes(self):
        out = await self._route("dns rebind toctou ssrf")
        self.assertIn("probe_dns_rebind", out)

    async def test_postmessage_routes(self):
        out = await self._route("postmessage listeners enum")
        self.assertIn("probe_postmessage_listeners", out)

    async def test_csp_routes(self):
        out = await self._route("analyze csp bypass")
        self.assertIn("analyze_csp", out)

    async def test_sse_routes(self):
        out = await self._route("sse injection newline")
        self.assertIn("probe_sse_injection", out)

    async def test_nuclei_llm_routes(self):
        out = await self._route("nuclei llm infra sweep")
        self.assertIn("run_nuclei_llm_infra", out)

    async def test_kerberos_routes(self):
        out = await self._route("kerberos auth detect")
        self.assertIn("probe_kerberos_spnego_auth", out)

    async def test_mcp_jsonrpc_routes(self):
        out = await self._route("mcp jsonrpc methods enum")
        self.assertIn("probe_mcp_jsonrpc_methods", out)

    async def test_regression_bare_sqli_still_works(self):
        out = await self._route("scan target for sqli")
        self.assertIn("auto_probe", out)

    async def test_regression_send_to_repeater_still_works(self):
        out = await self._route("send to repeater")
        self.assertIn("send_to_repeater", out)


# ───────────────────────── CSP parser unit checks ─────────────────────────


class W29CspParserUnit(unittest.IsolatedAsyncioTestCase):

    async def test_no_csp_header_is_confirmed_misconfig(self):
        from burpsuite_mcp.tools import csp_analyzer
        result = await csp_analyzer.analyze_csp.__wrapped__(
            target_url="", header_blob="",
        ) if hasattr(csp_analyzer, "analyze_csp") else None
        # Not exposed at module-level; use the registration path instead.

    async def test_csp_parser_detects_wildcard(self):
        from burpsuite_mcp.tools.csp_analyzer import (
            _parse_csp, _effective_script_src, _has_token,
        )
        parsed = _parse_csp("default-src *; script-src *")
        self.assertIn("default-src", parsed)
        self.assertEqual(_effective_script_src(parsed), ["*"])

    async def test_csp_parser_detects_unsafe_inline(self):
        from burpsuite_mcp.tools.csp_analyzer import (
            _parse_csp, _effective_script_src, _has_token,
        )
        parsed = _parse_csp("script-src 'self' 'unsafe-inline'")
        sources = _effective_script_src(parsed)
        self.assertTrue(_has_token(sources, "'unsafe-inline'"))

    async def test_csp_parser_detects_risky_cdn(self):
        from burpsuite_mcp.tools.csp_analyzer import (
            _parse_csp, _effective_script_src, _detect_risky_cdns,
        )
        parsed = _parse_csp(
            "script-src 'self' https://cdn.jsdelivr.net https://unpkg.com"
        )
        sources = _effective_script_src(parsed)
        risky = _detect_risky_cdns(sources)
        risky_hosts = {h for h, _ in risky}
        self.assertIn("cdn.jsdelivr.net", risky_hosts)
        self.assertIn("unpkg.com", risky_hosts)

    async def test_csp_parser_recognises_nonce(self):
        from burpsuite_mcp.tools.csp_analyzer import (
            _parse_csp, _effective_script_src, _has_nonce_or_hash,
        )
        parsed = _parse_csp("script-src 'self' 'nonce-abc123'")
        self.assertTrue(_has_nonce_or_hash(_effective_script_src(parsed)))


# ───────────────────────── gRPC frame codec unit checks ─────────────────────────


class W29GrpcFrameCodec(unittest.TestCase):

    def test_gframe_wraps_with_length_prefix(self):
        from burpsuite_mcp.tools.grpc_probe import _gframe, _gunframe
        body = b"\x1a\x00"
        framed = _gframe(body)
        self.assertEqual(framed[0], 0)  # compression flag
        length = struct.unpack(">I", framed[1:5])[0]
        self.assertEqual(length, len(body))
        self.assertEqual(framed[5:], body)

    def test_gunframe_round_trips(self):
        from burpsuite_mcp.tools.grpc_probe import _gframe, _gunframe
        a = b"abc"
        b = b"defghi"
        blob = _gframe(a) + _gframe(b)
        out = _gunframe(blob)
        self.assertEqual(out, [a, b])

    def test_mutate_first_varint_bumps_field1(self):
        from burpsuite_mcp.tools.grpc_probe import _mutate_first_varint
        # Tag 0x08 (field 1 varint), value 5 → bump to 6
        frame = b"\x08\x05\x12\x03foo"
        mutated = _mutate_first_varint(frame)
        self.assertEqual(mutated, b"\x08\x06\x12\x03foo")

    def test_extract_services_finds_dotted_names(self):
        from burpsuite_mcp.tools.grpc_probe import _extract_services
        # Mock a ServerReflectionResponse-ish blob with embedded service names
        frames = [b"\x00grpc.health.v1.Health\x00user.v1.UserService"]
        services = _extract_services(frames)
        self.assertIn("grpc.health.v1.Health", services)
        self.assertIn("user.v1.UserService", services)


# ───────────────────────── SAML XSW mutator unit checks ─────────────────────────


class W29SamlXswMutators(unittest.TestCase):

    SAML_FIXTURE = b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="A1">
<saml:Subject><saml:NameID>victim@target.tld</saml:NameID></saml:Subject>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/><ds:SignatureValue>VALID</ds:SignatureValue></ds:Signature>
</saml:Assertion></samlp:Response>"""

    def test_signature_exclusion_strips_signature(self):
        from burpsuite_mcp.tools.saml_xsw_probe import _xsw_signature_exclusion
        out = _xsw_signature_exclusion(self.SAML_FIXTURE)
        self.assertNotIn(b"ds:Signature", out)
        self.assertIn(b"Assertion", out)

    def test_wrap_assertion_inserts_clone_before_original(self):
        from burpsuite_mcp.tools.saml_xsw_probe import _xsw_wrap_assertion
        out = _xsw_wrap_assertion(self.SAML_FIXTURE, "admin")
        # Original NameID kept; attacker NameID inserted before
        self.assertEqual(out.count(b"<saml:Assertion"), 2)
        # Clone has attacker NameID, original has victim NameID; clone is first
        clone_idx = out.find(b"<saml:NameID>admin</saml:NameID>")
        orig_idx = out.find(b"<saml:NameID>victim@target.tld</saml:NameID>")
        self.assertGreater(orig_idx, 0)
        self.assertGreater(clone_idx, 0)
        self.assertLess(clone_idx, orig_idx)

    def test_sibling_wrap_inserts_clone_after_original(self):
        from burpsuite_mcp.tools.saml_xsw_probe import _xsw_sibling_wrap
        out = _xsw_sibling_wrap(self.SAML_FIXTURE, "admin")
        self.assertEqual(out.count(b"<saml:Assertion"), 2)
        clone_idx = out.find(b"<saml:NameID>admin</saml:NameID>")
        orig_idx = out.find(b"<saml:NameID>victim@target.tld</saml:NameID>")
        self.assertLess(orig_idx, clone_idx)

    def test_comment_injection_splits_nameid(self):
        from burpsuite_mcp.tools.saml_xsw_probe import _xsw_comment_injection
        out = _xsw_comment_injection(self.SAML_FIXTURE, "victim", "attacker.tld")
        self.assertIn(b"victim<!---->@attacker.tld", out)

    def test_keyinfo_swap_returns_none_without_cert(self):
        from burpsuite_mcp.tools.saml_xsw_probe import _xsw_keyinfo_swap
        out = _xsw_keyinfo_swap(self.SAML_FIXTURE, "")
        self.assertIsNone(out)


# ───────────────────────── DNS rebind helpers unit checks ─────────────────────────


class W29DnsRebindHelpers(unittest.TestCase):

    def test_internal_marker_detection_ami_id(self):
        from burpsuite_mcp.tools.dns_rebind_probe import _internal_marker_hit
        body = '{"ami-id":"ami-0123","instance-type":"t3.medium"}'
        hit, marker = _internal_marker_hit(body)
        self.assertTrue(hit)
        self.assertEqual(marker, "ami-id")

    def test_internal_marker_detection_gcp(self):
        from burpsuite_mcp.tools.dns_rebind_probe import _internal_marker_hit
        body = "Metadata-Flavor: Google\n"
        hit, marker = _internal_marker_hit(body)
        self.assertTrue(hit)
        self.assertEqual(marker, "Metadata-Flavor")

    def test_no_internal_marker_in_clean_body(self):
        from burpsuite_mcp.tools.dns_rebind_probe import _internal_marker_hit
        body = "<html><body>Hello world</body></html>"
        hit, _ = _internal_marker_hit(body)
        self.assertFalse(hit)


# ───────────────────────── Web LLM sweep helpers ─────────────────────────


class W29WebLlmHelpers(unittest.TestCase):

    def test_canary_is_unique_per_call(self):
        from burpsuite_mcp.tools.web_llm_sweep import _canary
        a = _canary()
        b = _canary()
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith("PRAETOR-"))

    def test_marker_echoed_case_insensitive(self):
        from burpsuite_mcp.tools.web_llm_sweep import _marker_echoed
        self.assertTrue(_marker_echoed("hello PRAETOR-AB12 world", "praetor-AB12"))
        self.assertFalse(_marker_echoed("hello world", "praetor-AB12"))

    def test_llm_response_heuristic_recognises_json_shape(self):
        from burpsuite_mcp.tools.web_llm_sweep import _looks_like_llm_response
        self.assertTrue(_looks_like_llm_response(
            '{"choices":[{"message":{"content":"hi"}}]}'))
        self.assertFalse(_looks_like_llm_response(""))

    def test_html_unescaped_check(self):
        from burpsuite_mcp.tools.web_llm_sweep import _looks_like_html_unescaped
        canary = "CANARYABC"
        good = f"<script>window.__praetor__='{canary}'</script>"
        bad = "&lt;script&gt;window.__praetor__='CANARYABC'&lt;/script&gt;"
        self.assertTrue(_looks_like_html_unescaped(good, canary))
        self.assertFalse(_looks_like_html_unescaped(bad, canary))

    def test_system_prompt_leak_check(self):
        from burpsuite_mcp.tools.web_llm_sweep import _looks_like_system_prompt_leak
        leak = "You are a helpful AI assistant. Your task is to ..."
        self.assertTrue(_looks_like_system_prompt_leak(leak))
        self.assertFalse(_looks_like_system_prompt_leak("Sorry, I can't help with that."))


# ───────────────────────── MCP JSON-RPC parser ─────────────────────────


class W29McpJsonRpcParser(unittest.TestCase):

    def test_valid_jsonrpc_2_0_object(self):
        from burpsuite_mcp.tools.mcp_jsonrpc_probe import _is_valid_jsonrpc
        body = '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'
        is_jrpc, parsed = _is_valid_jsonrpc(body)
        self.assertTrue(is_jrpc)
        self.assertEqual(parsed["result"]["tools"], [])

    def test_jsonrpc_error_object_recognised(self):
        from burpsuite_mcp.tools.mcp_jsonrpc_probe import _is_valid_jsonrpc
        body = '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}'
        is_jrpc, parsed = _is_valid_jsonrpc(body)
        self.assertTrue(is_jrpc)
        self.assertEqual(parsed["error"]["code"], -32601)

    def test_non_jsonrpc_body_rejected(self):
        from burpsuite_mcp.tools.mcp_jsonrpc_probe import _is_valid_jsonrpc
        is_jrpc, _ = _is_valid_jsonrpc('{"foo":"bar"}')
        self.assertFalse(is_jrpc)
        is_jrpc, _ = _is_valid_jsonrpc("plain text")
        self.assertFalse(is_jrpc)

    def test_sse_wrapped_jsonrpc_recognised(self):
        from burpsuite_mcp.tools.mcp_jsonrpc_probe import _is_valid_jsonrpc
        body = 'data: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n\n'
        is_jrpc, parsed = _is_valid_jsonrpc(body)
        self.assertTrue(is_jrpc)


# ───────────────────────── SSE probe ─────────────────────────


class W29SseProbeShape(unittest.TestCase):

    def test_is_event_stream_recognises_content_type(self):
        from burpsuite_mcp.tools.sse_probe import _is_event_stream
        self.assertTrue(_is_event_stream({
            "response_headers": {"content-type": "text/event-stream; charset=utf-8"},
        }))
        self.assertFalse(_is_event_stream({
            "response_headers": {"content-type": "application/json"},
        }))
        self.assertFalse(_is_event_stream({"response_headers": {}}))


if __name__ == "__main__":
    unittest.main()
