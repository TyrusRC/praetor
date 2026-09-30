"""IP-allowlist coverage auditor — pure classifier, differential, redaction.

No live network: exercises the classification and redaction helpers directly,
plus the surface-input parser.
"""

import json as _json
import unittest
from unittest import mock

from praetor.tools.redteam import ip_allowlist as ipa

_TOKEN = "ghp_ABCDEF0123456789abcdef0123456789_4f2a"


def _tool_fn():
    from praetor import server
    return server.mcp._tool_manager._tools["ip_allowlist_coverage"].fn


def _spoof_key_set():
    return {h.lower() for h in ipa.STANDARD_SPOOF_HEADERS}


def _fake_probe(responder):
    """Build a stand-in for ipa._probe. `responder(surface)` -> (status, body).

    A surface carrying one of the standard spoof headers is a header-trust probe;
    one without is the baseline. The responder decides the status/body.
    """
    async def fake(client, surface, auth_value, timeout):
        status, body = responder(surface)
        return status, body, ""
    return fake


def _spoof_header_in(surface):
    """Return (header, value) of the injected spoof header, or (None, None)."""
    for h, v in (surface.get("headers") or {}).items():
        if h.lower() in _spoof_key_set():
            return h, v
    return None, None


class TestProbeVerdict(unittest.TestCase):
    def test_403_ip_allowlist_body_is_blocked(self):
        raw, _ = ipa._probe_verdict(403, "Your IP allow list has blocked access",
                                    {403, 451}, "")
        self.assertEqual(raw, "BLOCKED")

    def test_200_is_allowed(self):
        raw, _ = ipa._probe_verdict(200, '{"login":"octocat"}', {403, 451}, "")
        self.assertEqual(raw, "ALLOWED")

    def test_401_is_bad_auth(self):
        raw, _ = ipa._probe_verdict(401, "Bad credentials", {403, 451}, "")
        self.assertEqual(raw, "BAD_AUTH")

    def test_403_without_phrase_is_still_block_status_only(self):
        raw, note = ipa._probe_verdict(403, "Forbidden", {403, 451}, "")
        self.assertEqual(raw, "BLOCKED")
        self.assertIn("status-only", note)

    def test_regex_narrows_block(self):
        # 403 but body does not match the operator's regex -> not a confirmed block
        raw, _ = ipa._probe_verdict(403, "Forbidden", {403, 451}, r"ip allow list")
        self.assertEqual(raw, "INCONCLUSIVE")
        raw2, _ = ipa._probe_verdict(403, "denied by ip allow list", {403, 451},
                                     r"ip allow list")
        self.assertEqual(raw2, "BLOCKED")

    def test_no_response_is_inconclusive(self):
        raw, _ = ipa._probe_verdict(None, "", {403, 451}, "")
        self.assertEqual(raw, "INCONCLUSIVE")


class TestSurfaceVerdict(unittest.TestCase):
    def test_single_mode(self):
        self.assertEqual(ipa._surface_verdict("BLOCKED", None), "ENFORCED")
        self.assertEqual(ipa._surface_verdict("ALLOWED", None), "GAP")
        self.assertEqual(ipa._surface_verdict("BAD_AUTH", None), "INCONCLUSIVE")

    def test_differential(self):
        # on-list allowed + off-list blocked -> control works
        self.assertEqual(ipa._surface_verdict("BLOCKED", "ALLOWED"), "ENFORCED")
        # both allowed -> surface ignores the allowlist
        self.assertEqual(ipa._surface_verdict("ALLOWED", "ALLOWED"), "GAP")
        # off-list allowed alone -> gap
        self.assertEqual(ipa._surface_verdict("ALLOWED", "BLOCKED"), "GAP")
        # both blocked -> can't conclude (surface down / bad pivot)
        self.assertEqual(ipa._surface_verdict("BLOCKED", "BLOCKED"), "INCONCLUSIVE")


class TestRedaction(unittest.TestCase):
    def test_shape_hides_value_shows_ends(self):
        shape = ipa._shape_secret(_TOKEN)
        self.assertNotIn(_TOKEN, shape)
        self.assertTrue(shape.startswith("ghp_"))
        self.assertTrue(shape.endswith("4f2a"))

    def test_redact_replaces_token_everywhere(self):
        text = f"Authorization: {_TOKEN} sent to api"
        out = ipa._redact(text, _TOKEN)
        self.assertNotIn(_TOKEN, out)
        self.assertIn(ipa._shape_secret(_TOKEN), out)

    def test_short_secret_not_naively_substringed(self):
        # secrets < 6 chars are left alone (avoid mangling unrelated text)
        self.assertEqual(ipa._redact("the cat sat", "cat"), "the cat sat")


class TestSurfaceParsing(unittest.TestCase):
    def test_json_array(self):
        s = '[{"label":"api","url":"https://api.x/user"},' \
            '{"label":"gql","url":"https://api.x/graphql","method":"post"}]'
        out = ipa._parse_surfaces(s)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["label"], "api")
        self.assertEqual(out[1]["method"], "POST")

    def test_newline_and_pipe_list(self):
        s = "web|https://x.io/dash|GET\nrawurl https://x.io/raw HEAD\nhttps://x.io/lfs"
        out = ipa._parse_surfaces(s)
        self.assertEqual(len(out), 3)
        self.assertEqual(out[0]["method"], "GET")
        self.assertEqual(out[1]["method"], "HEAD")
        self.assertEqual(out[2]["url"], "https://x.io/lfs")

    def test_comment_and_blank_skipped(self):
        out = ipa._parse_surfaces("# comment\n\nhttps://x.io/a")
        self.assertEqual(len(out), 1)


class TestBlockedStatusParse(unittest.TestCase):
    def test_default_and_custom(self):
        self.assertEqual(ipa._parse_blocked_status(""), {403, 451})
        self.assertEqual(ipa._parse_blocked_status("403, 429 451"), {403, 429, 451})


class TestRunRedaction(unittest.IsolatedAsyncioTestCase):
    async def test_returned_matrix_never_leaks_token(self):
        # No proxy, unroutable host -> INCONCLUSIVE, but the point is: the raw
        # token must not appear anywhere in the returned structure, and its
        # shape must be present in the `auth` field.
        import json as _json

        from praetor import server
        fn = server.mcp._tool_manager._tools["ip_allowlist_coverage"].fn
        res = await fn(
            surfaces="probe|http://127.0.0.1:1/never|GET",
            auth_header=f"Bearer {_TOKEN}",
            timeout=1,
        )
        blob = _json.dumps(res)
        self.assertNotIn(_TOKEN, blob)
        self.assertEqual(res["auth"], ipa._shape_secret(f"Bearer {_TOKEN}"))
        self.assertEqual(res["results"][0]["verdict"], "INCONCLUSIVE")


class TestSpoofProbes(unittest.TestCase):
    def test_off_when_empty(self):
        self.assertEqual(ipa._spoof_probes("", "127.0.0.1"), [])

    def test_auto_set_shape_and_cap(self):
        probes = ipa._spoof_probes("auto", "127.0.0.1")
        # 8 headers; XFF + Forwarded each add 2 variants -> 8 + 4 = 12, at cap.
        self.assertEqual(len(probes), 12)
        self.assertLessEqual(len(probes), ipa._SPOOF_CAP)
        headers = {p["header"] for p in probes}
        self.assertEqual(headers, set(ipa.STANDARD_SPOOF_HEADERS))
        # XFF has single + leftmost + rightmost.
        xff = [p for p in probes if p["header"] == "X-Forwarded-For"]
        self.assertEqual({p["position"] for p in xff},
                         {"single", "leftmost", "rightmost"})
        # A non-differential header has only a single probe.
        real = [p for p in probes if p["header"] == "X-Real-IP"]
        self.assertEqual(len(real), 1)
        self.assertEqual(real[0]["position"], "single")

    def test_differential_variant_values(self):
        probes = ipa._spoof_probes("X-Forwarded-For", "10.0.0.5")
        by_pos = {p["position"]: p["value"] for p in probes}
        self.assertEqual(by_pos["single"], "10.0.0.5")
        self.assertEqual(by_pos["leftmost"], f"10.0.0.5, {ipa._SPOOF_DECOY_IP}")
        self.assertEqual(by_pos["rightmost"], f"{ipa._SPOOF_DECOY_IP}, 10.0.0.5")

    def test_forwarded_uses_for_syntax(self):
        probes = ipa._spoof_probes("Forwarded", "127.0.0.1")
        by_pos = {p["position"]: p["value"] for p in probes}
        self.assertEqual(by_pos["single"], "for=127.0.0.1")
        self.assertEqual(by_pos["leftmost"],
                         f"for=127.0.0.1, for={ipa._SPOOF_DECOY_IP}")

    def test_custom_comma_list_no_dupes(self):
        probes = ipa._spoof_probes("X-Real-IP, True-Client-IP, x-real-ip", "1.2.3.4")
        self.assertEqual(len(probes), 2)
        self.assertEqual({p["header"] for p in probes},
                         {"X-Real-IP", "True-Client-IP"})


class TestHeaderTrustRun(unittest.IsolatedAsyncioTestCase):
    async def test_baseline_blocked_xff_allowed_is_bypass(self):
        # Baseline 403; the X-Forwarded-For single-value spoof gets served (200).
        def responder(surface):
            hdr, val = _spoof_header_in(surface)
            if hdr is None:
                return 403, "Forbidden"
            return (200, '{"login":"octocat"}') if val == "127.0.0.1" else (403, "Forbidden")

        with mock.patch.object(ipa, "_probe", _fake_probe(responder)):
            res = await _tool_fn()(
                surfaces="api|https://api.example.test/user|GET",
                auth_header=f"Bearer {_TOKEN}",
                spoof_headers="X-Forwarded-For",
                timeout=1,
            )
        row = res["results"][0]
        self.assertEqual(row["off_list"]["verdict"], "BLOCKED")
        # All three positions probed and recorded.
        positions = {e["position"] for e in row["header_trust"]}
        self.assertEqual(positions, {"single", "leftmost", "rightmost"})
        single = next(e for e in row["header_trust"] if e["position"] == "single")
        self.assertEqual(single["verdict"], "HEADER_TRUST_BYPASS")
        self.assertEqual(single["status"], 200)
        # Top-level bypass records header + position.
        self.assertEqual(res["header_bypasses"],
                         [{"label": "api", "header": "X-Forwarded-For",
                           "position": "single"}])
        # Auth never leaks when spoof mode is on.
        self.assertNotIn(_TOKEN, _json.dumps(res))
        self.assertEqual(res["auth"], ipa._shape_secret(f"Bearer {_TOKEN}"))

    async def test_leftmost_wins_records_position(self):
        # App trusts the LEFTMOST value: any XFF whose first hop is 127.0.0.1 served.
        def responder(surface):
            hdr, val = _spoof_header_in(surface)
            if hdr is None:
                return 403, "Forbidden"
            return (200, "ok") if val.startswith("127.0.0.1") else (403, "Forbidden")

        with mock.patch.object(ipa, "_probe", _fake_probe(responder)):
            res = await _tool_fn()(
                surfaces="api|https://api.example.test/user|GET",
                spoof_headers="X-Forwarded-For",
                timeout=1,
            )
        positions = {b["position"] for b in res["header_bypasses"]}
        self.assertEqual(positions, {"single", "leftmost"})
        self.assertNotIn("rightmost", positions)

    async def test_baseline_blocked_all_spoof_blocked_no_bypass(self):
        def responder(surface):
            return 403, "Forbidden"  # everything blocked

        with mock.patch.object(ipa, "_probe", _fake_probe(responder)):
            res = await _tool_fn()(
                surfaces="api|https://api.example.test/user|GET",
                spoof_headers="auto",
                timeout=1,
            )
        row = res["results"][0]
        self.assertEqual(len(row["header_trust"]), 12)
        self.assertTrue(all(e["verdict"] == "BLOCKED" for e in row["header_trust"]))
        self.assertEqual(res["header_bypasses"], [])

    async def test_baseline_allowed_header_test_is_na(self):
        # Off-list already served -> surface is a GAP; no header probing (no double-count).
        def responder(surface):
            return 200, '{"login":"octocat"}'

        with mock.patch.object(ipa, "_probe", _fake_probe(responder)):
            res = await _tool_fn()(
                surfaces="api|https://api.example.test/user|GET",
                spoof_headers="auto",
                timeout=1,
            )
        row = res["results"][0]
        self.assertEqual(row["verdict"], "GAP")
        self.assertEqual(row["header_trust"], [])  # N/A, not probed
        self.assertEqual(res["header_bypasses"], [])


class TestIpFormatVariants(unittest.TestCase):
    def test_loopback_encodings_present(self):
        vals = {v for _, v in ipa._ip_format_variants("127.0.0.1")}
        self.assertIn("2130706433", vals)      # dotless-decimal
        self.assertIn("0x7f000001", vals)      # hex-dword
        self.assertIn("127.1", vals)           # mixed/short
        self.assertIn("::ffff:127.0.0.1", vals)  # IPv6-mapped
        self.assertIn("127.0.0.1.", vals)      # trailing-dot
        self.assertIn("::1", vals)             # IPv6 loopback (input is loopback)

    def test_non_loopback_skips_ipv6_loopback(self):
        vals = {v for _, v in ipa._ip_format_variants("8.8.8.8")}
        self.assertNotIn("::1", vals)
        self.assertNotIn("[::1]", vals)
        self.assertIn("::ffff:8.8.8.8", vals)   # mapped still generated
        self.assertIn("134744072", vals)        # dotless-decimal of 8.8.8.8

    def test_invalid_ip_returns_empty(self):
        self.assertEqual(ipa._ip_format_variants("nope"), [])
        self.assertEqual(ipa._ip_format_variants(""), [])

    def test_values_are_unique(self):
        vals = [v for _, v in ipa._ip_format_variants("127.0.0.1")]
        self.assertEqual(len(vals), len(set(vals)))


class TestIpFormatProbes(unittest.TestCase):
    def test_only_ip_bearing_headers(self):
        headers = ipa._ip_format_header_set("auto")
        self.assertIn("X-Forwarded-For", headers)
        self.assertIn("X-Real-IP", headers)
        # Forwarded (for= syntax) and X-Forwarded-Host (hostname) are excluded.
        self.assertNotIn("Forwarded", headers)
        self.assertNotIn("X-Forwarded-Host", headers)

    def test_custom_list_intersects_and_dedupes(self):
        headers = ipa._ip_format_header_set("X-Real-IP, Forwarded, x-real-ip")
        self.assertEqual(headers, ["X-Real-IP"])

    def test_empty_spoof_no_probes(self):
        self.assertEqual(ipa._ip_format_probes("", "127.0.0.1"), [])

    def test_probes_capped(self):
        probes = ipa._ip_format_probes("auto", "127.0.0.1")
        self.assertLessEqual(len(probes), ipa._FMT_CAP)
        self.assertTrue(all({"header", "label", "value"} <= p.keys() for p in probes))


class TestSourceBindCheck(unittest.TestCase):
    def test_invalid_ip(self):
        self.assertIn("not a valid IP", ipa._check_source_bind("not-an-ip"))

    def test_loopback_bindable(self):
        self.assertEqual(ipa._check_source_bind("127.0.0.1"), "")

    def test_unowned_ip_reports_clear_error(self):
        with mock.patch("socket.socket") as ms:
            ms.return_value.bind.side_effect = OSError(99, "Cannot assign requested address")
            msg = ipa._check_source_bind("192.0.2.1")
        self.assertIn("cannot be bound", msg)


class TestIpFormatRun(unittest.IsolatedAsyncioTestCase):
    async def test_format_variant_flips_block_to_bypass(self):
        # Baseline 403; the dotless-decimal encoding of 127.0.0.1 is served (200).
        def responder(surface):
            hdr, val = _spoof_header_in(surface)
            if hdr is None:
                return 403, "Forbidden"
            return (200, "ok") if val == "2130706433" else (403, "Forbidden")

        with mock.patch.object(ipa, "_probe", _fake_probe(responder)):
            res = await _tool_fn()(
                surfaces="api|https://api.example.test/user|GET",
                auth_header=f"Bearer {_TOKEN}",
                spoof_headers="X-Real-IP",
                timeout=1,
            )
        row = res["results"][0]
        self.assertEqual(row["off_list"]["verdict"], "BLOCKED")
        fmt = {e["value"]: e["verdict"] for e in row["ip_format"]}
        self.assertEqual(fmt["2130706433"], "IP_FORMAT_BYPASS")
        # Other encodings stayed blocked.
        self.assertTrue(any(v == "BLOCKED" for v in fmt.values()))
        # Top-level record carries header + format + value.
        self.assertIn(
            {"label": "api", "header": "X-Real-IP",
             "format": "dotless-decimal", "value": "2130706433"},
            res["ip_format_bypasses"])
        # Auth never leaks in format-probe mode.
        self.assertNotIn(_TOKEN, _json.dumps(res))
        self.assertEqual(res["auth"], ipa._shape_secret(f"Bearer {_TOKEN}"))

    async def test_baseline_allowed_no_format_probing(self):
        def responder(surface):
            return 200, "ok"  # already served -> GAP, no re-probe

        with mock.patch.object(ipa, "_probe", _fake_probe(responder)):
            res = await _tool_fn()(
                surfaces="api|https://api.example.test/user|GET",
                spoof_headers="X-Real-IP",
                timeout=1,
            )
        row = res["results"][0]
        self.assertEqual(row["verdict"], "GAP")
        self.assertEqual(row["ip_format"], [])
        self.assertEqual(res["ip_format_bypasses"], [])


class TestSourceBindRun(unittest.IsolatedAsyncioTestCase):
    async def test_source_bind_plumbs_local_address(self):
        seen = {}

        def fake_transport(*args, **kwargs):
            seen.update(kwargs)
            return mock.AsyncMock()

        with mock.patch.object(ipa.httpx, "AsyncHTTPTransport",
                               side_effect=fake_transport) as tp, \
             mock.patch.object(ipa, "_probe",
                               _fake_probe(lambda s: (403, "Forbidden"))):
            res = await _tool_fn()(
                surfaces="api|https://api.example.test/user|GET",
                source_bind="127.0.0.1",
                timeout=1,
            )
        tp.assert_called()
        self.assertEqual(seen.get("local_address"), "127.0.0.1")
        self.assertNotIn("error", res)
        self.assertEqual(res["source_bind"], "127.0.0.1")

    async def test_invalid_source_bind_errors_before_probing(self):
        res = await _tool_fn()(
            surfaces="api|https://api.example.test/user|GET",
            source_bind="999.999.999.999",
            timeout=1,
        )
        self.assertIn("error", res)
        self.assertNotIn("results", res)


if __name__ == "__main__":
    unittest.main()
