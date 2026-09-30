"""IP-allowlist coverage auditor — pure classifier, differential, redaction.

No live network: exercises the classification and redaction helpers directly,
plus the surface-input parser.
"""

import unittest

from praetor.tools.redteam import ip_allowlist as ipa

_TOKEN = "ghp_ABCDEF0123456789abcdef0123456789_4f2a"


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


if __name__ == "__main__":
    unittest.main()
