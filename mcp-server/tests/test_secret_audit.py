"""Multi-service exposed-secret validator (Package 4b).

Pure classification/redaction/safety coverage + one monkeypatched safe
validator. No real network. Safety invariant under test: financial/destructive
key types are NEVER auto-validated.
"""

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class TestClassify(unittest.TestCase):
    def setUp(self):
        from praetor.tools import secret_audit as s
        self.s = s

    def test_classifies_known_types(self):
        cases = {
            "AKIAIOSFODNN7EXAMPLE": "aws_access_key",
            "ghp_" + "A" * 36: "github_token",
            "glpat-" + "A" * 20: "gitlab_token",
            "xoxb-" + "1" * 10 + "-abcdef": "slack_token",
            "sk_live_" + "A" * 24: "stripe_live",
            "SG." + "A" * 22 + "." + "B" * 43: "sendgrid",
            "AIza" + "0123456789abcdefghijklmnopqrstuvwxyz"[:35]: "google_api_key",
        }
        for secret, kind in cases.items():
            self.assertEqual(self.s.classify_secret(secret), kind, secret[:8])

    def test_unknown_secret_is_none(self):
        self.assertIsNone(self.s.classify_secret("just-a-random-string"))

    def test_redact_never_leaks_body(self):
        r = self.s.redact_secret("ghp_" + "A" * 36)
        self.assertIn("…", r)
        self.assertNotIn("A" * 20, r)

    def test_financial_types_not_safe_to_auto_validate(self):
        for kind in ("stripe_live", "aws_access_key", "twilio", "sendgrid", "mailgun"):
            self.assertFalse(self.s.is_safe_to_validate(kind), kind)

    def test_whoami_types_safe_to_auto_validate(self):
        for kind in ("github_token", "gitlab_token", "slack_token", "google_api_key"):
            self.assertTrue(self.s.is_safe_to_validate(kind), kind)

    def test_every_type_has_impact_text(self):
        for kind in self.s.SECRET_TYPES:
            self.assertTrue(self.s.impact_for(kind), kind)


class TestTool(unittest.TestCase):
    def test_financial_key_is_classified_not_called(self):
        import asyncio
        from praetor.tools import secret_audit as s

        called = []

        async def fake_get(method, url, headers, timeout, data=None):
            called.append(url)
            return 200, "{}", {}

        s._http_req = fake_get
        from mcp.server.fastmcp import FastMCP

        reg = {}
        mcp = FastMCP("t")
        mcp.tool = lambda: (lambda fn: reg.setdefault(fn.__name__, fn) or fn)
        s.register(mcp)

        stripe = "sk_live_" + "A" * 24
        out = asyncio.run(reg["audit_exposed_secret"](stripe))
        self.assertEqual(out["kind"], "stripe_live")
        self.assertFalse(out["auto_validated"])
        self.assertEqual(called, [])                 # NEVER hit a live Stripe key
        self.assertNotIn(stripe, str(out))           # redacted

    def test_safe_key_is_validated(self):
        import asyncio
        from praetor.tools import secret_audit as s

        async def fake_get(method, url, headers, timeout, data=None):
            return 200, '{"login":"victim"}', {"x-oauth-scopes": "repo, admin:org"}

        s._http_req = fake_get
        from mcp.server.fastmcp import FastMCP

        reg = {}
        mcp = FastMCP("t")
        mcp.tool = lambda: (lambda fn: reg.setdefault(fn.__name__, fn) or fn)
        s.register(mcp)

        gh = "ghp_" + "A" * 36
        out = asyncio.run(reg["audit_exposed_secret"](gh))
        self.assertEqual(out["kind"], "github_token")
        self.assertTrue(out["auto_validated"])
        self.assertTrue(out["active"])
        self.assertNotIn(gh, str(out))


if __name__ == "__main__":
    unittest.main()
