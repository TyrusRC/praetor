"""smuggle_acl_probe — front-end ACL bypass via request smuggling.

Mocks the raw send core (client.post); no live network. Guards the three
verdicts that matter: a flip to 2xx is a BYPASS, a held 403 is not, and an
already-served path is N/A.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from praetor.tools.testing_extended import smuggle_acl


def _run(**kw):
    return asyncio.run(smuggle_acl._run_probe(**kw))


class SmuggleAclProbeTest(unittest.TestCase):

    def _probe(self, responses, **kw):
        """Run the probe with client.post returning `responses` in order and
        scope forced open."""
        with patch.object(smuggle_acl, "client") as mc, \
             patch.object(smuggle_acl, "scope_or_error",
                          new=AsyncMock(return_value="")):
            mc.post = AsyncMock(side_effect=responses)
            return _run(base="https://target.example",
                        restricted_path="/admin", **kw)

    def test_baseline_403_smuggled_200_is_bypass(self):
        out = self._probe(
            [
                {"status_code": 403, "response_length": 20},          # baseline
                {"status_code": 200, "response_length": 5000,
                 "send_ref": "send-1"},                               # clte
            ],
            techniques="clte",
        )
        self.assertEqual(out["bypassed"], ["clte"])
        r = out["results"][0]
        self.assertEqual(r["verdict"], "BYPASS")
        self.assertEqual(r["status"], 200)
        # direct send has no proxy index — falls back to send_ref
        self.assertEqual(r["proxy_history_index"], "send-1")

    def test_baseline_403_smuggled_403_no_bypass(self):
        out = self._probe(
            [
                {"status_code": 403, "response_length": 20},
                {"status_code": 403, "response_length": 20},
            ],
            techniques="clte",
        )
        self.assertEqual(out["bypassed"], [])
        self.assertEqual(out["results"][0]["verdict"], "no-effect")

    def test_baseline_200_is_not_applicable(self):
        out = self._probe(
            [{"status_code": 200, "response_length": 1234}],
            techniques="clte,tecl,te0,cl0",
        )
        self.assertEqual(out["bypassed"], [])
        self.assertEqual(out["results"], [])
        self.assertIn("not front-end-restricted", out["summary"])

    def test_material_length_flip_while_4xx_is_bypass(self):
        # Same blocked status, but a materially larger body ⇒ backend served
        # different content past the ACL.
        out = self._probe(
            [
                {"status_code": 403, "response_length": 20},
                {"status_code": 403, "response_length": 8000},
            ],
            techniques="tecl",
        )
        self.assertEqual(out["bypassed"], ["tecl"])
        self.assertEqual(out["results"][0]["verdict"], "BYPASS")


if __name__ == "__main__":
    unittest.main()
