"""Regression test for client.py error envelope on httpx exceptions.

httpx.ReadTimeout / ConnectTimeout sometimes carry empty `args` so str(e) is
the empty string. The bare exception leak surfaced as "Error: " (empty after
colon) in MCP tool output — the operator had no way to know whether the
problem was the MCP server, Burp, or the target. This test asserts the
envelope always carries a non-empty class-name-qualified error string and
a class-specific hint.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch, MagicMock

import httpx

from praetor import client


class ClientErrorEnvelope(unittest.TestCase):
    def _trigger_post_with_exc(self, exc: Exception) -> dict:
        """Run client.post and have httpx.AsyncClient.post raise `exc`."""
        fake_client = MagicMock()

        async def fake_post(*_a, **_kw):
            raise exc
        fake_client.post = fake_post

        async def run():
            with patch.object(client, "_get_client",
                              return_value=fake_client):
                return await client.post("/api/anything", json={"k": "v"})
        return asyncio.run(run())

    def test_read_timeout_with_empty_message(self):
        # The specific failure observed in live test: ReadTimeout('') leaks
        # str(e) == '' through the generic except → bare "Error: ".
        env = self._trigger_post_with_exc(httpx.ReadTimeout(""))
        self.assertNotEqual(env["error"], "",
                            "envelope error must never be empty")
        self.assertIn("ReadTimeout", env["error"],
                      "error must include exception class for diagnostics")
        self.assertTrue(env["hint"],
                        "ReadTimeout must produce a non-empty hint")
        self.assertIn("Timeout", env["hint"] + env["error"],
                      "hint should mention the timeout class")

    def test_connect_timeout_with_empty_message(self):
        env = self._trigger_post_with_exc(httpx.ConnectTimeout(""))
        self.assertNotEqual(env["error"], "")
        self.assertIn("ConnectTimeout", env["error"])
        self.assertTrue(env["hint"])

    def test_connect_timeout_diagnosed_as_unreachable_not_slow(self):
        # ConnectTimeout is a TimeoutException (not ConnectError), so it lands
        # in the generic handler. A connect-phase timeout means the REST bridge
        # is unreachable — NOT that Burp is slow answering. The hint must point
        # at connectivity (health check / reload extension / WSL host), and must
        # NOT tell the operator to raise BURP_API_TIMEOUT, which does nothing
        # when nothing is listening.
        env = self._trigger_post_with_exc(httpx.ConnectTimeout(""))
        self.assertEqual(env["code"], "extension_unreachable")
        self.assertIn("/api/health", env["hint"])
        self.assertNotIn("BURP_API_TIMEOUT", env["hint"])

    def test_read_timeout_diagnosed_as_slow_response(self):
        # ReadTimeout means the connection was established but Burp did not
        # answer in time — raising BURP_API_TIMEOUT is the right lever here.
        env = self._trigger_post_with_exc(httpx.ReadTimeout(""))
        self.assertIn("BURP_API_TIMEOUT", env["hint"])
        self.assertNotIn("/api/health", env["hint"])

    def test_generic_exception_still_carries_class_name(self):
        env = self._trigger_post_with_exc(ValueError(""))
        self.assertNotEqual(env["error"], "")
        self.assertIn("ValueError", env["error"])
        # Generic exceptions don't get a class-specific hint
        self.assertEqual(env["hint"], "")

    def test_exception_with_real_message_preserved(self):
        env = self._trigger_post_with_exc(httpx.ReadTimeout("explicit timeout details"))
        self.assertIn("explicit timeout details", env["error"])
        self.assertIn("ReadTimeout", env["error"])


if __name__ == "__main__":
    unittest.main()
