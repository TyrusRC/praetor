"""A direct send is citable: the send_ref handle must reach the agent.

A direct send (request smuggling / absolute-target SSRF / pinned HTTP version)
never enters Burp's proxy history, so it has no proxy_history_index. The
extension stores it under a `send_ref` ('send-N') that save_finding accepts as
evidence. If the send tools drop that handle from their output, the send is
evidence-orphaned again — this guards the surfacing.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from praetor.tools.send import _send
from praetor.tools.send._format import _format_response


def _get_tools():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    _send.register(_Stub())
    return captured


class SendRefSurfacingTest(unittest.TestCase):

    def test_formatter_surfaces_send_ref(self):
        out = _format_response({
            "status_code": 200, "response_length": 12,
            "response_headers": [], "response_body": "hi",
            "send_ref": "send-7",
        })
        self.assertIn("send_ref=send-7", out)
        self.assertIn("evidence=", out, "must show how to cite it")

    def test_formatter_omits_send_ref_when_absent(self):
        out = _format_response({
            "status_code": 200, "response_length": 12,
            "response_headers": [], "response_body": "hi",
            "history_index": 42,
        })
        self.assertNotIn("send_ref", out, "normal proxy-visible send has no handle line")

    def test_send_raw_request_returns_send_ref(self):
        tool = _get_tools()["send_raw_request"]

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_length": 3,
                    "response_headers": [], "response_body": "abc",
                    "history_index": -1, "send_ref": "send-3"}

        with patch.object(_send.client, "post",
                          new=AsyncMock(side_effect=fake_post)):
            out = asyncio.run(tool("GET / HTTP/1.1\r\nHost: t\r\n\r\n", "t",
                                   http_version="direct"))
        self.assertIn("send-3", out)

    def test_get_sent_request_fetches_stored_send(self):
        tool = _get_tools()["get_sent_request"]
        seen: dict = {}

        async def fake_get(path, params=None):
            seen["path"] = path
            return {"status_code": 200, "response_length": 3,
                    "response_headers": [], "response_body": "abc",
                    "send_ref": "send-3"}

        with patch.object(_send.client, "get",
                          new=AsyncMock(side_effect=fake_get)):
            out = asyncio.run(tool("send-3"))
        self.assertEqual(seen["path"], "/api/http/stored/send-3")
        self.assertIn("send-3", out)


if __name__ == "__main__":
    unittest.main()
