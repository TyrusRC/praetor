"""Per-host noise governor (praetor._noise_governor) — gap found reviewing
ARTEX's egress/pace.go: Rule 6a bounds ONE call's volume, nothing throttled
the whole session's request rate per host. Off by default (matches every
other test's expectation of unthrottled sends); wired into client.post()
for target-dispatching paths only.

These tests use REAL wall-clock asyncio.sleep, not a mocked clock — Rule
21b: real execution, real evidence. Timings use a generous margin so they
don't flake on a loaded CI box.
"""

from __future__ import annotations

import asyncio
import time
import unittest
from unittest.mock import AsyncMock, patch

from praetor import _noise_governor as ng
from praetor import client as c


class NoiseGovernorUnitTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        ng.reset_for_test()
        ng.set_profile("off")

    def tearDown(self):
        ng.reset_for_test()
        ng.set_profile("off")

    async def test_off_by_default_no_delay(self):
        self.assertEqual(ng.get_profile(), "off")
        t0 = time.monotonic()
        for _ in range(20):
            d = await ng.wait_for_host("x.example.com")
            self.assertEqual(d, 0.0)
        self.assertLess(time.monotonic() - t0, 0.2)

    async def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            ng.set_profile("ludicrous")
        self.assertEqual(ng.get_profile(), "off")  # unchanged on rejection

    async def test_quiet_profile_bursts_then_throttles(self):
        ng.set_profile("quiet")  # rate=0.5/s, burst=2
        t0 = time.monotonic()
        delays = [await ng.wait_for_host("burst.example.com") for _ in range(3)]
        elapsed = time.monotonic() - t0
        self.assertLess(delays[0], 0.5, "first request should use burst capacity")
        self.assertLess(delays[1], 0.5, "second request should use burst capacity")
        self.assertGreater(delays[2], 1.0, "third request should wait for refill (~2s)")
        self.assertGreater(elapsed, 1.0)

    async def test_hosts_are_independent(self):
        ng.set_profile("quiet")
        for _ in range(2):  # exhaust host A's burst
            await ng.wait_for_host("a.example.com")
        # host B has its own bucket — still bursts freely
        t0 = time.monotonic()
        d = await ng.wait_for_host("b.example.com")
        self.assertLess(time.monotonic() - t0, 0.5)
        self.assertLess(d, 0.5)

    async def test_stats_reports_per_host_counts(self):
        ng.set_profile("balanced")
        await ng.wait_for_host("a.example.com")
        await ng.wait_for_host("a.example.com")
        await ng.wait_for_host("b.example.com")
        s = ng.stats()
        self.assertEqual(s["profile"], "balanced")
        self.assertEqual(s["hosts"]["a.example.com"], 2)
        self.assertEqual(s["hosts"]["b.example.com"], 1)


class NoiseGovernorClientWiringTest(unittest.IsolatedAsyncioTestCase):
    """client.post() must pace target-dispatching paths and never pace
    Burp-state-only ones — verified against the real post() function with
    only the network boundary (httpx) mocked, not the governor."""

    def setUp(self):
        ng.reset_for_test()
        ng.set_profile("off")

    def tearDown(self):
        ng.reset_for_test()
        ng.set_profile("off")

    class _FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"ok": True}

    async def test_paced_path_with_url_is_throttled(self):
        ng.set_profile("quiet")
        fake_httpx_client = AsyncMock()
        fake_httpx_client.post = AsyncMock(return_value=self._FakeResp())
        with patch.object(c, "_get_client", AsyncMock(return_value=fake_httpx_client)):
            t0 = time.monotonic()
            for _ in range(3):
                await c.post("/api/http/curl",
                             json={"url": "https://paced.example.com/x", "method": "GET"})
            elapsed = time.monotonic() - t0
        self.assertGreater(elapsed, 1.0, "3rd call on a quiet profile must wait for refill")

    async def test_burp_state_path_is_never_paced(self):
        ng.set_profile("aggressive")  # even the fastest profile must not matter here
        fake_httpx_client = AsyncMock()
        fake_httpx_client.post = AsyncMock(return_value=self._FakeResp())
        with patch.object(c, "_get_client", AsyncMock(return_value=fake_httpx_client)):
            t0 = time.monotonic()
            for _ in range(10):
                await c.post("/api/findings/save", json={"domain": "x"})
            elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 0.3, "a Burp-state-only path must never be paced")
        self.assertEqual(ng.stats()["hosts"], {}, "no host should have been charged")

    async def test_paced_path_without_url_is_not_paced(self):
        """A paced-prefix path with no `url` in the body (e.g. a malformed
        call) must not crash or hang — maybe_pace is a no-op without a host."""
        ng.set_profile("quiet")
        fake_httpx_client = AsyncMock()
        fake_httpx_client.post = AsyncMock(return_value=self._FakeResp())
        with patch.object(c, "_get_client", AsyncMock(return_value=fake_httpx_client)):
            out = await asyncio.wait_for(
                c.post("/api/http/curl", json={"method": "GET"}), timeout=1.0)
        self.assertEqual(out, {"ok": True})


if __name__ == "__main__":
    unittest.main()
