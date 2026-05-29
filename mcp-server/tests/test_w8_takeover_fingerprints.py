"""Tests for W8 +34 takeover fingerprints in recon_extended/fingerprints.py."""

from __future__ import annotations

import unittest

from burpsuite_mcp.tools.recon_extended.fingerprints import TAKEOVER_FINGERPRINTS


# W8 additions (subset of full 34 — spot-check the high-yield ones).
_W8_FINGERPRINTS = [
    "framer.app", "framer.website", "cleverapps.io", "canny.io", "gitbook.io",
    "helpdocs.io", "hubspot.net", "jetbrains.space", "leadpages.co",
    "meteorapp.com", "pingdom.com", "readthedocs.io", "simplebooklet.com",
    "softr.io", "wasabisys.com", "applytojob.com", "furyns.com",
]


class W8FingerprintsTest(unittest.TestCase):

    def test_w8_fingerprints_loaded(self):
        for host in _W8_FINGERPRINTS:
            self.assertIn(host, TAKEOVER_FINGERPRINTS, f"W8 fingerprint missing: {host}")

    def test_fingerprint_schema(self):
        for host in _W8_FINGERPRINTS:
            entry = TAKEOVER_FINGERPRINTS[host]
            self.assertIn("cname", entry)
            self.assertIn("body", entry)
            self.assertIsInstance(entry["cname"], str)
            self.assertIsInstance(entry["body"], str)

    def test_total_count_post_w8(self):
        # W7 baseline ~81 entries; W8 adds 34. Allow some slack for future growth.
        self.assertGreaterEqual(len(TAKEOVER_FINGERPRINTS), 110,
            f"Total fingerprint count below post-W8 baseline: {len(TAKEOVER_FINGERPRINTS)}")


if __name__ == "__main__":
    unittest.main()
