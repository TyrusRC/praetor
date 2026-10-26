"""Tests for the built-in OOB callback server (local_oob)."""

import socket
import time
import unittest
import urllib.request

from praetor.tools.collaborate._local_oob import LocalOobServer, OobHit
from praetor.tools.collaborate._local_oob_tools import _detect_local_ip


def _free_port() -> int:
    """Find an ephemeral port that is currently free."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LocalOobServerTest(unittest.TestCase):
    def setUp(self):
        self.port = _free_port()
        self.server = LocalOobServer(port=self.port, host="127.0.0.1")

    def tearDown(self):
        if self.server.running:
            self.server.stop()

    def test_start_and_running(self):
        result = self.server.start()
        self.assertTrue(self.server.running)
        self.assertIn(str(self.port), result)

    def test_double_start_returns_already_running(self):
        self.server.start()
        result = self.server.start()
        self.assertIn("already running", result)

    def test_stop(self):
        self.server.start()
        self.server.stop()
        self.assertFalse(self.server.running)

    def test_generate_id_uniqueness(self):
        ids = {self.server.generate_id() for _ in range(100)}
        self.assertEqual(len(ids), 100)

    def test_generate_id_length(self):
        uid = self.server.generate_id()
        self.assertEqual(len(uid), 16)

    def test_hit_recording_get(self):
        self.server.start()
        uid = self.server.generate_id()
        url = f"http://127.0.0.1:{self.port}/{uid}?test=1"
        urllib.request.urlopen(url, timeout=3)
        time.sleep(0.1)  # let handler finish
        hits = self.server.get_hits(uid)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].interaction_id, uid)
        self.assertEqual(hits[0].method, "GET")
        self.assertIn("test=1", hits[0].query)

    def test_hit_recording_post(self):
        self.server.start()
        uid = self.server.generate_id()
        url = f"http://127.0.0.1:{self.port}/{uid}"
        req = urllib.request.Request(url, data=b"payload=test", method="POST")
        urllib.request.urlopen(req, timeout=3)
        time.sleep(0.1)
        hits = self.server.get_hits(uid)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].method, "POST")
        self.assertIn("payload=test", hits[0].body)

    def test_filter_by_interaction_id(self):
        self.server.start()
        uid1 = self.server.generate_id()
        uid2 = self.server.generate_id()
        urllib.request.urlopen(f"http://127.0.0.1:{self.port}/{uid1}", timeout=3)
        urllib.request.urlopen(f"http://127.0.0.1:{self.port}/{uid2}", timeout=3)
        time.sleep(0.1)
        self.assertEqual(len(self.server.get_hits(uid1)), 1)
        self.assertEqual(len(self.server.get_hits(uid2)), 1)
        self.assertEqual(len(self.server.get_hits()), 2)

    def test_clear(self):
        self.server.start()
        urllib.request.urlopen(f"http://127.0.0.1:{self.port}/test", timeout=3)
        time.sleep(0.1)
        self.assertGreater(self.server.hit_count, 0)
        self.server.clear()
        self.assertEqual(self.server.hit_count, 0)

    def test_hit_count_property(self):
        self.server.start()
        self.assertEqual(self.server.hit_count, 0)
        urllib.request.urlopen(f"http://127.0.0.1:{self.port}/a", timeout=3)
        urllib.request.urlopen(f"http://127.0.0.1:{self.port}/b", timeout=3)
        time.sleep(0.1)
        self.assertEqual(self.server.hit_count, 2)


class DetectLocalIpTest(unittest.TestCase):
    def test_returns_valid_ip(self):
        ip = _detect_local_ip()
        parts = ip.split(".")
        self.assertEqual(len(parts), 4)
        for p in parts:
            self.assertTrue(0 <= int(p) <= 255)

    def test_not_empty(self):
        ip = _detect_local_ip()
        self.assertTrue(len(ip) > 0)


if __name__ == "__main__":
    unittest.main()
