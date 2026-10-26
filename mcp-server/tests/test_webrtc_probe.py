"""Tests for webrtc_probe: STUN packet building/parsing, ICE IP leak regex."""

import struct
import unittest

from praetor.tools.webrtc_probe import (
    _build_stun_request,
    _parse_stun_response,
    _MAGIC,
    _BINDING_REQUEST,
    _ALLOCATE_REQUEST,
    _PRIVATE_IP,
)


class StunBuildTest(unittest.TestCase):
    def test_binding_request_length(self):
        pkt = _build_stun_request(_BINDING_REQUEST)
        self.assertEqual(len(pkt), 20)

    def test_allocate_request_length(self):
        pkt = _build_stun_request(_ALLOCATE_REQUEST)
        self.assertEqual(len(pkt), 20)

    def test_header_magic_cookie(self):
        pkt = _build_stun_request(_BINDING_REQUEST)
        magic = struct.unpack("!I", pkt[4:8])[0]
        self.assertEqual(magic, _MAGIC)

    def test_message_type_encoded(self):
        pkt = _build_stun_request(_BINDING_REQUEST)
        msg_type = struct.unpack("!H", pkt[0:2])[0]
        self.assertEqual(msg_type, _BINDING_REQUEST)

    def test_custom_transaction_id(self):
        txn = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
        pkt = _build_stun_request(_BINDING_REQUEST, transaction_id=txn)
        self.assertEqual(pkt[8:20], txn)

    def test_with_attributes(self):
        attr = b"\x00\x19\x00\x04\x11\x00\x00\x00"  # REQUESTED-TRANSPORT
        pkt = _build_stun_request(_ALLOCATE_REQUEST, attributes=attr)
        self.assertEqual(len(pkt), 20 + len(attr))
        msg_len = struct.unpack("!H", pkt[2:4])[0]
        self.assertEqual(msg_len, len(attr))


class StunParseTest(unittest.TestCase):
    def _build_success_response(self, ip_bytes, port, xor=True):
        """Build a minimal STUN success response with XOR-MAPPED-ADDRESS."""
        txn = b"\x00" * 12
        if xor:
            xor_port = port ^ (_MAGIC >> 16)
            xor_ip = bytes(b ^ m for b, m in zip(ip_bytes, struct.pack("!I", _MAGIC)))
            attr_val = b"\x00\x01" + struct.pack("!H", xor_port) + xor_ip
            attr = struct.pack("!HH", 0x0020, len(attr_val)) + attr_val
        else:
            attr_val = b"\x00\x01" + struct.pack("!H", port) + ip_bytes
            attr = struct.pack("!HH", 0x0001, len(attr_val)) + attr_val
        header = struct.pack("!HHI", 0x0101, len(attr), _MAGIC) + txn
        return header + attr

    def test_parse_xor_mapped_address(self):
        ip = bytes([93, 184, 216, 34])  # 93.184.216.34
        resp = self._build_success_response(ip, 12345)
        parsed = _parse_stun_response(resp)
        self.assertTrue(parsed["success"])
        self.assertFalse(parsed["error"])
        self.assertEqual(parsed["mapped_address"]["ip"], "93.184.216.34")
        self.assertEqual(parsed["mapped_address"]["port"], 12345)

    def test_parse_plain_mapped_address(self):
        ip = bytes([10, 0, 0, 1])
        resp = self._build_success_response(ip, 8080, xor=False)
        parsed = _parse_stun_response(resp)
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["mapped_address"]["ip"], "10.0.0.1")
        self.assertEqual(parsed["mapped_address"]["port"], 8080)

    def test_parse_error_response_401(self):
        txn = b"\x00" * 12
        # ERROR-CODE attr: class=4, number=1 → 401
        error_val = b"\x00\x00\x04\x01" + b"Unauthorized"
        attr = struct.pack("!HH", 0x0009, len(error_val)) + error_val
        # Pad to 4-byte boundary
        pad = (4 - len(error_val) % 4) % 4
        attr += b"\x00" * pad
        header = struct.pack("!HHI", 0x0113, len(attr), _MAGIC) + txn
        parsed = _parse_stun_response(header + attr)
        self.assertTrue(parsed["error"])
        self.assertEqual(parsed["error_code"], 401)

    def test_parse_too_short(self):
        parsed = _parse_stun_response(b"\x00" * 10)
        self.assertIn("error", parsed)

    def test_parse_empty(self):
        parsed = _parse_stun_response(b"")
        self.assertIn("error", parsed)


class IceCandidateLeakTest(unittest.TestCase):
    def test_private_10_x(self):
        self.assertIsNotNone(_PRIVATE_IP.match("10.0.0.1"))
        self.assertIsNotNone(_PRIVATE_IP.match("10.255.255.255"))

    def test_private_172_16(self):
        self.assertIsNotNone(_PRIVATE_IP.match("172.16.0.1"))
        self.assertIsNotNone(_PRIVATE_IP.match("172.31.255.255"))

    def test_private_192_168(self):
        self.assertIsNotNone(_PRIVATE_IP.match("192.168.1.1"))

    def test_link_local(self):
        self.assertIsNotNone(_PRIVATE_IP.match("169.254.1.1"))

    def test_public_ip_does_not_match(self):
        self.assertIsNone(_PRIVATE_IP.match("8.8.8.8"))
        self.assertIsNone(_PRIVATE_IP.match("93.184.216.34"))

    def test_172_15_is_public(self):
        self.assertIsNone(_PRIVATE_IP.match("172.15.0.1"))

    def test_172_32_is_public(self):
        self.assertIsNone(_PRIVATE_IP.match("172.32.0.1"))

    def test_ula_ipv6(self):
        self.assertIsNotNone(_PRIVATE_IP.match("fd12:3456:789a::1"))
        self.assertIsNotNone(_PRIVATE_IP.match("fc00::1"))

    def test_sdp_candidate_extraction(self):
        """Full SDP with a private IP in a candidate line."""
        import re
        sdp = (
            "v=0\r\n"
            "o=- 123 456 IN IP4 0.0.0.0\r\n"
            "a=candidate:1 1 udp 2130706431 192.168.1.100 54321 typ host\r\n"
            "a=candidate:2 1 udp 1694498815 203.0.113.5 54322 typ srflx\r\n"
        )
        candidates = re.findall(r"a=candidate:.*", sdp)
        self.assertEqual(len(candidates), 2)
        leaks = []
        for line in candidates:
            ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
            for ip in ips:
                if _PRIVATE_IP.match(ip):
                    leaks.append(ip)
        self.assertEqual(leaks, ["192.168.1.100"])


if __name__ == "__main__":
    unittest.main()
