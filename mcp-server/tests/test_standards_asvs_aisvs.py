"""ASVS 5.0 + AISVS 1.0 coverage mappings (and MASVS-v2-present confirmation)."""

import unittest

from praetor.tools.assurance._standards import STANDARDS, category_of
from praetor.tools.assurance.coverage_map import build_heatmap


class FrameworkPresenceTest(unittest.TestCase):

    def test_asvs_17_chapters(self):
        self.assertEqual(STANDARDS["asvs"]["name"], "OWASP ASVS 5.0")
        self.assertEqual(len(STANDARDS["asvs"]["categories"]), 17)

    def test_aisvs_12_chapters(self):
        self.assertEqual(STANDARDS["aisvs"]["name"], "OWASP AISVS 1.0")
        self.assertEqual(len(STANDARDS["aisvs"]["categories"]), 12)

    def test_masvs_v2_already_present(self):
        # MASVS was never a gap — it is the mastg framework (8 control groups).
        self.assertIn("MASVS v2", STANDARDS["mastg"]["name"])
        self.assertEqual(len(STANDARDS["mastg"]["categories"]), 8)


class AsvsMappingTest(unittest.TestCase):

    def test_representative_classes(self):
        want = {"sqli": "V1", "idor": "V8", "oauth_device_flow": "V10", "jwt": "V9",
                "session_security": "V7", "file_upload": "V5", "graphql": "V4",
                "crypto_weakness": "V11", "dom_xss": "V3", "business_logic": "V2",
                "info_disclosure": "V14", "authentication": "V6",
                "deserialization": "V15", "webrtc": "V17"}
        for cls, chap in want.items():
            self.assertEqual(category_of("asvs", cls), chap, cls)

    def test_header_injection_is_v1_not_v13(self):
        # 'header' substring must not pull header_injection into Configuration.
        self.assertEqual(category_of("asvs", "header_injection"), "V1")


class AisvsMappingTest(unittest.TestCase):

    def test_representative_classes(self):
        want = {"ai_prompt_injection": "C02", "mcp_server_attacks": "C10",
                "mcp_tool_poisoning": "C10", "a2a_protocol": "C09",
                "rag_injection": "C08", "vector_db_injection": "C08",
                "echoleak": "C08", "web_llm": "C02"}
        for cls, chap in want.items():
            self.assertEqual(category_of("aisvs", cls), chap, cls)


class HeatmapTest(unittest.TestCase):

    def test_asvs_heatmap_has_all_chapters_untested(self):
        hm = build_heatmap("asvs", set(), [])
        self.assertEqual(len(hm["categories"]), 17)
        self.assertEqual(hm["standard_name"], "OWASP ASVS 5.0")

    def test_aisvs_heatmap_tested_class_marks_chapter(self):
        hm = build_heatmap("aisvs", {"ai_prompt_injection"}, [])
        self.assertEqual(hm["categories"]["C02"]["status"], "tested")


if __name__ == "__main__":
    unittest.main()
