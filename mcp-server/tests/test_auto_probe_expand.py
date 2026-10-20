"""Test _expand_multi_param_targets — the fix for auto_probe 0-probes on API targets."""

import unittest

from praetor.tools.scan.auto_probe import _expand_multi_param_targets


class TestExpandMultiParamTargets(unittest.TestCase):

    def test_flat_targets_pass_through(self):
        flat = [
            {"path": "/eval?s=1", "parameter": "s", "method": "GET", "location": "query"},
            {"path": "/tokens", "parameter": "username", "method": "POST", "location": "body"},
        ]
        result = _expand_multi_param_targets(flat)
        self.assertEqual(result, flat)

    def test_multi_param_expansion(self):
        targets = [
            {
                "url": "https://example.com/eval?s=test",
                "method": "GET",
                "params": [
                    {"name": "s", "type": "query"},
                    {"name": "X-Auth-Token", "type": "header"},
                ],
            }
        ]
        result = _expand_multi_param_targets(targets)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["parameter"], "s")
        self.assertEqual(result[0]["location"], "query")
        self.assertEqual(result[0]["path"], "https://example.com/eval?s=test")
        self.assertEqual(result[1]["parameter"], "X-Auth-Token")
        self.assertEqual(result[1]["location"], "header")

    def test_json_body_params(self):
        targets = [
            {
                "url": "https://example.com/tokens",
                "method": "POST",
                "content_type": "application/json",
                "params": [
                    {"name": "username", "type": "json"},
                    {"name": "password", "type": "json"},
                ],
            }
        ]
        result = _expand_multi_param_targets(targets)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["location"], "body")
        self.assertEqual(result[1]["location"], "body")
        self.assertEqual(result[0]["content_type"], "application/json")

    def test_xml_body_params(self):
        targets = [
            {
                "url": "https://example.com/search",
                "method": "POST",
                "content_type": "application/xml",
                "params": [{"name": "user", "type": "xml"}],
            }
        ]
        result = _expand_multi_param_targets(targets)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["location"], "body")
        self.assertEqual(result[0]["parameter"], "user")

    def test_mixed_flat_and_multi(self):
        targets = [
            {"path": "/help", "parameter": "", "method": "GET"},
            {
                "url": "https://example.com/eval?s=test",
                "method": "GET",
                "params": [{"name": "s", "type": "url"}],
            },
        ]
        result = _expand_multi_param_targets(targets)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["path"], "/help")
        self.assertEqual(result[1]["parameter"], "s")
        self.assertEqual(result[1]["location"], "query")

    def test_index_preserved(self):
        targets = [
            {
                "url": "https://example.com/eval?s=test",
                "method": "GET",
                "index": 2831,
                "params": [{"name": "s", "type": "query"}],
            }
        ]
        result = _expand_multi_param_targets(targets)
        self.assertEqual(result[0].get("index"), 2831)

    def test_empty_params_list_passes_through(self):
        targets = [{"url": "https://example.com/", "method": "GET", "params": []}]
        result = _expand_multi_param_targets(targets)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], targets[0])

    def test_url_type_maps_to_query(self):
        targets = [
            {
                "url": "https://example.com/test",
                "method": "GET",
                "params": [{"name": "q", "type": "url"}],
            }
        ]
        result = _expand_multi_param_targets(targets)
        self.assertEqual(result[0]["location"], "query")


if __name__ == "__main__":
    unittest.main()
