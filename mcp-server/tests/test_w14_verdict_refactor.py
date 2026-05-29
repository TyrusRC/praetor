"""W14-T1 — signature contracts for 6 refactored testing tools."""

from __future__ import annotations

import unittest


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class W14TestingRefactorsTest(unittest.TestCase):

    def test_race_singlepacket_returns_dict(self):
        from burpsuite_mcp.tools.testing import race_singlepacket
        stub, captured = _stub_mcp()
        race_singlepacket.register(stub)
        sig = captured["probe_race_singlepacket"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_race_lastbyte_returns_dict(self):
        from burpsuite_mcp.tools.testing import race_lastbyte
        stub, captured = _stub_mcp()
        race_lastbyte.register(stub)
        sig = captured["probe_race_lastbyte"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_timeless_timing_returns_dict(self):
        from burpsuite_mcp.tools.testing import timeless_timing
        stub, captured = _stub_mcp()
        timeless_timing.register(stub)
        sig = captured["probe_timeless_timing"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class W14TestingExtendedRefactorsTest(unittest.TestCase):

    def test_role_cleanup_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import role_cleanup
        stub, captured = _stub_mcp()
        role_cleanup.register(stub)
        sig = captured["probe_role_state_cleanup"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_content_type_switch_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import content_type_switch
        stub, captured = _stub_mcp()
        content_type_switch.register(stub)
        sig = captured["probe_content_type_switch"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_line_item_mutation_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import line_item_mutation
        stub, captured = _stub_mcp()
        line_item_mutation.register(stub)
        sig = captured["probe_line_item_mutation"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


if __name__ == "__main__":
    unittest.main()
