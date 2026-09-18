"""asset_role_matrix — feature map + role x feature authorization matrix (pure cores)."""

import unittest

from praetor.tools.assurance.asset_matrix import (
    build_feature_map,
    build_role_matrix,
    render_asset_role_matrix,
)

ENDPOINTS = [
    {"url": "https://x.test/api/orders", "method": "GET"},
    {"url": "https://x.test/api/orders/1042", "method": "DELETE"},
    {"url": "https://x.test/account/profile", "method": "POST"},
    {"url": "https://x.test/account", "method": "GET"},
    {"endpoint": "https://x.test/", "method": "GET"},
]


class BuildFeatureMapTest(unittest.TestCase):
    def test_groups_by_resource_and_strips_ids(self):
        fm = build_feature_map(ENDPOINTS)
        self.assertIn("api/orders", fm)          # api/<resource> kept together
        self.assertIn("account", fm)
        self.assertIn("(root)", fm)
        # /api/orders and /api/orders/1042 collapse to one feature (id stripped)
        self.assertEqual(fm["api/orders"]["endpoints"], 2)

    def test_methods_and_state_changing_flag(self):
        fm = build_feature_map(ENDPOINTS)
        self.assertEqual(fm["api/orders"]["methods"], ["DELETE", "GET"])
        self.assertTrue(fm["api/orders"]["state_changing"])   # DELETE
        self.assertTrue(fm["account"]["state_changing"])      # POST
        self.assertFalse(fm["(root)"]["state_changing"])      # GET only

    def test_ignores_entries_without_url(self):
        self.assertEqual(build_feature_map([{"method": "GET"}]), {})


class BuildRoleMatrixTest(unittest.TestCase):
    def test_all_untested_by_default(self):
        m = build_role_matrix(["admin", "user"], ["account", "api/orders"])
        self.assertEqual(m["admin"]["account"], "untested")
        self.assertEqual(m["user"]["api/orders"], "untested")

    def test_observed_cells_filled(self):
        m = build_role_matrix(
            ["admin", "user"], ["account"],
            observed={("user", "account"): "deny", ("admin", "account"): "allow"},
        )
        self.assertEqual(m["user"]["account"], "deny")
        self.assertEqual(m["admin"]["account"], "allow")


class RenderTest(unittest.TestCase):
    def test_renders_features_matrix_and_untested_count(self):
        fm = build_feature_map(ENDPOINTS)
        rm = build_role_matrix(["admin", "customer"], list(fm.keys()))
        out = render_asset_role_matrix("x.test", fm, rm)
        self.assertIn("Asset / feature map", out)
        self.assertIn("[state-changing]", out)
        self.assertIn("authorization matrix", out)
        # 2 roles x 3 features = 6 untested cells
        self.assertIn("UNTESTED authz cells: 6 of 6", out)

    def test_no_endpoints_message(self):
        out = render_asset_role_matrix("x.test", {}, {})
        self.assertIn("No endpoints recorded", out)

    def test_no_roles_message(self):
        fm = build_feature_map(ENDPOINTS)
        out = render_asset_role_matrix("x.test", fm, {})
        self.assertIn("No roles known", out)


if __name__ == "__main__":
    unittest.main()
