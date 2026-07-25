"""Cloud SSRF credential-endpoint coverage (2026-07-25 cloud review).

Guards the modern header-less AWS credential pivots (ECS/Fargate + EKS Pod
Identity) that stay reachable when IMDSv1 is disabled. Regression target: these
endpoints were absent from both the SSRF sweep and the dedicated one-shot.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch


class CloudMetadataMatrixTest(unittest.TestCase):

    def test_ssrf_sweep_has_container_cred_endpoints(self):
        from burpsuite_mcp.tools.vuln.test_ssrf import _CLOUD_METADATA
        blob = "\n".join(_CLOUD_METADATA)
        # ECS/Fargate task-role creds + EKS Pod Identity — header-less GET.
        self.assertIn("169.254.170.2", blob)
        self.assertIn("169.254.170.23", blob)
        # Direct IAM role-cred path (not just the meta-data/ root).
        self.assertIn("iam/security-credentials/", blob)

    def test_cred_json_indicators_present(self):
        from burpsuite_mcp.tools.vuln.test_ssrf import _SSRF_INDICATORS
        # Temp-credential JSON always carries these markers.
        self.assertIn("Expiration", _SSRF_INDICATORS)
        self.assertIn("\"ASIA", _SSRF_INDICATORS)


class TestCloudMetadataImplTest(unittest.IsolatedAsyncioTestCase):

    async def test_ecs_creds_leak_confirmed(self):
        from burpsuite_mcp.tools.edge import test_cloud_metadata as mod

        async def fake_post(path, json=None):
            url = (json or {}).get("path", "")
            # Only the ECS creds endpoint leaks; everything else is clean.
            if "169.254.170.2" in url:
                return {
                    "status": 200,
                    "response_body": '{"AccessKeyId":"ASIAEXAMPLE",'
                                     '"SecretAccessKey":"abc/def",'
                                     '"Token":"IQoJ...","Expiration":"2026-07-25T00:00:00Z"}',
                }
            return {"status": 404, "response_body": "not found"}

        with patch.object(mod.client, "post", side_effect=fake_post):
            out = await mod.test_cloud_metadata_impl(session="s", parameter="url", path="/fetch")

        self.assertEqual(out["verdict"], "CONFIRMED")
        joined = " ".join(out["details"]["vulnerabilities"])
        self.assertIn("ECS", joined)

    async def test_clean_target_failed(self):
        from burpsuite_mcp.tools.edge import test_cloud_metadata as mod

        async def fake_post(path, json=None):
            return {"status": 404, "response_body": "nope"}

        with patch.object(mod.client, "post", side_effect=fake_post):
            out = await mod.test_cloud_metadata_impl(session="s", parameter="url", path="/fetch")

        self.assertEqual(out["verdict"], "FAILED")

    async def test_extra_headers_forwarded(self):
        from burpsuite_mcp.tools.edge import test_cloud_metadata as mod
        seen = {}

        async def fake_post(path, json=None):
            if (json or {}).get("headers"):
                seen.update((json or {}).get("headers"))
            return {"status": 404, "response_body": "nope"}

        with patch.object(mod.client, "post", side_effect=fake_post):
            await mod.test_cloud_metadata_impl(
                session="s", parameter="url", path="/fetch",
                extra_headers={"Metadata-Flavor": "Google"})

        self.assertEqual(seen.get("Metadata-Flavor"), "Google")


if __name__ == "__main__":
    unittest.main()
