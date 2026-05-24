"""W6 — cloud_audit + iac_scan + ci_audit + visual_easm + sca/k8s/recon extensions."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from burpsuite_mcp.tools import (
    ci_audit,
    cloud_audit,
    iac_scan,
    k8s_audit,
    recon_pd,
    sca,
    visual_easm,
)


def _registered(module):
    tools: list[str] = []

    class _Stub:
        def tool(self):
            def _wrap(fn):
                tools.append(fn.__name__)
                return fn
            return _wrap

    module.register(_Stub())
    return tools


def _call(module, tool_name, *args, **kwargs):
    async def _async():
        holders: dict = {}

        class _Stub:
            def tool(self):
                def _wrap(fn):
                    holders[fn.__name__] = fn
                    return fn
                return _wrap

        module.register(_Stub())
        return await holders[tool_name](*args, **kwargs)

    return asyncio.run(_async())


class W6RegistrationTest(unittest.TestCase):

    def test_cloud_audit_tools(self):
        for t in ("run_prowler", "run_scout_suite", "run_cloudsploit", "run_pacu"):
            self.assertIn(t, _registered(cloud_audit))

    def test_iac_scan_tools(self):
        for t in ("run_checkov", "run_tfsec", "run_terrascan", "run_hadolint"):
            self.assertIn(t, _registered(iac_scan))

    def test_ci_audit_tools(self):
        for t in ("run_poutine", "run_octoscan"):
            self.assertIn(t, _registered(ci_audit))

    def test_visual_easm_tool(self):
        self.assertIn("visual_easm_diff", _registered(visual_easm))

    def test_sca_extended(self):
        names = _registered(sca)
        for t in ("run_syft", "run_cosign_verify"):
            self.assertIn(t, names)

    def test_k8s_extended(self):
        names = _registered(k8s_audit)
        for t in ("run_peirates", "run_kdigger", "run_kubeletctl"):
            self.assertIn(t, names)

    def test_recon_pd_extended(self):
        names = _registered(recon_pd)
        for t in ("run_chaos", "run_dnsgen", "run_shuffledns"):
            self.assertIn(t, names)


class W6InstallHintTest(unittest.TestCase):

    def test_prowler_hint(self):
        with mock.patch.object(cloud_audit, "_check_tool", return_value=False):
            out = _call(cloud_audit, "run_prowler")
        self.assertIn("prowler not installed", out)

    def test_scout_hint(self):
        with mock.patch.object(cloud_audit, "_check_tool", return_value=False):
            out = _call(cloud_audit, "run_scout_suite")
        self.assertIn("scout not installed", out)

    def test_cloudsploit_hint(self):
        with mock.patch.object(cloud_audit, "_check_tool", return_value=False):
            out = _call(cloud_audit, "run_cloudsploit")
        self.assertIn("cloudsploit not installed", out)

    def test_pacu_hint(self):
        with mock.patch.object(cloud_audit, "_check_tool", return_value=False):
            out = _call(cloud_audit, "run_pacu", "sess", ["iam__enum_users"])
        self.assertIn("pacu not installed", out)

    def test_pacu_blocks_destructive_modules(self):
        with mock.patch.object(cloud_audit, "_check_tool", return_value=True):
            out = _call(cloud_audit, "run_pacu", "sess",
                        ["iam__backdoor_users_keys"])
        self.assertIn("BLOCKED", out)
        self.assertIn("Rule 5", out)

    def test_pacu_requires_at_least_one_module(self):
        with mock.patch.object(cloud_audit, "_check_tool", return_value=True):
            out = _call(cloud_audit, "run_pacu", "sess", [])
        self.assertIn("at least one module", out)

    def test_checkov_hint(self):
        with mock.patch.object(iac_scan, "_check_tool", return_value=False):
            out = _call(iac_scan, "run_checkov", "./infra")
        self.assertIn("checkov not installed", out)

    def test_tfsec_hint(self):
        with mock.patch.object(iac_scan, "_check_tool", return_value=False):
            out = _call(iac_scan, "run_tfsec", "./infra")
        self.assertIn("tfsec not installed", out)

    def test_terrascan_hint(self):
        with mock.patch.object(iac_scan, "_check_tool", return_value=False):
            out = _call(iac_scan, "run_terrascan", "./infra")
        self.assertIn("terrascan not installed", out)

    def test_hadolint_hint(self):
        with mock.patch.object(iac_scan, "_check_tool", return_value=False):
            out = _call(iac_scan, "run_hadolint", "./Dockerfile")
        self.assertIn("hadolint not installed", out)

    def test_poutine_hint(self):
        with mock.patch.object(ci_audit, "_check_tool", return_value=False):
            out = _call(ci_audit, "run_poutine", "./repo")
        self.assertIn("poutine not installed", out)

    def test_octoscan_hint(self):
        with mock.patch.object(ci_audit, "_check_tool", return_value=False):
            out = _call(ci_audit, "run_octoscan", "./repo")
        self.assertIn("octoscan not installed", out)

    def test_syft_hint(self):
        with mock.patch.object(sca, "_check_tool", return_value=False):
            out = _call(sca, "run_syft", "./image:latest")
        self.assertIn("syft not installed", out)

    def test_cosign_hint(self):
        with mock.patch.object(sca, "_check_tool", return_value=False):
            out = _call(sca, "run_cosign_verify", "alpine:latest",
                        public_key="./key.pub")
        self.assertIn("cosign not installed", out)

    def test_peirates_hint(self):
        with mock.patch.object(k8s_audit, "_check_tool", return_value=False):
            out = _call(k8s_audit, "run_peirates")
        self.assertIn("peirates not installed", out)

    def test_kdigger_hint(self):
        with mock.patch.object(k8s_audit, "_check_tool", return_value=False):
            out = _call(k8s_audit, "run_kdigger")
        self.assertIn("kdigger not installed", out)

    def test_kubeletctl_hint(self):
        with mock.patch.object(k8s_audit, "_check_tool", return_value=False):
            out = _call(k8s_audit, "run_kubeletctl", "10.0.0.5")
        self.assertIn("kubeletctl not installed", out)

    def test_visual_easm_hint(self):
        with mock.patch.object(visual_easm, "_check_tool", return_value=False):
            out = _call(visual_easm, "visual_easm_diff", "example.com",
                        ["https://example.com"])
        self.assertIn("gowitness not installed", out)

    def test_dnsgen_hint(self):
        with mock.patch.object(recon_pd, "_check_tool", return_value=False):
            out = _call(recon_pd, "run_dnsgen", "/tmp/seed.txt")
        self.assertIn("dnsgen not installed", out)

    def test_shuffledns_resolvers_required(self):
        with mock.patch.object(recon_pd, "_check_tool", return_value=True):
            out = _call(recon_pd, "run_shuffledns", "/tmp/words.txt",
                        domain="example.com", resolvers_path="")
        self.assertIn("resolvers list", out)

    def test_chaos_requires_key(self):
        import os
        prior = os.environ.pop("CHAOS_KEY", None)
        try:
            with mock.patch.object(recon_pd, "_check_tool", return_value=True):
                out = _call(recon_pd, "run_chaos", "example.com")
        finally:
            if prior is not None:
                os.environ["CHAOS_KEY"] = prior
        self.assertIn("CHAOS_KEY", out)


class W6CosignKeylessGateTest(unittest.TestCase):

    def test_cosign_keyless_needs_identity_and_issuer(self):
        with mock.patch.object(sca, "_check_tool", return_value=True):
            out = _call(sca, "run_cosign_verify", "alpine:latest",
                        public_key="", certificate_identity="",
                        certificate_issuer="")
        self.assertIn("keyless mode", out)


class W6KEVEPSSEnrichTest(unittest.TestCase):

    def test_kev_epss_enrich_empty_list(self):
        from burpsuite_mcp.tools.cve import register as cve_register  # noqa: F401  (shim function)
        import importlib
        cve_register_mod = importlib.import_module("burpsuite_mcp.tools.cve.register")

        async def _go():
            holders: dict = {}

            class _Stub:
                def tool(self):
                    def _wrap(fn):
                        holders[fn.__name__] = fn
                        return fn
                    return _wrap

            cve_register_mod.register(_Stub())
            return await holders["kev_epss_enrich"]([])

        out = asyncio.run(_go())
        self.assertIn("no CVE IDs", out)

    def test_kev_epss_enrich_sorts_kev_first(self):
        from burpsuite_mcp.tools.cve import register as cve_register  # noqa: F401  (shim function)
        import importlib
        cve_register_mod = importlib.import_module("burpsuite_mcp.tools.cve.register")

        async def fake_lookup(cve_id):
            table = {
                "CVE-2024-AAAA": {"summary": "low epss", "cvss": 5.0,
                                  "epss": 0.01, "kev": False,
                                  "ransomware_campaign": False},
                "CVE-2024-BBBB": {"summary": "kev entry", "cvss": 7.5,
                                  "epss": 0.10, "kev": True,
                                  "ransomware_campaign": False},
                "CVE-2024-CCCC": {"summary": "high epss", "cvss": 8.0,
                                  "epss": 0.80, "kev": False,
                                  "ransomware_campaign": False},
            }
            return table[cve_id]

        async def _go():
            holders: dict = {}

            class _Stub:
                def tool(self):
                    def _wrap(fn):
                        holders[fn.__name__] = fn
                        return fn
                    return _wrap

            cve_register_mod.register(_Stub())
            kev_epss_mod = importlib.import_module(
                "burpsuite_mcp.tools.cve._register_kev_epss")
            with mock.patch.object(kev_epss_mod, "_shodan_cve_lookup",
                                   side_effect=fake_lookup):
                return await holders["kev_epss_enrich"](
                    ["CVE-2024-AAAA", "CVE-2024-BBBB", "CVE-2024-CCCC"],
                )

        out = asyncio.run(_go())
        bbbb_pos = out.find("CVE-2024-BBBB")
        cccc_pos = out.find("CVE-2024-CCCC")
        aaaa_pos = out.find("CVE-2024-AAAA")
        self.assertLess(bbbb_pos, cccc_pos)
        self.assertLess(cccc_pos, aaaa_pos)
        self.assertIn("[KEV]", out)


class W6CIActionsKBTest(unittest.TestCase):

    def test_ci_actions_kb_loads(self):
        from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR, _REFERENCE_ONLY
        path = KNOWLEDGE_DIR / "ci_actions_injection.json"
        self.assertTrue(path.exists(), f"missing: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["category"], "ci_actions_injection")
        self.assertIn("expression_injection", data["contexts"])
        self.assertIn("pwn_request", data["contexts"])
        self.assertIn("ci_actions_injection", _REFERENCE_ONLY)


if __name__ == "__main__":
    unittest.main()
