"""Tests for the host-hardening / SCA / CI-settings tools: check_linux_hardening,
check_windows_hardening, scan_model_artifacts, check_binary_hardening,
check_dependency_typosquat, audit_github_org_settings, audit_github_repo_settings.
"""

from __future__ import annotations

import json
import os
import pickle
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from praetor import server
from praetor.tools import ci_audit, sca
from praetor.tools.network import linux_hardening, windows_hardening


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


# ── Registration ───────────────────────────────────────────────────────

class RegistrationTest(unittest.TestCase):
    def test_all_nine_tools_registered(self):
        for name in (
            "check_linux_hardening", "list_linux_hardening_checks",
            "check_windows_hardening", "list_windows_hardening_checks",
            "scan_model_artifacts", "check_binary_hardening",
            "check_dependency_typosquat",
            "audit_github_org_settings", "audit_github_repo_settings",
        ):
            self.assertIn(name, server.mcp._tool_manager._tools, name)


# ── scan_model_artifacts / pickle opcode scan ────────────────────────────

class _EvilOs:
    def __reduce__(self):
        return (os.system, ("id",))


class _Harmless:
    def __reduce__(self):
        return (list, ([1, 2, 3],))


class PickleScanTest(unittest.IsolatedAsyncioTestCase):
    def test_detects_os_system_default_protocol(self):
        hits = sca._scan_pickle_bytes(pickle.dumps(_EvilOs()))
        self.assertIn("posix.system", hits)

    def test_detects_eval_protocol0_and_default(self):
        class EvilEval:
            def __reduce__(self):
                return (eval, ("1+1",))
        self.assertTrue(sca._scan_pickle_bytes(pickle.dumps(EvilEval(), protocol=0)))
        self.assertTrue(sca._scan_pickle_bytes(pickle.dumps(EvilEval())))

    def test_no_false_positive_on_builtins_containers(self):
        """builtins.list/dict/set/tuple are common, harmless REDUCE targets —
        flagging the whole `builtins` module would false-positive on most
        real model checkpoints."""
        self.assertEqual(sca._scan_pickle_bytes(pickle.dumps(_Harmless())), [])
        benign = pickle.dumps({"a": 1, "b": [1, 2], "c": {1, 2}, "d": (1, 2)})
        self.assertEqual(sca._scan_pickle_bytes(benign), [])

    def test_detects_subprocess_popen(self):
        import subprocess

        class EvilPopen:
            def __reduce__(self):
                return (subprocess.Popen, (["id"],))
        self.assertTrue(sca._scan_pickle_bytes(pickle.dumps(EvilPopen())))

    async def test_scan_model_artifacts_raw_pickle(self):
        fn = _tool("scan_model_artifacts")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "evil.pkl"
            p.write_bytes(pickle.dumps(_EvilOs()))
            out = await fn(str(p))
            self.assertIn("UNSAFE DESERIALIZATION", out)
            self.assertIn("posix.system", out)

            p2 = Path(td) / "benign.pkl"
            p2.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))
            out2 = await fn(str(p2))
            self.assertIn("no dangerous GLOBAL references found", out2)

    async def test_scan_model_artifacts_pytorch_zip(self):
        fn = _tool("scan_model_artifacts")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "evil.pt"
            with zipfile.ZipFile(p, "w") as zf:
                zf.writestr("archive/data.pkl", pickle.dumps(_EvilOs()))
            out = await fn(str(p))
            self.assertIn("pytorch-zip", out)
            self.assertIn("UNSAFE DESERIALIZATION", out)

    async def test_scan_model_artifacts_safetensors_safe_and_mislabeled(self):
        fn = _tool("scan_model_artifacts")
        with tempfile.TemporaryDirectory() as td:
            header = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
            good = Path(td) / "model.safetensors"
            good.write_bytes(len(header).to_bytes(8, "little") + header + b"\x00" * 4)
            out = await fn(str(good))
            self.assertIn("SAFE", out)

            bad = Path(td) / "bad.safetensors"
            bad.write_bytes(pickle.dumps(_EvilOs()))
            out2 = await fn(str(bad))
            self.assertIn("HEADER DID NOT PARSE", out2)

    async def test_scan_model_artifacts_missing_file(self):
        fn = _tool("scan_model_artifacts")
        out = await fn("/no/such/model.pkl")
        self.assertIn("Error", out)


# ── check_dependency_typosquat ───────────────────────────────────────────

class TyposquatTest(unittest.IsolatedAsyncioTestCase):
    def test_edit_distance(self):
        self.assertEqual(sca._edit_distance("numpy", "numpy"), 0)
        self.assertEqual(sca._edit_distance("requests", "reqeusts"), 2)

    async def test_flags_close_names_not_exact(self):
        fn = _tool("check_dependency_typosquat")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "package.json"
            p.write_text(json.dumps({"dependencies": {
                "lodash": "4.17.21", "expresss": "2.0.0", "reqeust": "1.0.0",
            }}))
            out = await fn(str(p), "npm")
            self.assertIn("expresss", out)
            self.assertIn("reqeust", out)
            self.assertNotIn("\n  lodash ", out)  # exact match not flagged

    async def test_clean_manifest_reports_zero(self):
        fn = _tool("check_dependency_typosquat")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "package.json"
            p.write_text(json.dumps({"dependencies": {"lodash": "4.17.21"}}))
            out = await fn(str(p), "npm")
            self.assertIn("0 typosquat candidates", out)


# ── check_binary_hardening — dual output-format parser ───────────────────

class BinaryHardeningTest(unittest.IsolatedAsyncioTestCase):
    async def test_parses_classic_checksec_json(self):
        fn = _tool("check_binary_hardening")
        fake_json = json.dumps({"/bin/ls": {"relro": "full", "nx": "yes"}})
        with tempfile.NamedTemporaryFile() as f, \
             patch.object(sca, "_check_tool", return_value=True), \
             patch.object(sca, "_run_cmd", new=AsyncMock(return_value=(fake_json, "", 0))):
            out = await fn(f.name)
            self.assertIn("relro: full", out)
            self.assertIn("nx: yes", out)

    async def test_parses_pwntools_plaintext_output(self):
        fn = _tool("check_binary_hardening")
        plain = (
            "[*] '/bin/ls'\n"
            "    Arch:       amd64-64-little\n"
            "    RELRO:      Full RELRO\n"
            "    Stack:      Canary found\n"
            "    NX:         NX enabled\n"
            "    PIE:        PIE enabled\n"
        )
        with tempfile.NamedTemporaryFile() as f, \
             patch.object(sca, "_check_tool", return_value=True), \
             patch.object(sca, "_run_cmd", new=AsyncMock(return_value=(plain, "", 0))):
            out = await fn(f.name)
            self.assertIn("RELRO: Full RELRO", out)
            self.assertIn("NX: NX enabled", out)

    async def test_missing_file(self):
        fn = _tool("check_binary_hardening")
        out = await fn("/no/such/binary")
        self.assertIn("Error", out)

    async def test_not_installed_hint(self):
        fn = _tool("check_binary_hardening")
        with tempfile.NamedTemporaryFile() as f, \
             patch.object(sca, "_check_tool", return_value=False):
            out = await fn(f.name)
            self.assertIn("not installed", out)


# ── Linux / Windows hardening checks ──────────────────────────────────────

class LinuxHardeningTest(unittest.IsolatedAsyncioTestCase):
    async def test_requires_creds(self):
        fn = _tool("check_linux_hardening")
        out = await fn("10.0.0.5")
        self.assertIn("creds required", out)

    async def test_rejects_unknown_check_id(self):
        fn = _tool("check_linux_hardening")
        out = await fn("10.0.0.5", creds="root:pw", checks="nope")
        self.assertIn("unknown check id", out)

    async def test_every_check_command_passes_validate_payload(self):
        """Every constructed `netexec ssh ... -x "<cmd>"` line must clear the
        HARD-destructive gate (Rules 5/7/8) — these are read-only checks and
        must never be refused at the tool layer."""
        from praetor.tools.exploit._safety import validate_payload
        import shlex
        for cid, spec in linux_hardening._CHECKS.items():
            for cmd in spec["cmds"]:
                args = f"ssh 10.0.0.5 -u root -p pw -x {shlex.quote(cmd)}"
                ok, why = validate_payload(f"netexec {args}", vuln_type="network")
                self.assertTrue(ok, f"{cid}: {cmd!r} refused: {why}")

    async def test_runs_named_check_via_sanctioned_runner(self):
        fn = _tool("check_linux_hardening")
        fake = AsyncMock(return_value={
            "ok": True, "error": "", "oplog_id": "op-1", "output": "pam_faillock found",
        })
        with patch.object(linux_hardening, "run_sanctioned", fake):
            out = await fn("10.0.0.5", creds="root:pw", checks="pam-lockout")
        self.assertIn("NET-PAM-001", out)
        self.assertIn("pam_faillock found", out)
        # the SSH command must be the literal grep from the check spec,
        # proving the wrapper didn't mangle the quoting.
        called_args = fake.call_args.args[1]
        self.assertIn("ssh 10.0.0.5", called_args)
        self.assertIn("pam_faillock", called_args)

    def test_list_checks_covers_all_29_tests(self):
        all_tests = {t for spec in linux_hardening._CHECKS.values() for t in spec["tests"]}
        self.assertEqual(len(all_tests), 29, sorted(all_tests))


class WindowsHardeningTest(unittest.IsolatedAsyncioTestCase):
    async def test_requires_creds(self):
        fn = _tool("check_windows_hardening")
        out = await fn("10.0.0.5")
        self.assertIn("creds required", out)

    async def test_every_check_command_passes_validate_payload(self):
        from praetor.tools.exploit._safety import validate_payload
        import shlex
        for cid, spec in windows_hardening._CHECKS.items():
            for cmd in spec["cmds"]:
                args = f"smb 10.0.0.5 -u admin -p pw -x {shlex.quote(cmd)}"
                ok, why = validate_payload(f"netexec {args}", vuln_type="network")
                self.assertTrue(ok, f"{cid}: {cmd!r} refused: {why}")

    async def test_runs_named_check_via_sanctioned_runner(self):
        fn = _tool("check_windows_hardening")
        fake = AsyncMock(return_value={
            "ok": True, "error": "", "oplog_id": "op-2",
            "output": "    RunAsPPL    REG_DWORD    0x1",
        })
        with patch.object(windows_hardening, "run_sanctioned", fake):
            out = await fn("10.0.0.5", creds="CORP/admin:pw", checks="win-lsaprotect")
        self.assertIn("NET-WIN-004", out)
        self.assertIn("RunAsPPL", out)


# ── GitHub org/repo settings reader ───────────────────────────────────────

class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {}

    def json(self):
        if not isinstance(self._body, (dict, list)):
            raise ValueError("not json")
        return self._body

    @property
    def text(self):
        return json.dumps(self._body)


class _FakeGhClient:
    """Queued-response async httpx.AsyncClient stub, GET-only (ci_audit only
    issues GETs)."""
    queue: list = []
    calls: list = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        _FakeGhClient.calls.append(url)
        return _FakeGhClient.queue.pop(0)


def _patch_gh():
    return patch.object(ci_audit.httpx, "AsyncClient", _FakeGhClient)


class GithubOrgSettingsTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        _FakeGhClient.queue = []
        _FakeGhClient.calls = []

    async def test_reports_2fa_and_admin_only_fields_degrade_gracefully(self):
        fn = _tool("audit_github_org_settings")
        _FakeGhClient.queue = [
            _Resp(200, {"two_factor_requirement_enabled": True,
                        "default_repository_permission": "read"}),
            _Resp(401, "bad creds"),          # actions/permissions
            _Resp(200, [{"login": "alice"}]),  # members?role=admin
            _Resp(401, "bad creds"),          # outside_collaborators
        ]
        with _patch_gh():
            out = await fn("acme-corp", token="ghp_x")
        self.assertIn("two_factor_requirement_enabled: True", out)
        self.assertIn("org owners/admins: 1", out)
        self.assertIn("alice", out)
        self.assertIn("needs admin:org token", out)

    async def test_404_org_reports_clean_error(self):
        fn = _tool("audit_github_org_settings")
        _FakeGhClient.queue = [_Resp(404, {"message": "Not Found"})]
        with _patch_gh():
            out = await fn("no-such-org")
        self.assertIn("not found", out)


class GithubRepoSettingsTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        _FakeGhClient.queue = []
        _FakeGhClient.calls = []

    async def test_branch_protection_and_vuln_alerts_parsed(self):
        fn = _tool("audit_github_repo_settings")
        _FakeGhClient.queue = [
            _Resp(200, {"default_branch": "main", "visibility": "private", "archived": False}),
            _Resp(200, {  # branch protection
                "required_pull_request_reviews": {"required_approving_review_count": 2,
                                                    "require_code_owner_reviews": True},
                "enforce_admins": {"enabled": True},
                "required_status_checks": {"contexts": ["ci"]},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
            }),
            _Resp(200, {"environments": []}),
            _Resp(200, {"secrets": [{"name": "API_KEY"}]}),
            _Resp(200, [{"title": "ci-deploy", "read_only": True}]),
            _Resp(204, {}),   # vulnerability-alerts: 204 = enabled
            _Resp(200, [{"config": {"url": "https://ci.example/hook"}}]),
        ]
        with _patch_gh():
            out = await fn("acme-corp/payments-api", token="ghp_x")
        self.assertIn("required_approving_review_count: 2", out)
        self.assertIn("vulnerability_alerts enabled: True", out)
        self.assertIn("API_KEY", out)
        self.assertIn("ci-deploy", out)

    async def test_vuln_alerts_unauthorized_is_not_reported_as_false(self):
        """A 401 on the vulnerability-alerts endpoint must not be coerced into
        'enabled: False' — that previously claimed a disabled control when
        the real answer was 'could not check' (caught by live testing against
        the real GitHub API during this fix)."""
        fn = _tool("audit_github_repo_settings")
        _FakeGhClient.queue = [
            _Resp(200, {"default_branch": "main", "visibility": "public", "archived": False}),
            _Resp(401, {}), _Resp(200, {"environments": []}), _Resp(401, {}),
            _Resp(401, {}), _Resp(401, {}), _Resp(401, {}),
        ]
        with _patch_gh():
            out = await fn("octocat/Hello-World")
        self.assertNotIn("vulnerability_alerts enabled: False", out)
        self.assertIn("vulnerability_alerts enabled: unknown", out)

    async def test_404_repo_reports_clean_error(self):
        fn = _tool("audit_github_repo_settings")
        _FakeGhClient.queue = [_Resp(404, {"message": "Not Found"})]
        with _patch_gh():
            out = await fn("no/such-repo")
        self.assertIn("not found", out)


if __name__ == "__main__":
    unittest.main()
