import asyncio
import unittest

from praetor.tools import cloud_audit


class _StubMCP:
    """Captures @mcp.tool()-decorated coroutines so we can call them directly."""
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


def _get_azurehound():
    mcp = _StubMCP()
    cloud_audit.register(mcp)
    return mcp.tools["run_azurehound"]


class TestAzurehound(unittest.TestCase):
    def test_requires_auth_method(self):
        fn = _get_azurehound()
        # Force "installed" so we reach the auth-validation branch.
        orig = cloud_audit._check_tool
        cloud_audit._check_tool = lambda t: True
        try:
            out = asyncio.run(fn(tenant="t-123"))
        finally:
            cloud_audit._check_tool = orig
        self.assertIn("auth method", out.lower())

    def test_credentials_are_never_echoed(self):
        fn = _get_azurehound()
        orig_check, orig_run = cloud_audit._check_tool, cloud_audit._run_cmd

        async def fake_run(cmd, timeout=0, bypass_proxy=False):
            # Simulate a failing run whose stderr echoes the secret.
            return "", "auth failed for hunter2SECRET", 1

        cloud_audit._check_tool = lambda t: True
        cloud_audit._run_cmd = fake_run
        try:
            out = asyncio.run(fn(tenant="t-123", username="admin",
                                 password="hunter2SECRET"))
        finally:
            cloud_audit._check_tool, cloud_audit._run_cmd = orig_check, orig_run
        self.assertNotIn("hunter2SECRET", out)
        self.assertIn("***", out)
