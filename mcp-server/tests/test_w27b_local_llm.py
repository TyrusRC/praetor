"""W27-b — local-LLM orchestrator tests."""

from __future__ import annotations

import json as _json
import unittest
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server
from burpsuite_mcp.tools.local_llm import _is_local_url


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


class IsLocalUrlTest(unittest.TestCase):

    def test_loopback_accepted(self):
        for u in ("http://127.0.0.1:11434", "http://localhost:1234",
                  "http://[::1]:8080"):
            ok, _ = _is_local_url(u)
            self.assertTrue(ok, f"{u} should be local")

    def test_rfc1918_accepted(self):
        for u in ("http://10.0.0.5:11434", "http://192.168.1.10:1234",
                  "http://172.16.5.5:8080"):
            ok, _ = _is_local_url(u)
            self.assertTrue(ok, f"{u} should be local")

    def test_local_tld_accepted(self):
        for u in ("http://ollama.local:11434", "http://lab.internal:1234"):
            ok, _ = _is_local_url(u)
            self.assertTrue(ok)

    def test_public_rejected(self):
        for u in ("http://api.openai.com/", "http://8.8.8.8:11434",
                  "https://chat.completions.example.com/"):
            ok, why = _is_local_url(u)
            self.assertFalse(ok, f"{u} should be rejected (got: {why})")


class ProbeLocalLlmTest(unittest.IsolatedAsyncioTestCase):

    async def test_no_endpoint_no_scan_returns_error(self):
        fn = _tool("probe_local_llm")
        out = await fn(endpoint="", scan_defaults=False)
        self.assertEqual(out["verdict"], "ERROR")

    async def test_non_local_endpoint_refused(self):
        fn = _tool("probe_local_llm")
        out = await fn(endpoint="https://api.openai.com/v1")
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("not local", out["evidence_summary"])

    async def test_ollama_detected(self):
        """Ollama /api/tags returns model list → CONFIRMED."""
        ollama_body = _json.dumps({"models": [
            {"name": "llama3:8b", "size": 4_700_000_000},
            {"name": "mistral:latest"},
        ]})

        async def fake_post(path, json=None):
            url = (json or {}).get("url", "")
            if url == "http://127.0.0.1:11434/api/tags":
                return {"status_code": 200, "response_body": ollama_body,
                        "proxy_index": 1}
            return {"status_code": 404, "response_body": "", "proxy_index": 2}

        with patch("burpsuite_mcp.tools.local_llm.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_local_llm")
            out = await fn(endpoint="", scan_defaults=True)
        self.assertEqual(out["verdict"], "CONFIRMED")
        det = out["details"]["detections"][0]
        self.assertEqual(det["backend"], "ollama")
        self.assertIn("llama3:8b", det["models"])

    async def test_lm_studio_openai_compat_detected(self):
        """LM Studio /v1/models OpenAI-compat shape → CONFIRMED."""
        lm_body = _json.dumps({"data": [
            {"id": "TheBloke/Mistral-7B-Instruct"},
            {"id": "Meta-Llama-3-8B"},
        ]})

        async def fake_post(path, json=None):
            url = (json or {}).get("url", "")
            if url == "http://127.0.0.1:1234/v1/models":
                return {"status_code": 200, "response_body": lm_body,
                        "proxy_index": 5}
            return {"status_code": 404, "response_body": "", "proxy_index": 6}

        with patch("burpsuite_mcp.tools.local_llm.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_local_llm")
            out = await fn(endpoint="", scan_defaults=True)
        self.assertEqual(out["verdict"], "CONFIRMED")

    async def test_nothing_detected_failed(self):
        async def fake_post(path, json=None):
            return {"status_code": 404, "response_body": "", "proxy_index": 9}

        with patch("burpsuite_mcp.tools.local_llm.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_local_llm")
            out = await fn(endpoint="", scan_defaults=True)
        self.assertEqual(out["verdict"], "FAILED")


class RunLocalLlmPromptInjectionTest(unittest.IsolatedAsyncioTestCase):

    async def test_non_local_refused(self):
        fn = _tool("run_local_llm_prompt_injection")
        out = await fn(endpoint="https://api.openai.com",
                       backend="lm-studio", model="gpt-4")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_unknown_backend_refused(self):
        fn = _tool("run_local_llm_prompt_injection")
        out = await fn(endpoint="http://127.0.0.1:11434",
                       backend="not-real", model="x")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_ollama_marker_echo_confirmed(self):
        """Model echoes the marker → CONFIRMED."""
        marker = "PRAETOR_PI_MARK_42"
        body = _json.dumps({"response": f"OK, here you go: {marker}"})

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body": body, "proxy_index": 20}

        with patch("burpsuite_mcp.tools.local_llm.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("run_local_llm_prompt_injection")
            out = await fn(endpoint="http://127.0.0.1:11434",
                           backend="ollama", model="llama3:8b")
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertGreaterEqual(out["details"]["echoes"], 1)

    async def test_compliant_model_no_echo_failed(self):
        """Model refuses (doesn't echo marker) → FAILED (model rejects PI)."""
        body = _json.dumps({"response": "I cannot follow that instruction."})

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body": body, "proxy_index": 30}

        with patch("burpsuite_mcp.tools.local_llm.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("run_local_llm_prompt_injection")
            out = await fn(endpoint="http://127.0.0.1:11434",
                           backend="ollama", model="llama3:8b")
        self.assertEqual(out["verdict"], "FAILED")


class LocalLlmRegistrationTest(unittest.TestCase):

    def test_both_tools_registered(self):
        names = set(server.mcp._tool_manager._tools.keys())
        for required in ("probe_local_llm", "run_local_llm_prompt_injection"):
            self.assertIn(required, names)


if __name__ == "__main__":
    unittest.main()
