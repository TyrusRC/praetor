"""Unified LLM layer — provider resolution + the real request shape per provider.

These prove a key put in the config actually drives a correct call: the OpenAI-compat
path (OpenAI / Ollama / Gemini / DeepSeek / Qwen / custom) hits /chat/completions with
a Bearer key, Anthropic hits /v1/messages with x-api-key, and the response parses.
"""

import os
import unittest
from unittest.mock import patch

from praetor.tools import _llm

_LLM_VARS = ("PRAETOR_LLM_PROVIDER", "PRAETOR_LLM_API_KEY", "PRAETOR_LLM_BASE_URL",
             "PRAETOR_LLM_MODEL", "PRAETOR_LLM_SYSTEM", "PRAETOR_LLM_TEMPERATURE")


def _clean_env() -> dict:
    """An env with every LLM/native key removed, for a deterministic resolve."""
    drop = set(_LLM_VARS) | {"OLLAMA_BASE_URL"} | set(_llm._NATIVE_KEY.values())
    return {k: v for k, v in os.environ.items() if k not in drop}


class _Resp:
    def __init__(self, data):
        self._d = data
        self.status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return self._d


class _Client:
    def __init__(self, cap, data):
        self.cap, self.data = cap, data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None):
        self.cap.update(url=url, headers=headers or {}, json=json or {})
        return _Resp(self.data)


class ResolveTest(unittest.TestCase):

    def _resolve(self, env, preferred=""):
        with patch.dict(os.environ, _clean_env(), clear=True), patch.dict(os.environ, env):
            return _llm.resolve_llm(preferred=preferred)

    def test_named_providers(self):
        cases = {
            "openai": ({"OPENAI_API_KEY": "k"}, "api.openai.com"),
            "anthropic": ({"ANTHROPIC_API_KEY": "k"}, "api.anthropic.com"),
            "gemini": ({"PRAETOR_LLM_PROVIDER": "gemini", "GEMINI_API_KEY": "k"}, "generativelanguage"),
            "deepseek": ({"PRAETOR_LLM_PROVIDER": "deepseek", "DEEPSEEK_API_KEY": "k"}, "api.deepseek.com"),
            "qwen": ({"PRAETOR_LLM_PROVIDER": "qwen", "DASHSCOPE_API_KEY": "k"}, "dashscope"),
            "zhipu": ({"PRAETOR_LLM_PROVIDER": "zhipu", "ZHIPU_API_KEY": "k"}, "bigmodel.cn"),
        }
        for name, (env, host) in cases.items():
            cfg = self._resolve(env)
            self.assertTrue(cfg.ok, (name, cfg.reason))
            self.assertIn(host, cfg.base_url, name)

    def test_custom_self_hosted_no_key(self):
        cfg = self._resolve({"PRAETOR_LLM_PROVIDER": "openai-compat",
                             "PRAETOR_LLM_BASE_URL": "https://my.host/v1",
                             "PRAETOR_LLM_MODEL": "my-model"})
        self.assertTrue(cfg.ok)                    # key-optional for custom endpoint
        self.assertEqual(cfg.base_url, "https://my.host/v1")

    def test_unconfigured(self):
        cfg = self._resolve({})
        self.assertFalse(cfg.ok)
        self.assertIn("no LLM configured", cfg.reason)


class RequestShapeTest(unittest.IsolatedAsyncioTestCase):

    async def test_openai_compat_hits_chat_completions(self):
        cap = {}
        data = {"choices": [{"message": {"content": "hi"}}]}
        with patch.dict(os.environ, _clean_env(), clear=True), \
             patch.dict(os.environ, {"PRAETOR_LLM_PROVIDER": "deepseek",
                                     "DEEPSEEK_API_KEY": "KEY", "PRAETOR_LLM_MODEL": "deepseek-chat"}), \
             patch.object(_llm.httpx, "AsyncClient", return_value=_Client(cap, data)):
            out = await _llm.complete("hello")
        self.assertTrue(cap["url"].endswith("/chat/completions"))
        self.assertEqual(cap["headers"]["Authorization"], "Bearer KEY")
        self.assertEqual(cap["json"]["model"], "deepseek-chat")
        self.assertEqual(out, "hi")

    async def test_anthropic_hits_messages(self):
        cap = {}
        data = {"content": [{"type": "text", "text": "hey"}]}
        with patch.dict(os.environ, _clean_env(), clear=True), \
             patch.dict(os.environ, {"PRAETOR_LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "KEY"}), \
             patch.object(_llm.httpx, "AsyncClient", return_value=_Client(cap, data)):
            out = await _llm.complete("hello", system="be terse")
        self.assertTrue(cap["url"].endswith("/v1/messages"))
        self.assertEqual(cap["headers"]["x-api-key"], "KEY")
        self.assertEqual(cap["json"]["system"], "be terse")
        self.assertEqual(out, "hey")

    async def test_style_from_env(self):
        cap = {}
        with patch.dict(os.environ, _clean_env(), clear=True), \
             patch.dict(os.environ, {"PRAETOR_LLM_PROVIDER": "openai", "OPENAI_API_KEY": "k",
                                     "PRAETOR_LLM_SYSTEM": "STE style", "PRAETOR_LLM_TEMPERATURE": "0.7"}), \
             patch.object(_llm.httpx, "AsyncClient",
                          return_value=_Client(cap, {"choices": [{"message": {"content": "x"}}]})):
            await _llm.complete("hi")
        self.assertEqual(cap["json"]["messages"][0], {"role": "system", "content": "STE style"})
        self.assertEqual(cap["json"]["temperature"], 0.7)


if __name__ == "__main__":
    unittest.main()
