"""Unified, provider-agnostic LLM config + client for Praetor tools.

Praetor's tools are deterministic and the HOST model does the reasoning, so most
tools never call an LLM. A few use one as an analysis ENGINE (the vulnhuntr /
xvulnhuntr wrappers today; future analysis tools may too). This module gives them
ONE config across providers: OpenAI, Anthropic, Ollama, and any OpenAI-compatible
endpoint (OpenRouter, Groq, Together, vLLM, LM Studio).

NOTE: this is for Praetor's own analysis calls only. Tools that treat an LLM as a
TARGET (local_llm, pyrit, garak, web_llm_sweep) keep their own target config on
purpose — never point this analysis config at a target you are testing.

Config (provider-agnostic; native vars are the fallback so existing setups work):
  PRAETOR_LLM_PROVIDER   openai | anthropic | ollama | openai-compat
  PRAETOR_LLM_API_KEY    the key   (fallback: OPENAI_API_KEY / ANTHROPIC_API_KEY)
  PRAETOR_LLM_BASE_URL   endpoint  (fallback: OLLAMA_BASE_URL; else provider default)
  PRAETOR_LLM_MODEL      model id  (else the provider default)
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

# Almost every vendor now speaks the OpenAI chat API (POST {base}/chat/completions),
# including Google Gemini (its OpenAI-compat route) and the Chinese models
# (DeepSeek, Qwen/DashScope, Zhipu/GLM, Moonshot/Kimi). Anthropic is the one that
# needs its own Messages API shape. A named provider just fills in the base URL.
_DEFAULT_BASE = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "ollama": "http://127.0.0.1:11434/v1",
    "openai-compat": "",
    # Google
    "google": "https://generativelanguage.googleapis.com/v1beta/openai",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    # Chinese vendors
    "deepseek": "https://api.deepseek.com",
    "qwen": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "dashscope": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "zhipu": "https://open.bigmodel.cn/api/paas/v4",
    "glm": "https://open.bigmodel.cn/api/paas/v4",
    "moonshot": "https://api.moonshot.cn/v1",
    "kimi": "https://api.moonshot.cn/v1",
    # Other OpenAI-compatible aggregators / vendors
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "together": "https://api.together.xyz/v1",
    "mistral": "https://api.mistral.ai/v1",
}
_DEFAULT_MODEL = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-sonnet-latest",
    "ollama": "llama3",
    "google": "gemini-1.5-flash", "gemini": "gemini-1.5-flash",
    "deepseek": "deepseek-chat",
    "qwen": "qwen-plus", "dashscope": "qwen-plus",
    "zhipu": "glm-4-flash", "glm": "glm-4-flash",
    "moonshot": "moonshot-v1-8k", "kimi": "moonshot-v1-8k",
    "groq": "llama-3.3-70b-versatile",
    "openrouter": "", "together": "", "mistral": "mistral-small-latest",
}
# The per-provider native key env var (fallback when PRAETOR_LLM_API_KEY is unset).
_NATIVE_KEY = {
    "openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY",
    "google": "GEMINI_API_KEY", "gemini": "GEMINI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "qwen": "DASHSCOPE_API_KEY", "dashscope": "DASHSCOPE_API_KEY",
    "zhipu": "ZHIPU_API_KEY", "glm": "ZHIPU_API_KEY",
    "moonshot": "MOONSHOT_API_KEY", "kimi": "MOONSHOT_API_KEY",
    "groq": "GROQ_API_KEY", "openrouter": "OPENROUTER_API_KEY",
    "together": "TOGETHER_API_KEY", "mistral": "MISTRAL_API_KEY",
}


@dataclass
class LLMConfig:
    provider: str
    api_key: str
    base_url: str
    model: str
    ok: bool
    reason: str = ""


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def resolve_llm(preferred: str = "", model: str = "") -> LLMConfig:
    """Resolve the active LLM config from PRAETOR_LLM_* with native-var fallback.

    `preferred` overrides PRAETOR_LLM_PROVIDER (a caller that knows its provider,
    e.g. a wrapper mapping its own 'claude'/'gpt' flag). Never raises.
    """
    prov = (preferred or _env("PRAETOR_LLM_PROVIDER")).lower()
    if not prov:  # infer from whichever provider native key is present
        for p, var in _NATIVE_KEY.items():
            if _env(var):
                prov = p
                break
        if not prov and _env("OLLAMA_BASE_URL"):
            prov = "ollama"
        if not prov:
            return LLMConfig("", "", "", "", False,
                             "no LLM configured — set PRAETOR_LLM_PROVIDER + "
                             "PRAETOR_LLM_API_KEY (or a provider native key: "
                             "OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY / "
                             "DEEPSEEK_API_KEY / DASHSCOPE_API_KEY / ..., or OLLAMA_BASE_URL)")

    key = _env("PRAETOR_LLM_API_KEY")
    if not key:
        native = _NATIVE_KEY.get(prov)
        key = _env(native) if native else ""
    if not key:  # generic {PROVIDER}_API_KEY fallback (e.g. a new vendor)
        key = _env(prov.upper().replace("-", "_") + "_API_KEY")
    if not key and prov == "ollama":
        key = "ollama"

    base = _env("PRAETOR_LLM_BASE_URL")
    if not base:
        base = (_env("OLLAMA_BASE_URL") if prov == "ollama" else "") or _DEFAULT_BASE.get(prov, "")
    if prov == "ollama" and base and not base.rstrip("/").endswith("/v1"):
        base = base.rstrip("/") + "/v1"   # use Ollama's OpenAI-compatible route

    mdl = (model or _env("PRAETOR_LLM_MODEL")) or _DEFAULT_MODEL.get(prov, "")

    is_local = any(h in (base or "") for h in ("127.0.0.1", "localhost", "0.0.0.0", "[::1]"))
    # ollama, a custom openai-compat endpoint, and any localhost endpoint may need
    # no key (self-hosted). A named cloud vendor always does.
    needs_key = prov not in ("ollama", "openai-compat") and not is_local
    if needs_key and not key:
        nv = _NATIVE_KEY.get(prov, "the provider key")
        return LLMConfig(prov, "", base, mdl, False,
                         f"{prov} selected but no API key — set PRAETOR_LLM_API_KEY (or {nv})")
    if not base:
        return LLMConfig(prov, key, "", mdl, False,
                         f"{prov} needs PRAETOR_LLM_BASE_URL (no default endpoint for this provider)")
    if not mdl:
        return LLMConfig(prov, key, base, "", False,
                         f"{prov} needs PRAETOR_LLM_MODEL (no default model for this provider)")
    return LLMConfig(prov, key, base, mdl, True)


def _default_temperature() -> float:
    try:
        return float(_env("PRAETOR_LLM_TEMPERATURE"))
    except ValueError:
        return 0.0


async def complete(prompt: str, system: str | None = None, max_tokens: int = 1024,
                   temperature: float | None = None, cfg: LLMConfig | None = None,
                   timeout: int = 60) -> str:
    """Send one completion to the resolved provider. Raises on misconfig / HTTP error.

    Response style is configurable: `system` defaults to PRAETOR_LLM_SYSTEM (the
    operator's chosen style / instructions) and `temperature` to
    PRAETOR_LLM_TEMPERATURE (else 0.0). Pass either to override per call.
    """
    cfg = cfg or resolve_llm()
    if not cfg.ok:
        raise RuntimeError(cfg.reason)
    if system is None:
        system = _env("PRAETOR_LLM_SYSTEM")
    if temperature is None:
        temperature = _default_temperature()
    if cfg.provider == "anthropic":
        return await _anthropic(cfg, prompt, system, max_tokens, temperature, timeout)
    return await _openai_compat(cfg, prompt, system, max_tokens, temperature, timeout)


async def _openai_compat(cfg, prompt, system, max_tokens, temperature, timeout) -> str:
    msgs = ([{"role": "system", "content": system}] if system else []) + \
           [{"role": "user", "content": prompt}]
    headers = {"Content-Type": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post(cfg.base_url.rstrip("/") + "/chat/completions", headers=headers,
                         json={"model": cfg.model, "messages": msgs,
                               "max_tokens": max_tokens, "temperature": temperature})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


async def _anthropic(cfg, prompt, system, max_tokens, temperature, timeout) -> str:
    headers = {"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01",
               "content-type": "application/json"}
    body = {"model": cfg.model, "max_tokens": max_tokens, "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}]}
    if system:
        body["system"] = system
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post(cfg.base_url.rstrip("/") + "/v1/messages", headers=headers, json=body)
        r.raise_for_status()
        data = r.json()
        return "".join(p.get("text", "") for p in data.get("content", [])
                       if p.get("type") == "text")


def _shape(k: str) -> str:
    k = k or ""
    if len(k) > 8:
        return f"{k[:4]}...{k[-2:]} ({len(k)}B)"
    return "set" if k else "(unset)"


def status() -> dict:
    """Operator-readable view of the resolved config (key shown as shape, never raw)."""
    cfg = resolve_llm()
    return {
        "configured": cfg.ok,
        "provider": cfg.provider or "(none)",
        "model": cfg.model or "(default)",
        "base_url": cfg.base_url or "(default)",
        "api_key": _shape(cfg.api_key),
        "reason": cfg.reason,
        "style": {
            "system": _env("PRAETOR_LLM_SYSTEM") or "(none)",
            "temperature": _default_temperature(),
        },
        "supported_providers": sorted(set(_DEFAULT_BASE) | {"openai-compat"}),
        "custom_endpoint": ("set PRAETOR_LLM_PROVIDER=openai-compat + "
                            "PRAETOR_LLM_BASE_URL=<your https url> (+ PRAETOR_LLM_API_KEY "
                            "if it needs one) for a self-hosted or any OpenAI-compatible model"),
    }
