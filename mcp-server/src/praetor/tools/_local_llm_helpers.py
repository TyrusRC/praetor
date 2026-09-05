"""Local-LLM detection + request/response helpers for probe_local_llm."""

from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.parse import urlparse

from praetor import client


_DEFAULT_ENDPOINTS = [
    ("http://127.0.0.1:11434", "ollama"),       # Ollama default
    ("http://127.0.0.1:1234", "lm-studio"),     # LM Studio default
    ("http://127.0.0.1:8080", "llama-cpp"),     # llama.cpp server default
    ("http://127.0.0.1:5001", "koboldcpp"),     # KoboldCPP default
    ("http://127.0.0.1:7860", "text-gen-webui"),  # text-generation-webui
]

# Endpoint paths per backend
_TAGS_PATHS = {
    "ollama": "/api/tags",
    "lm-studio": "/v1/models",
    "llama-cpp": "/v1/models",
    "koboldcpp": "/v1/models",
    "text-gen-webui": "/v1/models",
}
_GEN_PATHS = {
    "ollama": "/api/generate",
    "lm-studio": "/v1/chat/completions",
    "llama-cpp": "/v1/chat/completions",
    "koboldcpp": "/v1/chat/completions",
    "text-gen-webui": "/v1/chat/completions",
}


def _is_local_url(url: str) -> tuple[bool, str]:
    """Reject anything not on loopback / RFC1918. Returns (ok, reason)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "unparseable URL"
    host = parsed.hostname or ""
    if not host:
        return False, "no hostname"
    if host in ("localhost", "127.0.0.1", "::1"):
        return True, ""
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_private:
            return True, ""
        return False, f"non-local host {host} (loopback/RFC1918 only)"
    except ValueError:
        # Hostname (e.g. ollama.local) — accept .local but reject anything else
        if host.endswith(".local") or host.endswith(".internal"):
            return True, ""
        return False, f"non-local hostname {host} (loopback/.local/.internal only)"


async def _bare_post(url: str, body: dict, timeout: int = 30) -> dict[str, Any]:
    """POST a JSON body to a local-LLM endpoint. Routes through Burp's curl
    so the request appears in proxy history and the operator can inspect it."""
    return await client.post("/api/http/curl", json={
        "method": "POST",
        "url": url,
        "headers": {"Content-Type": "application/json"},
        "data": json.dumps(body),
        "follow_redirects": False,
        "bare_headers": True,
    })


async def _bare_get(url: str) -> dict[str, Any]:
    return await client.post("/api/http/curl", json={
        "method": "GET",
        "url": url,
        "follow_redirects": False,
        "bare_headers": True,
    })


def _extract_models(backend: str, resp_body: str) -> list[str]:
    """Parse model list from the backend-specific response shape."""
    try:
        data = json.loads(resp_body)
    except (ValueError, TypeError):
        return []
    if backend == "ollama":
        # /api/tags → {"models":[{"name":"llama3:8b"}, ...]}
        return [m.get("name", "") for m in data.get("models", [])
                if isinstance(m, dict)]
    # OpenAI-compat shape (LM Studio / llama-cpp / kobold / text-gen-webui)
    return [m.get("id", "") for m in data.get("data", [])
            if isinstance(m, dict)]


def _build_generate_body(backend: str, model: str, prompt: str) -> dict:
    if backend == "ollama":
        return {"model": model, "prompt": prompt, "stream": False}
    # OpenAI-compat
    return {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "max_tokens": 200,
    }


def _extract_completion(backend: str, resp_body: str) -> str:
    try:
        data = json.loads(resp_body)
    except (ValueError, TypeError):
        return ""
    if backend == "ollama":
        return data.get("response", "")
    # OpenAI-compat
    choices = data.get("choices", [])
    if choices and isinstance(choices[0], dict):
        msg = choices[0].get("message", {})
        if isinstance(msg, dict):
            return msg.get("content", "")
        return choices[0].get("text", "")
    return ""


