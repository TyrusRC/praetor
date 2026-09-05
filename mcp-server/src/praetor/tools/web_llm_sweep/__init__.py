"""web_llm_sweep: OWASP LLM Top 10 sweep over discovered LLM endpoints."""

from ._detect import (_canary, _marker_echoed, _looks_like_llm_response,
                      _looks_like_html_unescaped, _looks_like_system_prompt_leak)
from ._sweep import register

__all__ = ["register", "_canary", "_marker_echoed", "_looks_like_llm_response", "_looks_like_html_unescaped", "_looks_like_system_prompt_leak"]
