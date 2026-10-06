"""llm_status — report the resolved provider-agnostic LLM config (no secret leaked).

The config layer is praetor.tools._llm. This exposes its status as a tool so an
operator (or a tools-only host) can confirm which LLM the analysis tools will use.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from praetor.tools import _llm


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def llm_status() -> dict:
        """Report the LLM provider Praetor's analysis tools will use (OpenAI/Anthropic/Ollama/compat).

        Praetor tools are deterministic and the HOST model does the reasoning, so
        most tools need no LLM. A few use one as an analysis engine (run_vulnhuntr /
        run_xvulnhuntr). This reports the provider-agnostic config they resolve:

          PRAETOR_LLM_PROVIDER  openai | anthropic | ollama | openai-compat
          PRAETOR_LLM_API_KEY   the key (fallback: OPENAI_API_KEY / ANTHROPIC_API_KEY)
          PRAETOR_LLM_BASE_URL  endpoint (fallback: OLLAMA_BASE_URL; else the default)
          PRAETOR_LLM_MODEL     model id (else the provider default)

        Set these in the MCP server's env block (Codex config.toml, Claude .mcp.json,
        dsh cordis.yml) or a .env file. The API key is shown as a shape, never raw.
        """
        return _llm.status()
