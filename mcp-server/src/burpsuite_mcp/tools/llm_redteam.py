"""LLM red-team wrappers — garak, pyrit, mcp-scan.

Used when target is an LLM endpoint, MCP server, or agentic stack.
All three are OSS (Apache / MIT).
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


def _hint(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_garak(
        model: str,
        probes: str = "",
        generator: str = "openai",
        timeout: int = 900,
    ) -> str:
        """LLM vuln scan via garak.

        Args:
            model: model name (e.g. 'gpt-4o', 'claude-3-5-sonnet').
            probes: comma probe list ('promptinject,encoding,xss' etc). Empty = default suite.
            generator: openai | anthropic | huggingface | replicate | langchain | rest.
            timeout: seconds.
        """
        if not _check_tool("garak"):
            return _hint("garak", "pip install garak")
        cmd = ["garak", "--model_type", generator, "--model_name", model, "--quiet"]
        if probes:
            cmd += ["--probes", probes]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        if rc != 0 and not out:
            return f"garak failed [rc={rc}]: {err[:300]}"
        return f"# garak — {model} (generator={generator})\n\n{out.strip()[:5000]}"

    @mcp.tool()
    async def run_pyrit_orchestrator(
        config_path: str,
        timeout: int = 900,
    ) -> str:
        """PyRIT orchestrator run from a config file.

        Args:
            config_path: PyRIT YAML config path.
            timeout: seconds.
        """
        if not _check_tool("pyrit"):
            return _hint(
                "pyrit",
                "pip install pyrit-ai  |  https://github.com/Azure/PyRIT",
            )
        out, err, rc = await _run_cmd(
            ["pyrit", "run", "-c", config_path],
            timeout=timeout, bypass_proxy=True,
        )
        if rc != 0 and not out:
            return f"pyrit failed [rc={rc}]: {err[:300]}"
        return f"# pyrit — {config_path}\n\n{out.strip()[:5000]}"

    @mcp.tool()
    async def run_mcp_scan(target_path: str, timeout: int = 120) -> str:
        """Static analyzer for MCP server tool definitions (mcp-scan).

        Detects tool-poisoning, indirect-injection in tool descriptions,
        and unsafe schema patterns.

        Args:
            target_path: path to MCP server repo / config / package.json.
            timeout: seconds.
        """
        if not _check_tool("mcp-scan"):
            return _hint(
                "mcp-scan",
                "pip install mcp-scan  |  https://github.com/invariantlabs-ai/mcp-scan",
            )
        out, err, rc = await _run_cmd(
            ["mcp-scan", "scan", "--json", target_path],
            timeout=timeout, bypass_proxy=True,
        )
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        findings = data.get("findings") or data.get("issues") or []
        lines = [f"mcp-scan: {len(findings)} findings in {target_path}"]
        for f in findings[:30]:
            rule = f.get("rule") or f.get("id") or "?"
            sev = f.get("severity") or "?"
            msg = (f.get("message") or "")[:120]
            lines.append(f"  [{sev:<8}] {rule}  {msg}")
        if rc != 0 and not findings:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)
