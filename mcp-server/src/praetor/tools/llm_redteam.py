"""LLM red-team wrappers — garak, pyrit, mcp-scan.

Used when target is an LLM endpoint, MCP server, or agentic stack.
All three are OSS (Apache / MIT).
"""

from __future__ import annotations

import importlib.util
import json
import sys

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd


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
        # --narrow_output (garak 0.17): compact CLI output. The old --quiet flag
        # does not exist in garak and made argparse exit rc=2 on every run.
        cmd = ["garak", "--model_type", generator, "--model_name", model, "--narrow_output"]
        if probes:
            cmd += ["--probes", probes]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        if rc != 0 and not out:
            return f"garak failed [rc={rc}]: {err[:300]}"
        return f"# garak — {model} (generator={generator})\n\n{out.strip()[:5000]}"

    @mcp.tool()
    async def run_pyrit_orchestrator(
        script_path: str,
        timeout: int = 900,
    ) -> str:
        """Run a PyRIT orchestrator SCRIPT. PyRIT is a Python LIBRARY, not a CLI.

        Azure PyRIT ships no `pyrit` command — you drive it from Python. Point
        this at a .py orchestrator written against the PyRIT API; it runs on the
        server's own interpreter with the installed `pyrit` library. (The old
        implementation shelled out to a non-existent `pyrit run -c` CLI and could
        never succeed.)

        Args:
            script_path: path to a PyRIT Python orchestrator script.
            timeout: seconds.
        """
        # Gate on the LIBRARY being importable by this interpreter, not on a
        # `pyrit` binary (there is none). sys.executable is the same interpreter
        # find_spec inspects, so the check matches what will run the script.
        if importlib.util.find_spec("pyrit") is None:
            return _hint(
                "pyrit (Python library)",
                "uv pip install pyrit  |  https://github.com/Azure/PyRIT  (library, no CLI)",
            )
        out, err, rc = await _run_cmd(
            [sys.executable, script_path],
            timeout=timeout, bypass_proxy=True,
        )
        if rc != 0 and not out:
            return f"pyrit script failed [rc={rc}]: {err[:300]}"
        return f"# pyrit — {script_path}\n\n{out.strip()[:5000]}"

    @mcp.tool()
    async def run_mcp_scan(
        target_path: str, timeout: int = 120, run_servers: bool = False
    ) -> str:
        """Analyze MCP server tool definitions for poisoning / injection (snyk-agent-scan).

        Detects tool-poisoning, indirect-injection in tool descriptions,
        and unsafe schema patterns.

        The invariantlabs `mcp-scan` package was renamed to `snyk-agent-scan`;
        the old `pip install mcp-scan` now yields a dead redirect stub that
        scans nothing (always "0 findings"). This targets the live package.

        Behavior change with the rename: snyk-agent-scan inspects a server by
        STARTING it. For stdio servers in the config that means executing the
        server's code. It is off by default and non-interactive:
          - run_servers=False (default): passes no consent, so the tool
            auto-declines the interactive prompt and reports only what it can
            without launching anything (no code execution).
          - run_servers=True: passes --dangerously-run-mcp-servers to start
            every server in the config and get the full analysis. Only use on
            MCP servers you are authorized to run — it executes their code.

        Args:
            target_path: path to an MCP config (mcp.json / claude config / etc).
            timeout: seconds.
            run_servers: start (execute) the config's servers for full analysis.
        """
        if not _check_tool("snyk-agent-scan"):
            return _hint(
                "snyk-agent-scan",
                "uv tool install snyk-agent-scan  |  renamed from invariantlabs-ai/mcp-scan",
            )
        cmd = ["snyk-agent-scan", "scan", "--json", target_path]
        if run_servers:
            cmd.append("--dangerously-run-mcp-servers")
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        findings = data.get("findings") or data.get("issues") or []
        lines = [f"snyk-agent-scan: {len(findings)} findings in {target_path}"]
        for f in findings[:30]:
            rule = f.get("rule") or f.get("id") or "?"
            sev = f.get("severity") or "?"
            msg = (f.get("message") or "")[:120]
            lines.append(f"  [{sev:<8}] {rule}  {msg}")
        if rc != 0 and not findings:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)
