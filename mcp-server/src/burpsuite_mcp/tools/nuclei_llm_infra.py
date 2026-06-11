"""run_nuclei_llm_infra — pre-filtered nuclei sweep for LLM/AI/MCP infrastructure (W29-h).

nuclei-templates v10.4.x (April-May 2026) pushed a massive AI/ML attack-
surface drop: RCE/SSRF/file-read on Marimo / Flowise / Langflow / LiteLLM /
LMDeploy / NocoBase / Mesop / AstrBot / Gradio / AnythingLLM + panel detect
for 19 AI/ML platforms.

This wrapper around `run_nuclei` ships a curated tag set so the operator
doesn't have to remember every framework name. Single call gets RCE +
panel + sensitive-file leak across the whole LLM stack.

Coverage:
  - LLM serving stacks: ollama, lmstudio, openllm, vllm, llama-cpp, lmdeploy,
    triton, text-generation-inference (tgi)
  - LLM frameworks / chat UIs: anythingllm, openwebui, gradio, chainlit,
    langflow, flowise, n8n, marimo, mesop, koboldcpp, sillytavern, dify
  - Vector DBs: chromadb, qdrant, weaviate, milvus, pinecone (cloud-only)
  - Orchestration: superagi, autogen, openhands, agentgpt
  - MCP: mcp-server, mcp-jsonrpc, mcp-introspect (Wallarm-derived template)
  - AI platforms / panels: comfyui, sd-webui (stable-diffusion-webui),
    xinference, marqo, wandb (weights-and-biases), nocobase, langfuse
"""

from __future__ import annotations

import json
import os

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import (
    _check_tool, _run_cmd, _USER_AGENT, BURP_PROXY_URL,
)


# Curated tag list — kept conservative so we don't pick up generic web tags.
# Format mirrors nuclei `-tags` comma-separated input.
_LLM_INFRA_TAGS = ",".join([
    # LLM serving
    "ollama", "lmstudio", "vllm", "llama-cpp", "lmdeploy", "triton",
    "tgi", "openllm",
    # Frameworks / chat UIs
    "anythingllm", "openwebui", "gradio", "chainlit", "langflow",
    "flowise", "marimo", "mesop", "koboldcpp", "sillytavern", "dify",
    "n8n",
    # Vector DBs / RAG
    "chromadb", "qdrant", "weaviate", "milvus",
    # Orchestration
    "superagi", "autogen", "openhands", "agentgpt",
    # MCP
    "mcp-server", "mcp", "jsonrpc",
    # Visual / ML
    "comfyui", "stable-diffusion-webui", "xinference", "marqo", "wandb",
    "nocobase", "langfuse", "astrbot",
    # Generic but useful in this context
    "ai", "llm",
])


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_nuclei_llm_infra(  # cost: expensive (external)
        target: str,
        severity: str = "medium,high,critical",
        extra_tags: str = "",
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> str:
        """Run nuclei against the LLM/AI/MCP infrastructure tag set.

        Single call covers RCE / SSRF / file-read / panel-detect / auth-bypass
        on the full 2026 LLM stack (40+ tags). Routes through Burp proxy so
        every hit appears in Burp Proxy history.

        Args:
            target: Target URL (https://app.example.com)
            severity: Comma-separated severities (default medium+high+critical)
            extra_tags: Additional tag list (comma-separated) appended to defaults
            use_proxy: Route via Burp (default True)
            timeout: Max seconds (default 600)
        """
        if not _check_tool("nuclei"):
            return "Error: nuclei not installed. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

        templates_dir = os.path.expanduser("~/nuclei-templates")
        if not os.path.isdir(templates_dir) or len(os.listdir(templates_dir)) < 5:
            await _run_cmd(["nuclei", "-ut"], timeout=120)

        tag_filter = _LLM_INFRA_TAGS
        if extra_tags:
            tag_filter += "," + extra_tags

        cmd = ["nuclei", "-u", target, "-silent", "-no-color", "-jsonl",
               "-H", f"User-Agent: {_USER_AGENT}",
               "-tags", tag_filter,
               "-rl", "100", "-c", "25",
               "-bs", "10",
               "-timeout", "10",
               "-retries", "1",
               "-mhe", "10",
               "-duc"]
        if severity:
            cmd.extend(["-severity", severity])
        if use_proxy:
            cmd.extend(["-proxy", BURP_PROXY_URL])

        stdout, stderr, code = await _run_cmd(cmd, timeout)

        if code != 0 and not stdout:
            return f"nuclei failed (exit {code}): {stderr[:500]}"

        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                info = obj.get("info", {})
                findings.append({
                    "template": obj.get("template-id", obj.get("template-path", "?")),
                    "name": info.get("name", "?"),
                    "severity": info.get("severity", "?"),
                    "tags": info.get("tags", []),
                    "matched_at": obj.get("matched-at", obj.get("host", "?")),
                    "type": obj.get("type", "http"),
                })
            except json.JSONDecodeError:
                continue

        return json.dumps({
            "target": target,
            "tag_filter": tag_filter,
            "severity_filter": severity,
            "findings_count": len(findings),
            "findings": findings,
        }, indent=2)
