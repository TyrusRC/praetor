"""External recon tool orchestration — subfinder, nuclei, katana, ffuf, sqlmap, dalfox.

Tools split across submodules by purpose:
  - inventory: check_recon_tools, probe_hosts
  - subdomain: run_subfinder
  - crawling: run_katana
  - scanning: run_nuclei, run_dalfox, run_ffuf, run_sqlmap
  - pipeline: run_recon_pipeline

Web bug bounty focus: all tools are HTTP-based and route through Burp's proxy
(where applicable) so their traffic appears in Proxy history. Network-layer
tools like nmap are intentionally excluded — they can't route through an
HTTP proxy and don't fit the web-testing workflow.
"""

from mcp.server.fastmcp import FastMCP

from . import inventory, subdomain, crawling, scanning, pipeline


def register(mcp: FastMCP):
    inventory.register(mcp)
    subdomain.register(mcp)
    crawling.register(mcp)
    scanning.register(mcp)
    pipeline.register(mcp)
