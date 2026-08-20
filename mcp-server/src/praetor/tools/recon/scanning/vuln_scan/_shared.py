"""Vulnerability scanners: nuclei, dalfox, commix, sqlmap, nikto, wpscan, ysoserial."""

import json

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd, _USER_AGENT, BURP_PROXY_URL
from praetor.tools._runtime_guard import wrap_untrusted
