"""Benchmark harness tools (autopenbench/caibench/xbow) — split into _run/_report."""

from mcp.server.fastmcp import FastMCP

from ._core import _check_tool, _run_cmd, _bench_root, _save_run, _intel_dir
from . import _run, _report


def register(mcp: FastMCP):
    _run.register(mcp)
    _report.register(mcp)
