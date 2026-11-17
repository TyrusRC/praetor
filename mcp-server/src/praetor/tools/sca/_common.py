"""Shared helpers for sca sub-modules."""

from __future__ import annotations


def _hint(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"
