"""GitHub code-search URL builder."""

from __future__ import annotations

from urllib.parse import quote_plus


def _github_code_search(query: str) -> str:
    return f"https://github.com/search?q={quote_plus(query)}&type=code"
