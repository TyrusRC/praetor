"""GitHub Advisory Database search URL builder."""

from __future__ import annotations

from urllib.parse import quote_plus


def _github_advisory_search(query: str) -> str:
    return f"https://github.com/advisories?query={quote_plus(query)}"
