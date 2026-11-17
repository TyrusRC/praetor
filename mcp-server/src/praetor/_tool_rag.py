"""BM25-based Tool RAG — project only relevant tools into the MCP manifest.

Inspired by ARTEX's toolrag.go. With 300+ tools the full manifest wastes
tokens and dilutes model attention. This module scores each non-core tool
against a query (the current task/intent) using Okapi BM25 and keeps only the
top-k most relevant, plus a fixed core set that is always visible.

Opt-in: PRAETOR_TOOL_RAG=1. Top-k configurable via PRAETOR_TOOL_RAG_TOPK
(default 20). Off by default — Claude Code defers schemas, so the saving is
smaller there; eager hosts (dsh / Codex) benefit most.

Hidden tools remain fully executable via run_tool (same as lane gating).
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter

# ── core tools: always visible, never filtered ───────────────────────────────

CORE_TOOLS: frozenset[str] = frozenset({
    # finding pipeline
    "save_finding", "assess_finding", "get_findings", "lock_findings",
    "record_probe_outcome",
    # HTTP send / read
    "curl_request", "send_raw_request", "session_request",
    "get_request_detail", "search_history", "get_proxy_history",
    # annotation + evidence
    "annotate_request", "send_to_organizer", "curate_evidence",
    # scope + coverage
    "check_scope", "coverage_summary",
    # scan + probe
    "auto_probe", "discover_attack_surface",
    # intel persistence
    "load_target_intel", "save_target_intel", "write_checkpoint",
    "save_target_notes",
    # advisor + routing
    "pick_tool", "run_tool", "get_profile",
    # recon
    "run_vigil", "run_groma",
    # bootstrap + meta
    "praetor_bootstrap", "get_rules", "list_knowledge", "get_knowledge",
    "list_skills", "get_skill", "list_agents", "get_agent",
})

# ── BM25 parameters (Okapi defaults) ────────────────────────────────────────

_K1 = 1.2
_B = 0.75

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    """Split on non-alphanumeric, lowercase. Cheap and sufficient for tool metadata."""
    return _TOKEN_RE.findall(text.lower())


def _tool_document(tool) -> str:
    """Build a searchable text document from a tool's metadata.

    Concatenates: tool name (underscores split) + description (first line) +
    input-schema property names. This is what BM25 scores against the query.
    """
    parts: list[str] = []
    name = getattr(tool, "name", "") or ""
    parts.append(name.replace("_", " "))

    desc = getattr(tool, "description", "") or ""
    first_line = ""
    for ln in desc.strip().splitlines():
        if ln.strip():
            first_line = ln.strip()
            break
    parts.append(first_line)

    params = getattr(tool, "parameters", None)
    if isinstance(params, dict):
        props = params.get("properties")
        if isinstance(props, dict):
            parts.append(" ".join(props.keys()))

    return " ".join(parts)


# ── BM25 scorer ─────────────────────────────────────────────────────────────

class _BM25:
    """Minimal Okapi BM25 scorer over a pre-built corpus."""

    __slots__ = ("_df", "_N", "_avgdl", "_docs", "_names")

    def __init__(self, names: list[str], docs: list[list[str]]):
        self._names = names
        self._docs = docs
        self._N = len(docs)
        total = sum(len(d) for d in docs)
        self._avgdl = total / self._N if self._N else 1.0
        df: Counter[str] = Counter()
        for d in docs:
            df.update(set(d))
        self._df = df

    def score(self, query_tokens: list[str]) -> list[tuple[str, float]]:
        """Return (name, score) for every document, descending by score."""
        results: list[tuple[str, float]] = []
        for i, doc in enumerate(self._docs):
            tf = Counter(doc)
            dl = len(doc)
            s = 0.0
            for qt in query_tokens:
                f = tf.get(qt, 0)
                if f == 0:
                    continue
                n = self._df.get(qt, 0)
                idf = math.log((self._N - n + 0.5) / (n + 0.5) + 1.0)
                num = f * (_K1 + 1.0)
                denom = f + _K1 * (1.0 - _B + _B * dl / self._avgdl)
                s += idf * num / denom
            results.append((self._names[i], s))
        results.sort(key=lambda x: x[1], reverse=True)
        return results


# ── public API ───────────────────────────────────────────────────────────────

# Shadow storage for tools hidden by RAG filtering. Same pattern as _lanes.HIDDEN.
HIDDEN_BY_RAG: dict = {}

# Last filter result for diagnostics.
LAST_FILTER: dict = {"enabled": False, "query": "", "kept": 0, "hidden": 0, "top_k": 0}


def is_enabled() -> bool:
    return os.environ.get("PRAETOR_TOOL_RAG", "").strip().lower() in ("1", "true", "yes", "on")


def top_k() -> int:
    try:
        v = int(os.environ.get("PRAETOR_TOOL_RAG_TOPK", "20"))
        return max(5, min(v, 200))
    except (ValueError, TypeError):
        return 20


def restore_hidden(mcp) -> int:
    """Re-advertise all RAG-hidden tools. Call before re-filtering."""
    tm = getattr(mcp, "_tool_manager", None)
    if tm is None:
        return 0
    n = 0
    for name, tool in list(HIDDEN_BY_RAG.items()):
        tm._tools[name] = tool
        n += 1
    HIDDEN_BY_RAG.clear()
    return n


def filter_tools_by_relevance(mcp, query: str) -> int:
    """Score all non-core tools against `query` and keep only the top-k.

    Returns the number of tools hidden. Hidden tools stay executable via
    run_tool (lane_control reads _lanes.HIDDEN first, then HIDDEN_BY_RAG).

    Fallback to full catalog when: disabled, empty query, fewer than 30 tools,
    or scorer error. Idempotent: restores previous RAG-hidden tools first.
    """
    global LAST_FILTER

    restore_hidden(mcp)

    if not is_enabled():
        LAST_FILTER = {"enabled": False, "query": "", "kept": 0, "hidden": 0, "top_k": 0}
        return 0

    tm = getattr(mcp, "_tool_manager", None)
    tools = getattr(tm, "_tools", None) if tm else None
    if not isinstance(tools, dict):
        return 0

    q = (query or "").strip()
    k = top_k()

    if not q or len(tools) < 30:
        LAST_FILTER = {"enabled": True, "query": q, "kept": len(tools),
                       "hidden": 0, "top_k": k, "reason": "fallback"}
        return 0

    try:
        query_tokens = _tokenize(q)
        if not query_tokens:
            return 0

        scoreable_names: list[str] = []
        scoreable_docs: list[list[str]] = []
        core_names: list[str] = []

        for name, tool in tools.items():
            if name in CORE_TOOLS:
                core_names.append(name)
                continue
            doc_text = _tool_document(tool)
            scoreable_names.append(name)
            scoreable_docs.append(_tokenize(doc_text))

        if not scoreable_names:
            return 0

        scorer = _BM25(scoreable_names, scoreable_docs)
        ranked = scorer.score(query_tokens)

        keep: set[str] = set()
        for name, score in ranked[:k]:
            keep.add(name)

        hidden = 0
        for name, _score in ranked:
            if name not in keep:
                tool = tools.get(name)
                if tool is not None:
                    HIDDEN_BY_RAG[name] = tool
                    hidden += 1

        for name in list(HIDDEN_BY_RAG):
            if name in tools:
                del tools[name]

        LAST_FILTER = {
            "enabled": True, "query": q[:100],
            "kept": len(core_names) + len(keep), "hidden": hidden, "top_k": k,
        }
        return hidden

    except Exception:
        LAST_FILTER = {"enabled": True, "query": q[:100], "kept": len(tools),
                       "hidden": 0, "top_k": k, "reason": "scorer_error"}
        return 0
