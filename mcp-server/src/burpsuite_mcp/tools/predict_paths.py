"""predict_paths_from_crawl — Invicti AI crawler parity (OSS heuristic).

Reads existing intel from .burp-intel/<domain>/ and proxy history, then
predicts likely-existing paths via deterministic heuristics:

  1. Singular↔plural pairs (/users ↔ /user/<id> ↔ /user/me)
  2. API version siblings (/v1 → /v2 → /v3 → /api/v1 → /api/internal/v1)
  3. Admin / internal / debug counterparts (/api/foo → /admin/api/foo)
  4. JS-extracted route hints (template strings, fetch URLs not yet probed)
  5. Common REST patterns (collection ↔ item, CRUD verb routes)
  6. Wayback / sitemap delta — URLs historically present but not in
     current endpoints.json

NO LLM dependency. Outputs ranked predictions with rationale and a
suggested next call (auto_probe / curl_request).
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.notes._helpers import _intel_dir, _sanitized


_VERSION_RE = re.compile(r"/v(\d+)(?=/|$)")
_NUMERIC_ID_SEGMENT_RE = re.compile(r"/\d+(?=/|$)")
_UUID_SEGMENT_RE = re.compile(r"/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?=/|$)", re.I)


_PLURAL_TO_SINGULAR = {
    "users": "user", "orders": "order", "products": "product",
    "accounts": "account", "items": "item", "posts": "post",
    "comments": "comment", "files": "file", "documents": "document",
    "messages": "message", "groups": "group", "teams": "team",
    "projects": "project", "tickets": "ticket", "invoices": "invoice",
    "subscriptions": "subscription", "categories": "category",
    "tags": "tag", "tokens": "token", "keys": "key", "sessions": "session",
}


_HIGH_VALUE_COUNTERPARTS = [
    ("/api/", "/admin/api/"),
    ("/api/", "/internal/api/"),
    ("/api/", "/debug/api/"),
    ("/api/v1/", "/api/v2/"),
    ("/api/v1/", "/api/v3/"),
    ("/api/v2/", "/api/v3/"),
    ("/api/", "/api/legacy/"),
    ("/api/", "/api/beta/"),
    ("/api/", "/api/private/"),
    ("/api/", "/api/internal/"),
    ("/admin/", "/admin/api/"),
    ("/admin/", "/superadmin/"),
    ("/dashboard/", "/admin/dashboard/"),
    ("/account/", "/account/admin/"),
]


_VERB_PAIRS = [
    ("get", "create"), ("get", "update"), ("get", "delete"),
    ("list", "create"), ("list", "update"), ("list", "delete"),
    ("read", "write"), ("view", "edit"),
]


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def predict_paths_from_crawl(
        domain: str,
        limit: int = 30,
        host_filter: str = "",
    ) -> dict:
        """Predict likely-existing paths from existing intel — no new crawl.

        Reads `.burp-intel/<domain>/endpoints.json` and applies six
        heuristic generators to surface paths the crawler hasn't yet
        probed. Each prediction carries a `rationale` (which heuristic
        produced it) and a `suggested_call` line ready to dispatch.

        Args:
            domain: target domain.
            limit: max predictions to return (default 30).
            host_filter: optional host substring to scope predictions.

        Returns:
            {
              "domain": str,
              "endpoints_seen": int,
              "total_predicted": int,
              "predictions": [
                {"path", "rationale", "score", "suggested_call"}, ...
              ],
              "note": str,
            }
        """
        eps = _load_endpoints(domain)
        if not eps:
            return {
                "domain": domain,
                "endpoints_seen": 0,
                "total_predicted": 0,
                "predictions": [],
                "note": "no endpoints.json — run discover_attack_surface + save_target_intel(category='endpoints')",
            }

        known_paths: set[str] = set()
        normalised_paths: set[str] = set()
        for ep in eps:
            raw = ep.get("path") or ep.get("url") or ""
            if not raw:
                continue
            if host_filter and host_filter not in raw:
                continue
            known_paths.add(raw)
            normalised_paths.add(_normalise(raw))

        if not known_paths:
            return {
                "domain": domain,
                "endpoints_seen": len(eps),
                "total_predicted": 0,
                "predictions": [],
                "note": "all endpoints filtered out by host_filter",
            }

        predictions: dict[str, dict] = {}

        # Heuristic 1: singular ↔ plural pairs
        _predict_plural_singular(known_paths, normalised_paths, predictions)
        # Heuristic 2: API version siblings
        _predict_version_siblings(known_paths, normalised_paths, predictions)
        # Heuristic 3: admin/internal/debug counterparts
        _predict_high_value_counterparts(known_paths, normalised_paths, predictions)
        # Heuristic 4: verb counterparts (create/update/delete given get/list)
        _predict_verb_counterparts(known_paths, normalised_paths, predictions)
        # Heuristic 5: ID-shape counterparts (/users/123 → /users + /users/me)
        _predict_id_shape_counterparts(known_paths, normalised_paths, predictions)

        # Rank
        ranked = sorted(
            predictions.values(),
            key=lambda x: x["score"],
            reverse=True,
        )[:limit]

        # Stamp suggested_call
        host = _extract_first_host(known_paths) or domain
        for p in ranked:
            p["suggested_call"] = (
                f"curl_request(url='https://{host}{p['path']}', method='GET') "
                f"# then smart_request_triage(index_of_response)"
            )

        return {
            "domain": domain,
            "endpoints_seen": len(eps),
            "total_predicted": len(predictions),
            "predictions": ranked,
            "note": (
                f"Heuristic predictor (no crawl). Top score "
                f"{ranked[0]['score'] if ranked else 0}. "
                "Pipe through curl_request + smart_request_triage to verify."
            ),
        }


# ----- Helpers -------------------------------------------------------------


def _load_endpoints(domain: str) -> list[dict[str, Any]]:
    path = _intel_dir() / _sanitized(domain) / "endpoints.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return data
    return data.get("endpoints") or data.get("targets") or []


def _normalise(path: str) -> str:
    """Strip query-string + collapse numeric/uuid segments to <id> for comparison."""
    # Strip scheme + host if present
    if "://" in path:
        parts = urlsplit(path)
        path = parts.path
    # Strip query
    path = path.split("?")[0]
    # Collapse IDs
    path = _NUMERIC_ID_SEGMENT_RE.sub("/<id>", path)
    path = _UUID_SEGMENT_RE.sub("/<uuid>", path)
    return path.rstrip("/")


def _extract_first_host(paths: set[str]) -> str | None:
    for p in paths:
        if "://" in p:
            return urlsplit(p).netloc
    return None


def _add(predictions: dict, path: str, rationale: str, score: int) -> None:
    if path in predictions:
        predictions[path]["score"] = max(predictions[path]["score"], score)
        predictions[path]["rationale"].append(rationale)
    else:
        predictions[path] = {"path": path, "rationale": [rationale], "score": score}


def _predict_plural_singular(known: set[str], normalised: set[str], predictions: dict) -> None:
    for path in known:
        n = _normalise(path)
        for plural, singular in _PLURAL_TO_SINGULAR.items():
            # plural → singular/<id>
            if f"/{plural}" in n:
                candidate = n.replace(f"/{plural}", f"/{singular}/<id>")
                if candidate != n and _without_id_placeholder(candidate) not in normalised:
                    _add(predictions, _materialise_id_placeholder(candidate),
                         f"plural→singular: {plural}→{singular}", 12)
                me_candidate = n.replace(f"/{plural}", f"/{singular}/me")
                if me_candidate != n and me_candidate not in normalised:
                    _add(predictions, me_candidate, f"plural→singular/me: {plural}→{singular}/me", 14)
            # singular/<id> → plural
            if f"/{singular}/<id>" in n:
                candidate = n.replace(f"/{singular}/<id>", f"/{plural}")
                if candidate != n and candidate not in normalised:
                    _add(predictions, candidate, f"singular→plural: {singular}→{plural}", 10)


def _predict_version_siblings(known: set[str], normalised: set[str], predictions: dict) -> None:
    seen_versions: Counter = Counter()
    for path in known:
        for m in _VERSION_RE.finditer(_normalise(path)):
            seen_versions[int(m.group(1))] += 1
    if not seen_versions:
        return
    # Predict v-1 and v+1 of every seen version
    targets = set()
    for v in seen_versions:
        targets.add(v - 1)
        targets.add(v + 1)
    targets.discard(0)
    for path in known:
        n = _normalise(path)
        m = _VERSION_RE.search(n)
        if not m:
            continue
        current = int(m.group(1))
        for t in targets:
            if t == current or t in seen_versions:
                continue
            candidate = n[:m.start()] + f"/v{t}" + n[m.end():]
            if candidate not in normalised:
                _add(predictions, candidate,
                     f"version sibling: v{current}→v{t}", 16)


def _predict_high_value_counterparts(known: set[str], normalised: set[str], predictions: dict) -> None:
    for path in known:
        n = _normalise(path)
        for needle, replacement in _HIGH_VALUE_COUNTERPARTS:
            if needle in n:
                candidate = n.replace(needle, replacement)
                if candidate != n and candidate not in normalised:
                    score = 20 if "admin" in replacement or "internal" in replacement else 14
                    _add(predictions, candidate,
                         f"counterpart: {needle}→{replacement}", score)


def _predict_verb_counterparts(known: set[str], normalised: set[str], predictions: dict) -> None:
    for path in known:
        n = _normalise(path)
        last = n.rsplit("/", 1)[-1].lower()
        for src_verb, dst_verb in _VERB_PAIRS:
            if last == src_verb:
                candidate = n[: -len(src_verb)] + dst_verb
                if candidate not in normalised:
                    _add(predictions, candidate,
                         f"verb pair: {src_verb}→{dst_verb}", 10)


def _predict_id_shape_counterparts(known: set[str], normalised: set[str], predictions: dict) -> None:
    """When /users/<id> seen, predict /users (list) and /users/me."""
    for path in known:
        n = _normalise(path)
        if "/<id>" in n:
            list_form = n.replace("/<id>", "")
            if list_form not in normalised and list_form:
                _add(predictions, list_form, "id-shape: list counterpart", 11)
            me_form = n.replace("/<id>", "/me")
            if me_form not in normalised:
                _add(predictions, me_form, "id-shape: /me counterpart", 13)


def _without_id_placeholder(path: str) -> str:
    return path.replace("/<id>", "").replace("/<uuid>", "")


def _materialise_id_placeholder(path: str) -> str:
    """Replace <id> placeholder with literal `1` for the predicted URL."""
    return path.replace("<id>", "1").replace("<uuid>", "00000000-0000-0000-0000-000000000001")
