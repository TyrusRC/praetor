"""Path-prediction heuristics + regex/mapping tables for predict_paths_from_crawl."""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

from praetor.tools.notes._helpers import _intel_dir, _sanitized


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
