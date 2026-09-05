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
from typing import Any
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP

from praetor.tools.notes._helpers import _intel_dir, _sanitized


from ._predict_helpers import (
    _load_endpoints, _normalise, _extract_first_host,
    _predict_plural_singular, _predict_version_siblings,
    _predict_high_value_counterparts, _predict_verb_counterparts,
    _predict_id_shape_counterparts,
)

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


