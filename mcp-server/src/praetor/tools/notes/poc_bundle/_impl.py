"""export_poc_bundle — full reproducible PoC artefact per confirmed finding (W7, T7).

XBOW/Strix differentiator: every confirmed finding ships with a self-contained
PoC bundle that a triager can extract + run from a fresh machine and observe
the same anomaly. Closes the visible delta vs commercial agentic pentesters.

Bundle layout (.tar.gz):

    poc-<finding_id>/
        README.md            # impact + steps + expected output
        request.http         # raw HTTP request bytes (CRLF normalised)
        response.http        # captured response bytes (truncated to 64KB)
        repro.sh             # curl-through-Burp reproduction (re-uses generate_repro_script)
        verify.py            # Python re-fire + class-specific assertion
        finding.json         # full saved-finding record
        evidence/            # auxiliary collaborator IDs, screenshots, reproductions[]

Verification assertions (verify.py):
    sqli       -> response body contains SQL error markers
    sqli_blind -> response time delta vs baseline >= 4000ms
    xss        -> reflected payload appears in executable context
    ssrf       -> collaborator interaction recorded OR response includes IMDS marker
    rce        -> uid/whoami/id markers in response
    idor       -> 200 status accessing other-user resource
    *          -> status / length / hash matches saved evidence
"""

from __future__ import annotations

import io
import json
import shlex
import tarfile
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from praetor import client

from praetor.tools.notes._helpers import _intel_dir, _safe_findings_path, _sanitized
from praetor.tools.notes.repro_script import _render_repro

_CAPSULE_SCHEMA_VERSION = "1.0"

from ._capsule_render import (  # re-exported (package __init__ copies _impl surface)
    _VERIFY_HINTS, _curl_for_request, _raw_request, _raw_response, _verify_py, _readme,
)


def _oracle_spec(finding: dict, req: dict) -> dict:
    """Distil the machine-checkable oracle that separates a true positive from
    noise for THIS finding. Consumed by manifest.json and the replay script so
    a re-fire can decide pass/fail without a human re-reading the response.

    Mirrors the decision ladder in _verify_py so both agree on the verdict.
    """
    vt = str(finding.get("vuln_type") or "").lower()
    evidence = finding.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}

    markers: list[str] = []
    for prefix, hints in _VERIFY_HINTS.items():
        if vt.startswith(prefix):
            markers = list(hints)
            break

    timing_class = vt in (
        "sqli_blind", "sqli_time", "ssrf_blind", "rce_blind", "command_injection_blind",
    )
    collab_id = evidence.get("collaborator_interaction_id")

    baseline = evidence.get("baseline") or {}
    if not isinstance(baseline, dict):
        baseline = {}
    bl_status = baseline.get("status") or evidence.get("baseline_status")
    bl_len = baseline.get("length") or evidence.get("baseline_length")

    if collab_id:
        kind = "collaborator"
        description = (
            f"True positive iff Collaborator interaction {collab_id} is present "
            "(out-of-band DNS/HTTP callback from the target confirms the blind vuln)."
        )
    elif timing_class:
        kind = "timing"
        description = (
            "True positive iff response latency >= 4000ms (injected time delay "
            "reproduces the blind timing side-channel vs baseline)."
        )
    elif markers:
        kind = "markers"
        description = (
            f"True positive iff response body contains any class marker "
            f"({', '.join(markers[:5])}{'...' if len(markers) > 5 else ''}) — "
            "confirms the payload reached an executable/parsing sink."
        )
    else:
        kind = "baseline_delta"
        description = (
            "True positive iff response status differs from baseline, or body "
            "length differs by > 200 bytes (anomaly vs recorded clean baseline)."
        )

    return {
        "vuln_class": vt or "unknown",
        "verdict_kind": kind,
        "markers": markers,
        "timing_threshold_ms": 4000 if timing_class else None,
        "collaborator_interaction_id": collab_id,
        "baseline": {"status": bl_status, "length": bl_len},
        "endpoint": finding.get("endpoint") or req.get("url") or "",
        "description": description,
    }
