"""W30-c — `smart_request_triage`.

Audit (W30 research wave): 106/340 tools return verbose strings; operator
chains get_request_detail → extract_* → smart_analyze → reason → pick next
probe = 5 LLM-mediated steps per captured request. Token burn at every step.

This tool collapses that loop. Input: ONE proxy/logger index. Output:
structured triage dict + priority-ordered attack_plan with concrete
suggested_call lines per W30-b synthesiser pattern.

Routing matrix (content-type + signal driven):
  text/x-component         -> probe_cve_with_variants (CVE-2025-55182)
  application/javascript   -> smart_js_analyze
  application/graphql+json -> test_graphql(test_introspection=True)
  text/html w/ forms       -> test_csrf + test_dom_sinks
  application/json + auth  -> test_auth_matrix + auto_probe
  application/xml          -> test_xxe
  5xx + stack-trace        -> confirm_sqli / confirm_ssti / confirm_rce
  302 + Location           -> test_open_redirect
  401/403                  -> test_auth_matrix + probe_kerberos_spnego_auth

Zero deps. Static regex + content-type sniff; no extra Burp roundtrips beyond
the single proxy-detail fetch.
"""

from __future__ import annotations

import re
import secrets
from typing import Any

from mcp.server.fastmcp import FastMCP

from praetor import client


# ----- Error-marker regexes for inline class detection ----------------------

from ._triage_markers import *  # noqa: F401,F403
from ._triage_scan import *  # noqa: F401,F403
from ._triage_scan import (_canary, _hkv, _parse_query, _parse_form_body,  # noqa: F401
                           _scan_secrets, _classify_body)
from ._triage_synth import _synthesise  # noqa: F401
from ._triage_markers import _AUTH_HEADERS  # noqa: F401
