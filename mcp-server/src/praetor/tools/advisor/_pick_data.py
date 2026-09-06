"""pick_tool data tables: NL task->tool mappings + tier-1 hunt-loop entries.

Declarative data only — the matching logic lives in pick_tool.py, which
re-exports these names for backward compatibility. The task->tool table is
split across topical _pick_data_*.py slices and re-assembled here; entry
order across the slices is significant (first keyword match wins).
"""

from ._pick_data_analysis import _ANALYSIS
from ._pick_data_core import _CORE
from ._pick_data_probes import _PROBES
from ._pick_data_workflow import _WORKFLOW

# Checked in order, first match wins -- more specific keywords (e.g. "jwt")
# must come BEFORE more generic ones (e.g. "token"). The slice concatenation
# order below preserves the original hand-ranked ordering.
_MAPPINGS = _WORKFLOW + _ANALYSIS + _PROBES + _CORE


# ----------------------------------------------------------------------
# Tier-1 hunt-loop entry points — these are the tools an operator should
# reach for first on any new target. Surfaced via `list_tier1_tools` so the
# model can default to them when no specific keyword matches.
# ----------------------------------------------------------------------
TIER1_HUNT_LOOP = [
    # Recon entry
    ("check_scope", "scope validation — call once per new domain (Rule 1)"),
    ("load_target_intel", "persistent target memory — call session-start (Rule 20a)"),
    ("discover_attack_surface", "crawl + map endpoints + risk-score params"),
    ("browser_crawl", "SPA / JS-heavy site mapping"),
    ("full_recon", "deep recon: discover + tech + secrets + headers"),
    # Probing
    ("auto_probe", "KB-driven probes across vuln categories"),
    ("quick_scan", "one-shot send + auto-analyze"),
    ("smart_analyze", "auto attack-surface analysis on a captured index"),
    # HTTP send
    ("curl_request", "default fresh request — auto Chrome 131 fingerprint"),
    ("session_request", "session-aware (cookie jar, token extraction)"),
    # Captured-first retrieval (token-efficient)
    ("get_proxy_history", "browse captured traffic"),
    ("search_history", "find captured req/resp by query"),
    ("get_request_detail", "view a single captured exchange"),
    ("extract_regex", "pull data from captured response (regex)"),
    ("extract_json_path", "pull data from JSON response"),
    ("extract_headers", "pull specific headers"),
    # Evidence + reporting
    ("annotate_request", "color + comment on a captured index (Rule 18)"),
    ("send_to_organizer", "bookmark evidence for report (Rule 18)"),
    ("send_to_repeater", "iterate visibly in Burp UI"),
    ("assess_finding", "7-question validation gate (Rule 10b)"),
    ("save_finding", "persist finding (Rule 10c)"),
    ("smart_decode", "encoding detection"),
]
