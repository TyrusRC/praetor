"""Read existing target state into a normalized signal set. Best-effort:
missing/malformed files degrade to fewer signals, never a crash."""

import json
import os
import re
from urllib.parse import urlparse, parse_qsl

# Param names that commonly carry SQL-injectable values (mirrors bucket_urls sqli
# set). A matching param on an endpoint emits a sqli_candidate signal so the
# router can fire a sqlmap detection sweep before an error marker ever appears.
_SQLI_PARAM = re.compile(
    r"^(id|user_id|order_id|product_id|cat|category|item|pid|cid|uid|sid|gid|aid|"
    r"fid|rid|page|sort|filter|orderby|order|select|column|where|table|view|"
    r"book_id|article_id|news_id|story_id|topic_id|q|search|query|keyword)$",
    re.I,
)


def _load(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _sqli_candidates(url: str) -> list[str]:
    """Query-param names on `url` that look SQL-injectable."""
    try:
        qs = urlparse(url).query
    except (ValueError, AttributeError):
        return []
    return [k for k, _ in parse_qsl(qs) if _SQLI_PARAM.match(k)]


def collect_signals(domain: str, base_dir: str = ".burp-intel") -> list[dict]:
    root = os.path.join(base_dir, domain)
    if not os.path.isdir(root):
        return []
    sigs: list[dict] = []

    profile = _load(os.path.join(root, "profile.json")) or {}
    for t in profile.get("tech_stack", []) + profile.get("frameworks", []):
        sigs.append({"type": "tech", "value": str(t), "target": domain,
                     "source": "profile"})
    endpoints = list(profile.get("high_value_endpoints", []))
    ep_data = _load(os.path.join(root, "endpoints.json")) or {}
    if isinstance(ep_data, dict):
        endpoints += [e.get("url", "") if isinstance(e, dict) else str(e)
                      for e in ep_data.get("endpoints", [])]
    seen_cand: set[tuple[str, str]] = set()
    for ep in endpoints:
        ep = str(ep)
        if not ep:
            continue
        sigs.append({"type": "params_present", "value": "", "target": ep,
                     "source": "profile"})
        for param in _sqli_candidates(ep):
            key = (ep, param)
            if key not in seen_cand:
                seen_cand.add(key)
                sigs.append({"type": "sqli_candidate", "value": param,
                             "target": ep, "source": "endpoints"})

    findings = _load(os.path.join(root, "findings.json")) or {}
    flist = findings.get("findings", []) if isinstance(findings, dict) else findings
    for f in flist:
        vt = f.get("vuln_type") if isinstance(f, dict) else None
        if vt:
            sigs.append({"type": "finding", "value": vt,
                         "target": f.get("endpoint", domain), "source": "findings"})

    coverage = _load(os.path.join(root, "coverage.json")) or {}
    for c in coverage.get("tested", []):
        sigs.append({"type": "covered", "value": c.get("vuln_type", ""),
                     "target": c.get("endpoint", ""), "source": "coverage"})

    return sigs


def normalize_signals(raw: list[dict]) -> list[dict]:
    out = []
    for s in raw or []:
        out.append({"type": s.get("type", ""), "value": s.get("value", ""),
                    "target": s.get("target", ""), "source": s.get("source", "caller")})
    return out
