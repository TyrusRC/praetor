"""Pure-regex extraction of endpoints, secrets, and DOM sinks/sources from JS.
Burp-independent. Secrets are redacted to shape before leaving this module."""

import re

from ._report import redact_secret

_ENDPOINT = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{2,}?)["'`]""")
_FETCH = re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|patch|delete))\s*\(\s*["'`](/[^"'`]+)["'`]""")
_ADMIN = re.compile(r"/(admin|internal|debug|actuator|console|manage|superuser)", re.I)
_UPLOAD = re.compile(r"/(upload|download|export|import|file)", re.I)
_SECRETS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")),
    ("generic_secret", re.compile(r"""(?:api[_-]?key|secret|token)["'\s:=]{1,4}["']([A-Za-z0-9_\-]{16,})["']""", re.I)),
]
_SINKS = re.compile(r"\b(innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval|setTimeout|Function)\b")
_SOURCES = re.compile(r"\b(location\.hash|location\.search|document\.referrer|window\.name|postMessage)\b")


def scan_js(text: str, label: str) -> dict:
    # Dedupe by endpoint within a file; prefer a known method over "?".
    ep_method: dict[str, str] = {}

    def add(ep: str, method: str) -> None:
        cur = ep_method.get(ep)
        if cur is None or cur == "?":
            ep_method[ep] = method

    for m in _FETCH.finditer(text):
        add(m.group(1), "GET")
    for m in _ENDPOINT.finditer(text):
        add(m.group(1), "?")

    api = [{"endpoint": ep, "method": mth, "source": label}
           for ep, mth in ep_method.items()]

    surface = []
    for ep in ep_method:
        why = []
        if _ADMIN.search(ep):
            why.append("admin/internal route")
        if _UPLOAD.search(ep):
            why.append("file handling route")
        if why:
            surface.append({"endpoint": ep, "method": ep_method[ep], "params": [],
                            "why": ", ".join(why)})

    secrets = []
    for name, pat in _SECRETS:
        for m in pat.finditer(text):
            raw = m.group(1) if m.groups() else m.group(0)
            secrets.append({"type": name, "shape": redact_secret(raw),
                            "verified": False, "location": label})

    sources_sinks = []
    for m in _SINKS.finditer(text):
        sources_sinks.append({"kind": "sink", "value": m.group(1), "location": label})
    for m in _SOURCES.finditer(text):
        sources_sinks.append({"kind": "source", "value": m.group(1), "location": label})

    return {"api_inventory": api, "inputs": [], "secrets": secrets,
            "sources_sinks": sources_sinks, "attack_surface": surface,
            "observations": [f"scanned JS: {label}"]}


def merge_js_results(results: list[dict]) -> dict:
    ep_best: dict[str, dict] = {}
    surf, seen_surf = [], set()
    secs, seen_sec = [], set()
    ss, obs = [], []
    for r in results:
        for e in r.get("api_inventory", []):
            cur = ep_best.get(e["endpoint"])
            if cur is None or (cur["method"] == "?" and e["method"] != "?"):
                ep_best[e["endpoint"]] = e
        for a in r.get("attack_surface", []):
            if a["endpoint"] not in seen_surf:
                seen_surf.add(a["endpoint"])
                surf.append(a)
        for s in r.get("secrets", []):
            if s["shape"] not in seen_sec:
                seen_sec.add(s["shape"])
                secs.append(s)
        ss += r.get("sources_sinks", [])
        obs += r.get("observations", [])
    return {"api_inventory": list(ep_best.values()), "inputs": [], "secrets": secs,
            "sources_sinks": ss, "attack_surface": surf, "observations": obs}
