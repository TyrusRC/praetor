"""Parse a saved HTTP raw-request file into inputs, IDs, and hypotheses.
Observations are factual; hypotheses are labelled and never asserted as bugs."""

import json
import re
from urllib.parse import parse_qsl, urlparse

from ._report import redact_secret

_BIZ_LOGIC = {"role", "isadmin", "admin", "price", "amount", "quantity", "qty",
              "coupon", "discount", "invite", "invitecode", "referrer", "plan",
              "balance", "credit", "status", "type", "tier"}
_ID_HINT = re.compile(r"(^|_)(id|uuid|order|account|user|customer|invoice)s?$", re.I)
_SECRET_HINT = re.compile(r"(authorization|token|secret|apikey|api_key|session)", re.I)


def _flatten_json(obj, prefix=""):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _flatten_json(v, f"{prefix}{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _flatten_json(v, f"{prefix}[{i}]")
    else:
        out.append((prefix, obj))
    return out


def parse_raw_request(text: str) -> dict:
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = [ln for ln in head.split("\n") if ln.strip()]
    if not lines:
        return {"inputs": [], "id_references": [], "secrets": [],
                "observations": ["empty request"], "hypotheses": []}

    parts = lines[0].split()
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else ""
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    inputs, id_refs, secrets, observations, hypotheses = [], [], [], [], []

    # Query params
    for name, value in parse_qsl(urlparse(path).query):
        inputs.append({"name": name, "value": value, "location": "query"})

    # Body params
    ctype = headers.get("content-type", "")
    if body.strip():
        if "json" in ctype:
            try:
                for name, value in _flatten_json(json.loads(body)):
                    inputs.append({"name": name, "value": value, "location": "body_json"})
            except ValueError:
                observations.append("Content-Type is JSON but body did not parse")
        elif "x-www-form-urlencoded" in ctype:
            for name, value in parse_qsl(body):
                inputs.append({"name": name, "value": value, "location": "body_form"})

    # ID references + business-logic hypotheses
    for i in inputs:
        n = i["name"].split("[")[-1].strip("]").split(".")[-1]
        if _ID_HINT.search(n):
            id_refs.append({"name": i["name"], "value": i["value"], "idor_candidate": True})
        if n.lower() in _BIZ_LOGIC:
            hypotheses.append({
                "claim": f"{i['name']} is client-controlled and may be trusted server-side "
                         f"(privilege/business-logic tampering)",
                "expected_evidence": f"resending with a modified {n} changes authorization "
                                     f"or price/quantity/discount outcome",
                "validation_steps": f"replay with {n} altered (e.g. role=admin, price=0, "
                                    f"coupon reused); compare response + resulting state",
            })

    # Auth + security headers (observations, redacted)
    for hk, hv in headers.items():
        if _SECRET_HINT.search(hk):
            secrets.append({"type": hk, "shape": redact_secret(hv), "location": f"header:{hk}"})
    cookie = headers.get("cookie", "")
    for cpair in cookie.split(";"):
        if "=" in cpair:
            cn, cv = cpair.split("=", 1)
            if cv.strip().count(".") == 2 and cv.strip().startswith("ey"):
                observations.append(f"cookie {cn.strip()} looks like a JWT session token")
                secrets.append({"type": f"cookie:{cn.strip()}",
                                "shape": redact_secret(cv), "location": "cookie"})
    for h in ("x-forwarded-for", "x-csrf-token", "origin", "referer"):
        if h in headers:
            observations.append(f"security-relevant header present: {h}: {headers[h]}")

    observations.append(f"request: {method} {path}")
    return {"inputs": inputs, "id_references": id_refs, "secrets": secrets,
            "observations": observations, "hypotheses": hypotheses}
