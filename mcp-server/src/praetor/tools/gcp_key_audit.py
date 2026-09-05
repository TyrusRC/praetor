"""audit_google_api_key — validate an exposed Google/Gemini API key + frame impact.

Detection of AIza keys already exists (smart_js_analyze / offline / triage).
The gap this fills is ESCALATION (Rule 29): prove a leaked key is live, show
what it unlocks (Gemini models, incl. costly Veo/Imagen/TTS), and frame the
financial impact — turning "an exposed secret" into a reportable HIGH.

Safe-by-design:
- Only read-only calls: GET the Gemini `models` list (free) + the 403 Referer
  bypass the restriction relies on. It NEVER fires billable generation
  (generateContent / :predict / TTS) against the key's account — that is abuse
  of the victim's billing (Rule 7 / no-abusive-code). Impact is ESTIMATED from
  a pricing table instead.
- The key is a secret: every returned field and the PoC curl are redacted to
  shape (AIza…xxxx). The full key never enters output or the transcript.
- Other Google services (Maps/Firebase/Vision/YouTube) are listed as manual
  follow-ups, not auto-hit, so the tool never rings up spend on its own.
"""

from __future__ import annotations

import json
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

GOOGLE_KEY_RE = re.compile(r"AIza[0-9A-Za-z_\-]{35}")
_MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models?key="

# Approximate public list-price anchors (USD). Confirm against the live Gemini
# pricing page before quoting in a report — these move.
_PRICING = {
    "veo": "video generation ~$0.40/sec (a 5s clip ≈ $2) — highest-cost abuse vector",
    "imagen": "image generation ~$0.04/image — premium per-request cost",
    "tts": "text-to-speech billed per character — scalable voice-gen abuse",
    "text": "text generation billed per token — spam/automation on victim billing",
}
# Substrings that identify a costly model family among the listed models.
_COSTLY = {"veo": "veo", "imagen": "imagen", "tts": "tts"}

_OTHER_SERVICES = [
    "Maps (Geocoding/Static/Directions)", "Firebase", "Cloud Vision",
    "YouTube Data", "Translate", "Places",
]


def extract_google_keys(text: str) -> list[str]:
    """All AIza-format keys in text, de-duplicated, order preserved."""
    seen: dict[str, None] = {}
    for m in GOOGLE_KEY_RE.findall(text or ""):
        seen.setdefault(m, None)
    return list(seen)


def redact_key(key: str) -> str:
    """Shape only: AIza…<last4>. Never returns the key body."""
    if not key or len(key) < 8:
        return "AIza…"
    return f"AIza…{key[-3:]}"


def classify_gemini(status: int, body: str) -> dict[str, Any]:
    """Classify a models-endpoint response into active/restriction/models."""
    models: list[str] = []
    try:
        data = json.loads(body) if body else {}
    except ValueError:
        data = {}

    if status == 200:
        for m in data.get("models", []) or []:
            name = str(m.get("name", "")).split("/")[-1]
            if name:
                models.append(name)
        return {"active": True, "restriction": "none", "models": models}

    msg = json.dumps(data).upper()
    if status == 400 or "API_KEY_INVALID" in msg or "INVALID_ARGUMENT" in msg:
        return {"active": False, "restriction": "invalid", "models": []}
    if status == 403 or "PERMISSION_DENIED" in msg or "API_KEY_RESTRICTED" in msg:
        return {"active": False, "restriction": "restricted", "models": []}
    return {"active": False, "restriction": f"http_{status}", "models": []}


def estimate_impact(models: list[str]) -> list[str]:
    """Impact bullets for the costly capabilities the model list exposes."""
    out: list[str] = []
    low = [m.lower() for m in models]
    for fam, needle in _COSTLY.items():
        if any(needle in m for m in low):
            out.append(_PRICING[fam])
    if models:  # any active model = at least text-gen abuse
        out.append(_PRICING["text"])
    return out


async def _http_get(url: str, headers: dict, timeout: int) -> tuple[int, str]:
    """Read-only GET. Isolated so tests can monkeypatch the network."""
    import httpx

    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
        r = await client.get(url, headers=headers)
        return r.status_code, r.text


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def audit_google_api_key(
        key: str, referer: str = "", timeout: int = 15
    ) -> dict:
        """Validate an exposed Google/Gemini API key and frame its impact.

        Read-only: lists Gemini models (free) and, on a 403, retries with a
        google.com Referer to test a weak browser restriction. NEVER runs
        billable generation — impact is estimated from pricing. The key is
        redacted to shape in all output.

        Returns: {key_redacted, active, restriction, models, referer_bypass,
        impact_estimate, other_services_to_check, poc, safe_note}.
        """
        if not GOOGLE_KEY_RE.fullmatch(key or ""):
            return {"error": "not a valid AIza-format Google API key"}

        headers = {"Referer": referer} if referer else {}
        status, body = await _http_get(_MODELS_URL + key, headers, timeout)

        referer_bypass = False
        if status == 403 and not referer:
            s2, b2 = await _http_get(
                _MODELS_URL + key, {"Referer": "https://www.google.com/"}, timeout
            )
            if s2 == 200:
                status, body, referer_bypass = s2, b2, True

        c = classify_gemini(status, body)
        red = redact_key(key)
        return {
            "key_redacted": red,
            "active": c["active"],
            "restriction": c["restriction"],
            "models": c["models"],
            "referer_bypass": referer_bypass,
            "impact_estimate": estimate_impact(c["models"]) if c["active"] else [],
            "other_services_to_check": _OTHER_SERVICES if c["active"] or c["restriction"] == "restricted" else [],
            "poc": f'curl "{_MODELS_URL}{red}"'
            + ('  -H "Referer: https://www.google.com/"' if referer_bypass else ""),
            "safe_note": (
                "Read-only validation only. Do NOT run generateContent/Veo/Imagen/"
                "TTS against the target's key — that bills the victim. Estimate "
                "cost from the pricing page for the report."
            ),
        }
