"""audit_exposed_secret — classify an exposed secret, validate it SAFELY, frame impact.

Generalises the Google-key escalation (gcp_key_audit) to the common
bug-bounty secret families. A leaked secret is a lead (Rule 29); the value is
what it unlocks. This proves that — but only where proving it is safe.

Safety model (hard):
- Auto-validation is allowed ONLY for read-only "whoami"-style endpoints that
  neither bill nor change state: GitHub /user, GitLab /user, Slack auth.test,
  npm whoami, Google Gemini model list.
- Financial / destructive / send-capable keys (Stripe, AWS, Twilio, SendGrid,
  Mailgun, private keys) are NEVER auto-called — hitting a live Stripe key or
  signing an AWS request can move money or data. They are classified with
  impact + a manual, authorized-only note.
- Every secret is redacted to shape in all output; the value never enters the
  transcript.

Pure helpers (classify_secret / redact_secret / is_safe_to_validate /
impact_for) are tested disk- and network-free.
"""

from __future__ import annotations

import json
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

# name -> {regex, service, safe (read-only whoami auto-validate), impact, severity}
SECRET_TYPES: dict[str, dict[str, Any]] = {
    "aws_access_key": {
        "regex": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "service": "AWS", "safe": False,
        "impact": "AWS account access (S3/EC2/IAM) — needs the matching secret "
                  "key; validate manually via sts:GetCallerIdentity, never blind.",
        "severity": "high",
    },
    "google_api_key": {
        "regex": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "service": "Google/Gemini", "safe": True,
        "impact": "Gemini/Maps/Firebase access; costly models (Veo/Imagen/TTS) "
                  "= billable-compute abuse. Deep-dive: audit_google_api_key.",
        "severity": "high",
    },
    "github_token": {
        "regex": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        "service": "GitHub", "safe": True,
        "impact": "Repo/org access at the token's scopes — source, secrets, CI, "
                  "supply-chain push. Scopes in X-OAuth-Scopes.",
        "severity": "high",
    },
    "gitlab_token": {
        "regex": re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
        "service": "GitLab", "safe": True,
        "impact": "GitLab API access at token scopes — repos, CI/CD variables, "
                  "registry.",
        "severity": "high",
    },
    "slack_token": {
        "regex": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "service": "Slack", "safe": True,
        "impact": "Workspace access — messages, files, user list; data exposure "
                  "and phishing pivot.",
        "severity": "high",
    },
    "npm_token": {
        "regex": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "service": "npm", "safe": True,
        "impact": "npm publish/read — package takeover / supply-chain.",
        "severity": "high",
    },
    "stripe_live": {
        "regex": re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b"),
        "service": "Stripe", "safe": False,
        "impact": "LIVE Stripe key — customers, charges, refunds. NEVER auto-call; "
                  "financial. Report as critical exposure; validate only with "
                  "explicit authorization.",
        "severity": "critical",
    },
    "stripe_test": {
        "regex": re.compile(r"\b(sk|rk)_test_[A-Za-z0-9]{20,}\b"),
        "service": "Stripe (test)", "safe": False,
        "impact": "Stripe test-mode key — lower impact but still confirms a leak "
                  "pattern; do not auto-call.",
        "severity": "low",
    },
    "sendgrid": {
        "regex": re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
        "service": "SendGrid", "safe": False,
        "impact": "Email send on the victim's account — phishing/spam from a "
                  "trusted domain. Send-capable; do not auto-fire.",
        "severity": "high",
    },
    "twilio": {
        "regex": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        "service": "Twilio", "safe": False,
        "impact": "Telephony (SMS/voice) on victim billing; toll fraud. "
                  "Do not auto-call.",
        "severity": "high",
    },
    "mailgun": {
        "regex": re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
        "service": "Mailgun", "safe": False,
        "impact": "Email send on victim domain — phishing/spam. Do not auto-fire.",
        "severity": "high",
    },
    "private_key": {
        "regex": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "service": "Private key", "safe": False,
        "impact": "Private key material — auth impersonation / decryption. "
                  "No remote validation; report the exposure directly.",
        "severity": "high",
    },
}

# Read-only whoami validators for the safe types: (method, url, header builder).
_VALIDATORS: dict[str, dict[str, Any]] = {
    "github_token": {
        "method": "GET", "url": "https://api.github.com/user",
        "headers": lambda s: {"Authorization": f"token {s}", "User-Agent": "praetor"},
        "id_field": "login",
    },
    "gitlab_token": {
        "method": "GET", "url": "https://gitlab.com/api/v4/user",
        "headers": lambda s: {"PRIVATE-TOKEN": s},
        "id_field": "username",
    },
    "slack_token": {
        "method": "POST", "url": "https://slack.com/api/auth.test",
        "headers": lambda s: {"Authorization": f"Bearer {s}"},
        "id_field": "user",
    },
    "npm_token": {
        "method": "GET", "url": "https://registry.npmjs.org/-/whoami",
        "headers": lambda s: {"Authorization": f"Bearer {s}"},
        "id_field": "username",
    },
}


def classify_secret(secret: str) -> str | None:
    """First matching secret type, or None. Order: specific before generic."""
    for name, spec in SECRET_TYPES.items():
        if spec["regex"].search(secret or ""):
            return name
    return None


def redact_secret(secret: str) -> str:
    """Shape only: <prefix>…<last4>. Never the body."""
    if not secret:
        return "…"
    prefix = secret[:4]
    tail = secret[-4:] if len(secret) > 12 else ""
    return f"{prefix}…{tail}"


def is_safe_to_validate(kind: str) -> bool:
    return bool(SECRET_TYPES.get(kind, {}).get("safe"))


def impact_for(kind: str) -> str:
    return SECRET_TYPES.get(kind, {}).get("impact", "")


async def _http_req(method: str, url: str, headers: dict, timeout: int, data=None):
    """Isolated so tests monkeypatch the network. Returns (status, text, headers)."""
    import httpx

    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
        r = await client.request(method, url, headers=headers, data=data)
        return r.status_code, r.text, dict(r.headers)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def audit_exposed_secret(secret: str, timeout: int = 15) -> dict:
        """Classify an exposed secret and, IF safe, validate it read-only.

        Auto-validates only whoami-style keys (GitHub/GitLab/Slack/npm/Google).
        Financial/destructive keys (Stripe/AWS/Twilio/SendGrid/Mailgun/private)
        are classified with impact + a manual-only note — never auto-called.
        The secret is redacted to shape in all output.

        Returns: {kind, service, severity, redacted, auto_validated, active,
        identity, scopes, impact, note}.
        """
        kind = classify_secret(secret or "")
        if kind is None:
            return {"error": "unrecognized secret format", "kind": None}

        spec = SECRET_TYPES[kind]
        base = {
            "kind": kind,
            "service": spec["service"],
            "severity": spec["severity"],
            "redacted": redact_secret(secret),
            "impact": spec["impact"],
            "auto_validated": False,
            "active": None,
        }

        if not is_safe_to_validate(kind):
            base["note"] = (
                "Not auto-validated: this key type can bill or change state. "
                "Report the exposure; validate only read-only and with explicit "
                "authorization."
            )
            return base

        v = _VALIDATORS.get(kind)
        if kind == "google_api_key":
            base["note"] = "Use audit_google_api_key for full Gemini capability + impact."
            v = None
        if v is None:
            return base

        status, body, resp_headers = await _http_req(
            v["method"], v["url"], v["headers"](secret), timeout
        )
        try:
            data = json.loads(body) if body else {}
        except ValueError:
            data = {}
        active = status == 200 and (kind != "slack_token" or data.get("ok") is True)
        base.update(
            {
                "auto_validated": True,
                "active": bool(active),
                "identity": data.get(v["id_field"]) if active else None,
                "scopes": resp_headers.get("x-oauth-scopes", "") if active else "",
            }
        )
        return base
