"""External-tool run ledger — which CLI tool ran against which target.

The tool-call ledger (``oplog/_toolcalls.py``) times every MCP call but drops
arguments, so it cannot answer "did sqlmap ever run against host X?". This
records the spawned CLI binary plus the target host(s) parsed from its argv, at
the subprocess seam. ``tool_coverage_gaps(domain)`` diffs this against a
per-lane roster of lead-generating tools and reports the ones that never ran —
so no recon/scan lane is silently skipped (Rules 19 / 19a).

Secret-safe by construction: target extraction is an ALLOWLIST, not a flag
denylist. Only dotted-hostname / IPv4 tokens are kept (authority only, URL
userinfo stripped). A password, header, cookie, or API token is never a dotted
hostname, so it can never be stored — and this sidesteps the ``-u``/``-p``
ambiguity (URL-vs-user, ports-vs-password) that a flag denylist would hit.

Fail-open: a ledger fault never breaks a tool call. Disable with
PRAETOR_TOOLLOG=off. Global ledger at .burp-intel/_harness/tool_runs.jsonl.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

# ── roster: lead-generating tools per lane ──────────────────────────────────
# Deliberately NOT every binary setup.sh installs — only the tools whose
# ABSENCE against a target is a real coverage gap worth surfacing. Utilities
# (dig, tesseract, decoders) are not here. Interchangeable tools are collapsed
# via _EQUIV so either member satisfies the slot.
ROSTER: dict[str, list[str]] = {
    "recon": ["subfinder", "amass", "dnsx", "httpx", "katana", "gau",
              "waybackurls", "ffuf", "nuclei", "tlsx", "asnmap", "arjun"],
    "web-scan": ["vigil", "sqlmap", "dalfox", "commix", "ghauri", "nikto",
                 "wpscan", "wafw00f", "graphw00f"],
    "network": ["nmap", "groma", "nxc"],
    "cloud": ["prowler", "scout", "checkov", "trivy", "kube-hunter"],
    "secrets-sast": ["trufflehog", "gitleaks", "osv-scanner", "grype", "semgrep"],
}
# recon + web-scan apply to every HTTP target; the rest activate once any of
# their tools has run against the target (lane is "in play").
ALWAYS_ON = ("recon", "web-scan")
# Interchangeable binaries → canonical roster name.
_EQUIV = {"netexec": "nxc", "scoutsuite": "scout", "opengrep": "semgrep"}

_LANE_OF: dict[str, str] = {}
for _lane, _tools in ROSTER.items():
    for _t in _tools:
        _LANE_OF[_t] = _lane

# Tokens that are dotted but are plainly not hosts.
_NON_HOST_EXT = {
    "json", "xml", "txt", "html", "htm", "csv", "log", "md", "yaml", "yml",
    "conf", "cfg", "ini", "py", "sh", "js", "ts", "out", "tmp", "db", "sqlite",
    "pem", "crt", "key", "zip", "gz", "tar", "jar", "war",
}
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9_-]+\.)+[a-z][a-z0-9-]*$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def enabled() -> bool:
    return os.environ.get("PRAETOR_TOOLLOG", "").strip().lower() not in ("off", "0", "false", "no")


def _ledger_path() -> Path:
    return Path.cwd() / ".burp-intel" / "_harness" / "tool_runs.jsonl"


def _norm_host(token: str) -> str:
    """Normalise one argv token to a bare hostname, or '' if it is not host-like.

    Allowlist: keep only a dotted domain or an IPv4. Strip scheme, URL
    userinfo (user:pass@), port, and any path/query. This is what makes the
    ledger secret-safe — a credential is never a dotted hostname.
    """
    if not token or not isinstance(token, str):
        return ""
    # --url=https://x form → take the value after '='.
    if token.startswith("-"):
        if "=" in token:
            token = token.split("=", 1)[1]
        else:
            return ""
    token = token.strip()
    if not token:
        return ""
    # Strip scheme.
    token = re.sub(r"^[a-z][a-z0-9+.-]*://", "", token, flags=re.IGNORECASE)
    # Authority only — cut at first path / query / fragment.
    token = re.split(r"[/?#]", token, 1)[0]
    # Strip userinfo (anything the password could hide in).
    if "@" in token:
        token = token.rsplit("@", 1)[1]
    # Strip port.
    if token.count(":") == 1:
        token = token.split(":", 1)[0]
    token = token.strip(".").lower()
    if not token:
        return ""
    if _IPV4_RE.match(token):
        return token
    if _DOMAIN_RE.match(token) and token.rsplit(".", 1)[-1] not in _NON_HOST_EXT:
        return token
    return ""


def _targets_from_argv(argv: list[str]) -> list[str]:
    """Host/IP targets parsed from argv, deduped, order-preserving."""
    out: list[str] = []
    seen: set[str] = set()
    for tok in argv[1:] if argv else []:
        host = _norm_host(tok)
        if host and host not in seen:
            seen.add(host)
            out.append(host)
            if len(out) >= 16:  # bound a pathological argv
                break
    return out


def make_entry(tool: str, targets: list[str]) -> dict:
    """Pure: one ledger line. Only ts / tool / targets — secret-free."""
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "targets": targets,
    }


def record_run(cmd: list[str], tool: str | None = None) -> None:
    """Best-effort append of one tool run. Never raises (fail-open).

    ``tool`` defaults to the basename of ``cmd[0]``; pass it when the binary is
    a runner (e.g. ``python exploit.py`` → tool='pyexploit').
    """
    try:
        if not enabled():
            return
        if not cmd or not isinstance(cmd, (list, tuple)) or not cmd[0]:
            return
        name = tool or os.path.basename(str(cmd[0]))
        entry = make_entry(name, _targets_from_argv(list(cmd)))
        path = _ledger_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # fail-open: the ledger is diagnostics, never a gate


def read_runs(limit: int = 5000, tool: str = "", target: str = "") -> list[dict]:
    """Most-recent-first ledger entries, optionally filtered by tool / target."""
    path = _ledger_path()
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: list[dict] = []
    for line in reversed(lines):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if tool and e.get("tool") != tool:
            continue
        if target and not any(_host_matches(t, target) for t in e.get("targets", [])):
            continue
        out.append(e)
        if len(out) >= max(1, limit):
            break
    return out


def _host_matches(target: str, domain: str) -> bool:
    """True when a recorded target maps to the queried domain.

    Exact, subdomain-of-domain, or parent-of-domain all count — an IP matches
    only itself.
    """
    t, d = str(target).lower().strip("."), str(domain).lower().strip(".")
    if not t or not d:
        return False
    return t == d or t.endswith("." + d) or d.endswith("." + t)


def compute_gaps(domain: str, runs: list[dict]) -> dict:
    """Pure: diff the per-lane roster against runs matched to ``domain``.

    Returns per-lane {active, ran, missing} plus a flat ``gaps`` list of
    ``lane/tool`` for every unrun tool in an ACTIVE lane.
    """
    ran_by_lane: dict[str, set[str]] = {lane: set() for lane in ROSTER}
    for e in runs:
        if not any(_host_matches(t, domain) for t in e.get("targets", [])):
            continue
        name = _EQUIV.get(e.get("tool", ""), e.get("tool", ""))
        lane = _LANE_OF.get(name)
        if lane:
            ran_by_lane[lane].add(name)

    lanes: dict[str, dict] = {}
    gaps: list[str] = []
    for lane, tools in ROSTER.items():
        ran = sorted(ran_by_lane[lane])
        active = lane in ALWAYS_ON or bool(ran)
        missing = [t for t in tools if t not in ran_by_lane[lane]]
        lanes[lane] = {"active": active, "ran": ran, "missing": missing}
        if active:
            gaps.extend(f"{lane}/{t}" for t in missing)
    return {"domain": domain, "lanes": lanes, "gaps": gaps}
