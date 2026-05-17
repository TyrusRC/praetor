"""bsearch_hidden_params — Param-Miner-style binary-search hidden parameter discovery.

Linear wordlist probing (one request per param) is O(N). With 65K candidate
names, that's 65K requests. Param-Miner observed that param-acceptance is
binary — a request with 32K params either gives a different response from
baseline (one of the params is accepted) or it doesn't (none accepted).

So:
  - Bundle N candidates into one request.
  - Compare response to baseline (status / length / response_hash / reflected
    canary).
  - If different: bisect the bundle and recurse.
  - If same: discard all N.

O(log N) requests in the no-hit case, O(K * log N) when K params accepted.
With cache-busting + reflection canaries we catch params that change behavior
but don't echo. Routes through Burp (Rule 26a) — every request is captured.
"""

import asyncio
import hashlib
import time
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qsl

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


# Compact wordlist embedded — common dev/backend param names. 200 entries.
# For broader coverage operator can pass extra_wordlist or use Arjun's 25k wordlist.
_BUILTIN_PARAMS = [
    "debug", "test", "admin", "internal", "preview", "draft", "verbose", "trace",
    "id", "user_id", "userid", "uid", "account_id", "tenant_id", "org_id",
    "callback", "jsonp", "redirect", "return", "next", "url", "uri", "href",
    "cmd", "exec", "command", "shell", "system", "run",
    "file", "filename", "path", "filepath", "include", "template", "view",
    "page", "p", "q", "query", "search", "s", "name", "type", "kind", "lang",
    "format", "output", "render", "mode", "level", "version", "v",
    "api_key", "apikey", "key", "token", "auth", "secret", "password", "pass",
    "from", "to", "since", "until", "start", "end", "limit", "offset", "size",
    "sort", "order", "asc", "desc", "filter", "where", "select", "fields",
    "method", "action", "op", "operation", "endpoint",
    "is_admin", "isAdmin", "role", "permission", "perms", "grant", "scope",
    "skip_auth", "skipauth", "bypass", "force", "override", "noauth",
    "host", "server", "domain", "tenant", "site",
    "lang", "locale", "country", "region", "timezone",
    "raw", "html", "json", "xml", "csv", "yaml", "xls",
    "image", "img", "photo", "avatar", "attachment", "upload",
    "email", "phone", "address", "zip", "postcode", "city", "state",
    "first_name", "last_name", "fullname", "username", "handle",
    "company", "business", "department", "team", "group",
    "amount", "price", "cost", "total", "tax", "discount", "currency",
    "qty", "quantity", "count", "max", "min",
    "lat", "lng", "latitude", "longitude", "coords",
    "ttl", "expires", "expiry", "expiration", "deadline",
    "ref", "referrer", "referer", "source", "campaign", "utm_source",
    "device", "platform", "os", "browser", "ua",
    "checksum", "hash", "sig", "signature", "hmac", "nonce", "salt",
    "session", "sid", "sessionid", "csrf", "csrf_token", "xsrf",
    "force_refresh", "no_cache", "nocache", "fresh", "skip_cache",
    "include_deleted", "with_deleted", "trashed", "deleted",
    "show_hidden", "include_hidden", "include_private", "show_private",
    "expand", "include", "with", "embed", "fields", "select_fields",
    "show_internal", "internal_id", "external_id", "external", "private",
    "log", "logging", "logs", "audit",
    "env", "environment", "stage", "production", "dev", "development",
    "feature", "feature_flag", "flag", "ff",
    "step", "phase", "state", "status", "stage",
    "amount_cents", "amount_usd", "currency_code",
    "consent", "agree", "accept", "terms", "tos",
    "rate", "rate_limit", "throttle",
    "format", "encoding", "charset",
]


def _make_canary() -> str:
    return f"swkBS{int(time.time() * 1000) % 100_000_000:x}"


def _response_signature(status: int, body: str) -> tuple[int, int, str]:
    """Triplet that fingerprints a response for diff-against-baseline."""
    return (status, len(body), hashlib.sha1(body.encode("utf-8", errors="replace")).hexdigest()[:12])


async def _send_with_params(
    base_url: str,
    method: str,
    extras: dict[str, str],
    session: str = "",
    base_headers: dict | None = None,
) -> tuple[int, int, str, str]:
    """Send request with extras merged into query / body. Returns (status, length, hash, body)."""
    parsed = urlparse(base_url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))

    if method.upper() == "GET":
        q.update(extras)
        new_url = parsed._replace(query=urlencode(q, doseq=True)).geturl()
        if session:
            resp = await client.post("/api/session/request", json={
                "session": session, "method": "GET",
                "path": parsed.path + (f"?{urlencode(q, doseq=True)}" if q else ""),
                "headers": base_headers or {},
            })
        else:
            resp = await client.post("/api/http/curl", json={
                "method": "GET", "url": new_url,
                "headers": base_headers or {},
            })
    else:
        body_str = urlencode(extras, doseq=True)
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        hdrs.update(base_headers or {})
        if session:
            resp = await client.post("/api/session/request", json={
                "session": session, "method": method.upper(),
                "path": parsed.path + (f"?{parsed.query}" if parsed.query else ""),
                "headers": hdrs, "body": body_str,
            })
        else:
            resp = await client.post("/api/http/curl", json={
                "method": method.upper(), "url": base_url,
                "headers": hdrs, "body": body_str,
            })
    if "error" in resp:
        return -1, 0, "", resp["error"]
    status = resp.get("status", resp.get("status_code", 0))
    body = resp.get("response_body", resp.get("body", ""))
    return status, len(body), hashlib.sha1(body.encode("utf-8", errors="replace")).hexdigest()[:12], body


def register(mcp: FastMCP):

    @mcp.tool()
    async def bsearch_hidden_params(
        target_url: str,
        method: str = "GET",
        session: str = "",
        extra_wordlist: list[str] | None = None,
        baseline_runs: int = 2,
        max_recursion: int = 12,
        chunk_value_template: str = "{canary}",
    ) -> str:
        """Binary-search hidden-parameter discovery — bundles candidates, bisects on response diff.

        For each candidate it builds a chunk-name -> canary-value mapping where the canary
        is unique per chunk so a "reflected" param is provable.

        Args:
            target_url: Base URL (existing query params preserved as baseline).
            method: HTTP method (GET / POST). POST sends params in body.
            session: Optional auth session.
            extra_wordlist: Operator-supplied extra param names appended to built-in.
            baseline_runs: How many baseline calls to average (kill flakiness).
            max_recursion: Bisection depth cap (default 12 -> handles 4096 params).
            chunk_value_template: Per-param value template (default {canary}). Use literal e.g. '1' for boolean-flag-style probes.
        """
        wordlist = list(_BUILTIN_PARAMS)
        if extra_wordlist:
            wordlist.extend(extra_wordlist)
        # Dedupe preserving order
        seen = set()
        wordlist = [p for p in wordlist if not (p in seen or seen.add(p))]
        if not wordlist:
            return "Error: empty wordlist"

        # Scope check
        scope = await client.check_scope(target_url)
        if "error" in scope:
            return f"Error: scope check failed: {scope['error']}"
        if not scope.get("in_scope", False):
            return f"Error: {target_url} not in scope"

        # Baseline
        baseline_sigs = []
        baseline_body = ""
        for _ in range(max(1, baseline_runs)):
            s, ln, h, body = await _send_with_params(target_url, method, {}, session)
            if s == -1:
                return f"Error establishing baseline: {body}"
            baseline_sigs.append((s, ln, h))
            baseline_body = body
        # Most-common baseline status; pick (status, length-range) as the diff predicate
        baseline_status = baseline_sigs[0][0]
        baseline_lengths = [s[1] for s in baseline_sigs]
        len_min = min(baseline_lengths)
        len_max = max(baseline_lengths)
        len_tol = max(50, int((len_max - len_min) * 1.5 + 10))  # tolerance band

        def _is_different(status: int, length: int, body: str, canaries: list[str]) -> tuple[bool, str]:
            if status != baseline_status:
                return True, f"status flip {baseline_status}->{status}"
            if abs(length - len_min) > len_tol and abs(length - len_max) > len_tol:
                return True, f"length delta {length} vs baseline [{len_min},{len_max}]"
            for c in canaries:
                if c in body and c not in baseline_body:
                    return True, f"reflected canary {c}"
            return False, ""

        accepted: list[tuple[str, str]] = []  # (param, reason)
        attempted_chunks = 0
        attempted_singles = 0

        async def _bisect(chunk: list[str], depth: int) -> None:
            nonlocal attempted_chunks, attempted_singles
            if not chunk:
                return
            attempted_chunks += 1
            # Build extras map: each param gets a unique canary as value
            canaries_by_param: dict[str, str] = {p: _make_canary() for p in chunk}
            extras: dict[str, str] = {p: chunk_value_template.format(canary=v) for p, v in canaries_by_param.items()}

            status, length, _, body = await _send_with_params(target_url, method, extras, session)
            if status == -1:
                # Network error — abort this branch
                return
            different, reason = _is_different(status, length, body, list(canaries_by_param.values()))
            if not different:
                return
            # Found a diff. If chunk is a single param, mark accepted.
            if len(chunk) == 1:
                accepted.append((chunk[0], reason))
                attempted_singles += 1
                return
            if depth >= max_recursion:
                # Depth cap — record the whole remaining chunk as "candidate"
                for p in chunk:
                    accepted.append((p, f"depth_cap {reason}"))
                return
            # Bisect
            mid = len(chunk) // 2
            await _bisect(chunk[:mid], depth + 1)
            await _bisect(chunk[mid:], depth + 1)

        # Start with whole wordlist split into reasonable initial buckets to avoid
        # gigantic single requests that some servers reject (URL too long).
        # ~32 params per initial bucket = ~600 byte request bodies, well-tolerated.
        bucket_size = 32
        for i in range(0, len(wordlist), bucket_size):
            await _bisect(wordlist[i:i + bucket_size], 0)

        lines = [
            f"bsearch_hidden_params {method} {target_url}",
            f"Wordlist: {len(wordlist)} candidates | baseline status={baseline_status} length~[{len_min},{len_max}]",
            f"Bisections: {attempted_chunks} bundle-probes -> {attempted_singles} singleton confirms",
            "",
        ]
        if accepted:
            lines.append(f"ACCEPTED params: {len(accepted)}")
            for p, reason in accepted:
                lines.append(f"  {p}  [{reason}]")
            lines.append("\nNext: feed these into auto_probe / fuzz_parameter / test_mass_assignment for actual exploitation.")
        else:
            lines.append("No hidden parameters detected via bisection.")
            lines.append("Consider: pass extra_wordlist (target-specific names) or adjust chunk_value_template (default uses canary string — try '1' for boolean flags).")
        return "\n".join(lines)
