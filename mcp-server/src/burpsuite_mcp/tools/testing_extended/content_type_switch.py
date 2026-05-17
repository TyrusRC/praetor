"""probe_content_type_switch — parser-dependent validation bypass via content-type swap.

Same logical payload, sent as different content-types. If validators run only
against one parser (e.g. JSON schema) but the controller dispatches the same
data via another parser (form / XML / multipart), validation can be bypassed.

Strix-derived. Pure black-box.
"""

import json
import urllib.parse
import uuid as _uuid

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def _to_form(d: dict) -> str:
    items = []
    for k, v in d.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v)
        items.append((str(k), str(v)))
    return urllib.parse.urlencode(items)


def _to_multipart(d: dict) -> tuple[str, str]:
    boundary = "----formdata-" + _uuid.uuid4().hex
    parts = []
    for k, v in d.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v)
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
    parts.append(f"--{boundary}--\r\n")
    return boundary, "".join(parts)


def _to_xml(d: dict, root: str = "request") -> str:
    """Naive dict -> XML — primitive values only at top level."""
    parts = [f"<{root}>"]
    for k, v in d.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v)
        parts.append(f"<{k}>{v}</{k}>")
    parts.append(f"</{root}>")
    return "<?xml version=\"1.0\"?>" + "".join(parts)


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_content_type_switch(
        session: str,
        endpoint: str,
        body: dict,
        method: str = "POST",
        xml_root: str = "request",
    ) -> str:
        """Replay the same body across JSON / form / multipart / XML / plain to find parser-trust mismatch.

        Args:
            session: Auth session.
            endpoint: Target path.
            body: Body as a dict (will be re-encoded per content-type).
            method: HTTP method.
            xml_root: Root element name for XML variant.
        """
        # baseline = canonical JSON
        json_body = json.dumps(body)
        baseline = await client.post("/api/session/request", json={
            "session": session, "method": method, "path": endpoint,
            "headers": {"Content-Type": "application/json"},
            "body": json_body,
        })
        if "error" in baseline:
            return f"Error on JSON baseline: {baseline['error']}"
        b_status = baseline.get("status", 0)
        b_len = len(baseline.get("response_body", ""))
        b_body = baseline.get("response_body", "")

        lines = [
            f"probe_content_type_switch {method} {endpoint}",
            f"[application/json baseline] status={b_status} len={b_len}",
            "",
        ]

        # Variants
        form_body = _to_form(body)
        boundary, multipart_body = _to_multipart(body)
        xml_body = _to_xml(body, xml_root)

        variants = [
            ("application/x-www-form-urlencoded", form_body, "form"),
            (f"multipart/form-data; boundary={boundary}", multipart_body, "multipart"),
            ("application/xml", xml_body, "xml"),
            ("text/xml", xml_body, "text-xml"),
            ("text/plain", json_body, "text-plain (JSON body)"),
            ("application/x-www-form-urlencoded", json_body, "form-ct-json-body (LIE)"),
            ("application/json; charset=utf-7", json_body, "json+utf7 (parser-quirk)"),
            ("application/json/x-jsonlines", json_body, "non-standard subtype"),
            ("", json_body, "empty content-type"),
        ]

        findings: list[str] = []

        for ct, vbody, label in variants:
            send_headers = {"Content-Type": ct} if ct else {}
            r = await client.post("/api/session/request", json={
                "session": session, "method": method, "path": endpoint,
                "headers": send_headers,
                "body": vbody,
            })
            if "error" in r:
                lines.append(f"  {label}: error — {r['error']}")
                continue
            s = r.get("status", 0)
            ln = len(r.get("response_body", ""))
            rbody = r.get("response_body", "")

            flags = []
            # baseline was rejected (4xx) but variant is accepted
            if b_status >= 400 and 200 <= s < 300:
                flags.append("VALIDATION_BYPASSED")
            # baseline was accepted; variant returns different status
            elif b_status != s:
                flags.append(f"STATUS_DIFF:{s}")
            # both 2xx but body materially differs — different code path
            elif 200 <= s < 300 and 200 <= b_status < 300 and b_len > 0 and abs(ln - b_len) / b_len > 0.25:
                flags.append("BODY_DIVERGES")

            flag_str = " ".join(f"[!{f}]" for f in flags) if flags else "[OK]"
            lines.append(f"  {label} ({ct or '<empty>'}): status={s} len={ln} {flag_str}")
            if flags:
                findings.append((label, ct, flags))

        lines.append("\n--- Summary ---")
        if findings:
            lines.append(f"Anomalies: {len(findings)}")
            for label, ct, flags in findings:
                lines.append(f"  [!] {label} ({ct}): {', '.join(flags)}")
            lines.append("\nRisk: server uses different parsers per content-type and validators may not cover all of them. Verify with parameter-pollution / mass-assignment payloads in the accepted variant.")
        else:
            lines.append("No content-type parser divergence detected.")
        return "\n".join(lines)
