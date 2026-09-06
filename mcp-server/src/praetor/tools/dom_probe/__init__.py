"""DOM-aware probe layer.

Sends a unique marker — optionally wrapped in a polyglot exploit syntax
and embedded in a custom URL-shape — through query / fragment / referrer
and captures which DOM sinks the marker reaches. Designed to surface
the vuln classes pure HTTP-and-look-at-response probing cannot detect:

- DOM-based XSS         (innerHTML / code-eval / document.write / Function)
- DOM open redirection  (location.assign / replace / href / window.open)
- Link manipulation     (href / src / action attribute set with marker)
- DOM data manipulation (textNode marker reflection without sink fire)
- CSPP                  (Object.prototype canary OR new own-prop appeared)
- AngularJS CSTI        (ng-bind / ng-include text contains marker)

Source kinds:

- query         ?<source_param>=<payload>
- fragment      #<payload>
- fragment_kv   #<source_param>=<payload>
- fragment_shapes  several router patterns (see _FRAGMENT_SHAPES)
- referrer      Referer: <attacker>?<source_param>=<payload>

Polyglot wrappers are rotated per source kind so the same source/sink
pair gets multiple chances to trigger framework evaluation, DOM
injection, or prototype pollution.

Split from a single 612-line dom_probe.py:
  _constants.py — sink map / polyglot wrappers / CSPP keys / fragment shapes
  _helpers.py    — marker, URL builder, click-crawl, init-script loader, input validation
  _findings.py   — post-scan finding extraction + VerdictResult rendering
  __init__.py    — register(mcp) + test_dom_sinks tool (browser-loop orchestration)
"""

from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from praetor.tools.browser import _ensure_browser

from ._constants import _POLYGLOTS
from ._findings import (
    _findings_from_cspp_scan,
    _findings_from_scan,
    _render_dom_verdict,
)
from ._helpers import (
    _build_target_url,
    _click_crawl,
    _load_init_js,
    _make_marker,
    _validate_probe_inputs,
)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def test_dom_sinks(  # cost: medium
        url: str,
        source_param: str = "q",
        source_kinds: list[str] | None = None,
        polyglots: list[str] | None = None,
        fragment_shapes: list[str] | None = None,
        cspp_known_keys: list[str] | None = None,
        wait_ms: int = 2500,
        click_crawl: bool = True,
        max_clicks: int = 3,
    ) -> dict:
        """Inject a marker (optionally polyglot-wrapped) via query/fragment/referrer and capture which DOM sinks it reaches. Returns VerdictResult.

        Detects DOM XSS, DOM open-redirect, link manipulation, DOM data manipulation, CSPP, AngularJS CSTI.

        Args:
            url: Target URL (must be in scope).
            source_param: Param to inject into (query/fragment_kv/fragment_shapes/referrer).
            source_kinds: Subset of query/fragment/fragment_kv/fragment_shapes/referrer. Default all.
            polyglots: Subset of plain/angular_csti/handlebars/proto_pollute/proto_constr/xss_svg/xss_img/url_break. Default: plain, angular_csti, proto_pollute, xss_svg.
            fragment_shapes: Router patterns for 'fragment_shapes' (bare/param/qs_in_hash/hash_route/hash_route_kv/hashbang_kv). Default all.
            cspp_known_keys: Object.prototype keys to pollute via ?__proto__[key]=marker; sinks reading the key flag DOM-XSS-via-CSPP. Default: transport_url/src/url/html/redirect_uri/... Pass [] to disable.
            wait_ms: Wait after navigation for async DOM mutations (default 2500).
            click_crawl: Click up to max_clicks same-origin anchors to trigger SPA-router sinks. Default True.
            max_clicks: Cap on click_crawl navigations. Default 3.
        """
        from praetor import client as burp_client

        scope = await burp_client.check_scope(url)
        if "error" not in scope and not scope.get("in_scope", False):
            return f"Error: {url} is OUT OF SCOPE. configure_scope() first."

        resolved = _validate_probe_inputs(
            source_kinds, polyglots, fragment_shapes, cspp_known_keys,
        )
        if isinstance(resolved, str):
            return resolved
        kinds, active_polys, active_shapes, active_cspp_keys = resolved

        try:
            init_template = _load_init_js()
        except OSError as e:
            return f"Error: could not load DOM init script ({e})"

        _, context, _ = await _ensure_browser()

        all_findings: list[dict] = []
        per_run_summary: list[str] = []

        # Build the (kind, shape) tuples to iterate. fragment_shapes expands
        # into one entry per shape; other kinds appear once with shape=None.
        run_specs: list[tuple[str, str | None]] = []
        for kind in kinds:
            if kind == "fragment_shapes":
                for shape in active_shapes:
                    run_specs.append((kind, shape))
            else:
                run_specs.append((kind, None))

        for kind, shape in run_specs:
            for poly_name in active_polys:
                shape_tag = (shape or "")[:3]
                marker = _make_marker(suffix=f"{kind[:1]}{poly_name[:1]}{shape_tag}")
                payload = _POLYGLOTS[poly_name].format(marker=marker)
                target_url, extra_headers = _build_target_url(
                    url, payload, source_param, kind, shape or "bare",
                )
                init = init_template.replace("__SWMARKER__", marker)

                page = await context.new_page()
                try:
                    await page.add_init_script(init)
                    if extra_headers:
                        await page.set_extra_http_headers(extra_headers)
                    try:
                        await page.goto(target_url, wait_until="domcontentloaded", timeout=20000)
                    except Exception as e:
                        per_run_summary.append(
                            f"  [{kind}{('/'+shape) if shape else ''}/{poly_name}] navigate failed: {str(e)[:120]}"
                        )
                        continue

                    try:
                        await page.mouse.move(100, 100)
                        await page.mouse.move(200, 200)
                        await page.mouse.down()
                        await page.mouse.up()
                    except Exception:
                        pass

                    await page.wait_for_timeout(wait_ms)

                    # In-app click-crawl: SPA routers often only fire their
                    # DOM-side template/render sinks after a navigation event.
                    # The initial goto sets the URL, but the JS routing code
                    # that consumes the fragment may not run until a click
                    # triggers it.
                    if click_crawl:
                        await _click_crawl(page, max_clicks=max_clicks, wait_each_ms=wait_ms // 2 or 800)

                    try:
                        scan = await page.evaluate(
                            "() => window.__sw_post_scan ? window.__sw_post_scan() : null"
                        )
                    except Exception as e:
                        per_run_summary.append(
                            f"  [{kind}{('/'+shape) if shape else ''}/{poly_name}] scan call failed: {str(e)[:120]}"
                        )
                        continue

                    if not scan:
                        per_run_summary.append(
                            f"  [{kind}{('/'+shape) if shape else ''}/{poly_name}] init script did not load"
                        )
                        continue

                    new_findings, summary = _findings_from_scan(
                        scan, kind, shape, poly_name, source_param, marker,
                    )
                    all_findings.extend(new_findings)
                    per_run_summary.append(summary)
                finally:
                    try:
                        await page.close()
                    except Exception:
                        pass

        # CSPP known-key pass: pollute Object.prototype.<key> with the marker
        # as VALUE. Detection: marker showed up at any sink, or
        # Object.prototype[<key>] === marker post-scan.
        for ck in active_cspp_keys:
            marker = _make_marker(suffix=f"c{ck[:4]}")
            parsed = urlparse(url)
            sep = "&" if parsed.query else "?"
            target_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{('?' + parsed.query) if parsed.query else ''}{sep}__proto__[{ck}]={marker}"
            if parsed.fragment:
                target_url += f"#{parsed.fragment}"
            init = init_template.replace("__SWMARKER__", marker)
            page = await context.new_page()
            try:
                await page.add_init_script(init)
                try:
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=20000)
                except Exception as e:
                    per_run_summary.append(
                        f"  [cspp_known_key/{ck}] navigate failed: {str(e)[:120]}"
                    )
                    continue
                await page.wait_for_timeout(wait_ms)
                if click_crawl:
                    await _click_crawl(page, max_clicks=max_clicks, wait_each_ms=wait_ms // 2 or 800)

                try:
                    proto_val = await page.evaluate(
                        "(k) => { try { return Object.prototype[k]; } catch(e) { return null; } }",
                        ck,
                    )
                except Exception:
                    proto_val = None
                try:
                    scan = await page.evaluate(
                        "() => window.__sw_post_scan ? window.__sw_post_scan() : null"
                    )
                except Exception:
                    scan = None

                new_findings, summary = _findings_from_cspp_scan(scan, proto_val, ck, marker)
                all_findings.extend(new_findings)
                per_run_summary.append(summary)
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

        return _render_dom_verdict(
            url, source_param, kinds, active_polys, active_shapes,
            active_cspp_keys, click_crawl, max_clicks, all_findings, per_run_summary,
        )
