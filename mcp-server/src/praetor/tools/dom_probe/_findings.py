"""Pure post-scan processing for the DOM probe: turn a per-run DOM scan dict
into finding records, and render the final VerdictResult. No browser I/O — the
async navigation loop stays in __init__.py; these consume its scan output."""

from praetor.tools.testing._verdict import make_verdict

from ._constants import _SINK_TO_VULN_CLASS


def _findings_from_scan(
    scan: dict,
    kind: str,
    shape: str | None,
    poly_name: str,
    source_param: str,
    marker: str,
) -> tuple[list[dict], str]:
    """Convert one main-loop scan result into (findings, summary_line)."""
    hits = scan.get("hits", []) or []
    attr_hits = scan.get("attribute_marker_hits", []) or []
    text_hits = scan.get("textnode_marker_hits", 0) or 0
    pp_canary = scan.get("pp_canary")
    pp_keys = scan.get("pp_polluted_keys", []) or []
    rendered_marker = scan.get("rendered_html_marker", False)

    src_param = source_param if kind != "fragment" else "(fragment)"
    findings: list[dict] = []

    for h in hits:
        sink = h.get("sink", "?")
        vclass, descr = _SINK_TO_VULN_CLASS.get(sink, ("dom_xss", f"Marker reached {sink}"))
        findings.append({
            "vuln_class": vclass,
            "sink": sink,
            "source_kind": kind,
            "fragment_shape": shape,
            "polyglot": poly_name,
            "source_param": src_param,
            "marker": marker,
            "description": descr,
            "value_excerpt": h.get("value_excerpt", ""),
            "stack": h.get("stack", ""),
            "tag": h.get("tag", ""),
        })

    for a in attr_hits:
        findings.append({
            "vuln_class": "link_manipulation",
            "sink": f"<{a.get('tag','?').lower()} {a.get('attr','?')}>",
            "source_kind": kind,
            "fragment_shape": shape,
            "polyglot": poly_name,
            "source_param": src_param,
            "marker": marker,
            "description": f"Marker reflected into {a.get('attr', '?')} attribute of <{a.get('tag','?').lower()}> — DOM link manipulation",
            "value_excerpt": a.get("value", "")[:200],
        })

    if text_hits > 0 and not any(
        h.get("sink") in ("innerHTML", "outerHTML", "document.write") for h in hits
    ):
        findings.append({
            "vuln_class": "dom_data_manipulation",
            "sink": "textnode",
            "source_kind": kind,
            "fragment_shape": shape,
            "polyglot": poly_name,
            "source_param": src_param,
            "marker": marker,
            "description": (
                f"Marker written into {text_hits} text node(s) — DOM data "
                f"manipulation (no executable sink, but content reflects "
                f"user-controlled source)"
            ),
        })

    if isinstance(pp_canary, str) and marker in pp_canary:
        findings.append({
            "vuln_class": "client_side_prototype_pollution",
            "sink": "Object.prototype.__sw_pp_canary__",
            "source_kind": kind,
            "fragment_shape": shape,
            "polyglot": poly_name,
            "source_param": src_param,
            "marker": marker,
            "description": "Marker reached Object.prototype via merge/extend gadget — CSPP",
            "value_excerpt": str(pp_canary)[:200],
        })

    if marker in pp_keys:
        findings.append({
            "vuln_class": "client_side_prototype_pollution",
            "sink": f"Object.prototype.{marker}",
            "source_kind": kind,
            "fragment_shape": shape,
            "polyglot": poly_name,
            "source_param": src_param,
            "marker": marker,
            "description": (
                f"`__proto__[{marker}]=1` polyglot succeeded — "
                f"Object.prototype acquired the marker key. Confirms CSPP merge-gadget."
            ),
        })

    summary = (
        f"  [{kind}{('/'+shape) if shape else ''}/{poly_name}] "
        f"sinks={len(hits)} attr={len(attr_hits)} text={text_hits} "
        f"pp_canary={'Y' if pp_canary else 'N'} pp_keys={len(pp_keys)} "
        f"html={'Y' if rendered_marker else 'N'}"
    )
    return findings, summary


def _findings_from_cspp_scan(
    scan: dict | None,
    proto_val,
    ck: str,
    marker: str,
) -> tuple[list[dict], str]:
    """Convert one CSPP known-key scan result into (findings, summary_line)."""
    hits = (scan or {}).get("hits", []) or []
    attr_hits = (scan or {}).get("attribute_marker_hits", []) or []
    polluted = isinstance(proto_val, str) and marker in proto_val
    findings: list[dict] = []

    if polluted:
        findings.append({
            "vuln_class": "client_side_prototype_pollution",
            "sink": f"Object.prototype.{ck}",
            "source_kind": "query",
            "fragment_shape": None,
            "polyglot": "cspp_known_key",
            "source_param": f"__proto__[{ck}]",
            "marker": marker,
            "description": (
                f"`?__proto__[{ck}]=...` polluted Object.prototype.{ck} "
                f"with the marker. App-used key — direct gadget for any "
                f"sink that reads {ck} from a config object."
            ),
            "value_excerpt": str(proto_val)[:200],
        })

    for h in hits:
        sink = h.get("sink", "?")
        vclass, descr = _SINK_TO_VULN_CLASS.get(sink, ("dom_xss", f"Marker reached {sink}"))
        chain_note = (
            f" (CSPP→sink chain: __proto__[{ck}] populated, then {sink} read it)"
            if polluted else f" (CSPP attempt for key={ck})"
        )
        findings.append({
            "vuln_class": vclass,
            "sink": sink,
            "source_kind": "query",
            "fragment_shape": None,
            "polyglot": f"cspp_known_key[{ck}]",
            "source_param": f"__proto__[{ck}]",
            "marker": marker,
            "description": descr + chain_note,
            "value_excerpt": h.get("value_excerpt", ""),
            "stack": h.get("stack", ""),
            "tag": h.get("tag", ""),
        })

    for a in attr_hits:
        findings.append({
            "vuln_class": "link_manipulation",
            "sink": f"<{a.get('tag','?').lower()} {a.get('attr','?')}>",
            "source_kind": "query",
            "fragment_shape": None,
            "polyglot": f"cspp_known_key[{ck}]",
            "source_param": f"__proto__[{ck}]",
            "marker": marker,
            "description": (
                f"CSPP→link chain: marker reflected into "
                f"{a.get('attr', '?')} of <{a.get('tag','?').lower()}> after "
                f"polluting Object.prototype.{ck}"
            ),
            "value_excerpt": a.get("value", "")[:200],
        })

    summary = (
        f"  [cspp_known_key/{ck}] sinks={len(hits)} attr={len(attr_hits)} "
        f"polluted={'Y' if polluted else 'N'}"
    )
    return findings, summary


def _render_dom_verdict(
    url: str,
    source_param: str,
    kinds: list[str],
    active_polys: list[str],
    active_shapes: list[str],
    active_cspp_keys: list[str],
    click_crawl: bool,
    max_clicks: int,
    all_findings: list[dict],
    per_run_summary: list[str],
) -> dict:
    """Build the human summary + final VerdictResult from accumulated findings."""
    lines = [f"DOM probe: {url}"]
    lines.append(
        f"Source param: {source_param} | Kinds: {', '.join(kinds)} | "
        f"Polyglots: {', '.join(active_polys)}"
        + (f" | Frag shapes: {', '.join(active_shapes)}" if "fragment_shapes" in kinds else "")
        + (f" | CSPP keys: {len(active_cspp_keys)}" if active_cspp_keys else "")
        + (f" | click_crawl=on (max {max_clicks})" if click_crawl else " | click_crawl=off")
    )
    lines.append("")
    lines.extend(per_run_summary)
    lines.append("")
    if not all_findings:
        lines.append("No DOM sink reflections detected.")
        return make_verdict(
            "FAILED", 0.1,
            "no DOM sink reflections found across query / fragment / referrer / CSPP probes",
            vuln_type="dom_xss",
            details={"url": url, "kinds_tried": list(kinds)},
            summary="\n".join(lines),
        )

    lines.append(f"FINDINGS ({len(all_findings)}):")
    grouped: dict[str, list[dict]] = {}
    for f in all_findings:
        grouped.setdefault(f["vuln_class"], []).append(f)
    for vc, fs in grouped.items():
        lines.append(f"\n--- {vc.upper()} ({len(fs)}) ---")
        for f in fs[:8]:
            shape = f.get("fragment_shape")
            shape_str = f"/{shape}" if shape else ""
            lines.append(
                f"  sink={f['sink']}  source={f['source_kind']}{shape_str}({f['source_param']})  "
                f"poly={f.get('polyglot','-')}"
            )
            lines.append(f"    {f['description']}")
            ve = f.get("value_excerpt", "")
            if ve:
                lines.append(f"    value: {ve[:160]}")
            tag = f.get("tag", "")
            if tag:
                lines.append(f"    tag: <{tag.lower()}>")
        if len(fs) > 8:
            lines.append(f"  ... +{len(fs) - 8} more")

    lines.append("")
    lines.append(
        "Verify each finding manually before save_finding — confirm the source is "
        "attacker-controllable (cross-origin / link-shared / fragment-craftable) and "
        "the sink isn't sanitised (Trusted Types / DOMPurify / framework escaping)."
    )
    human = "\n".join(lines)

    # Severity-class signal: presence of dom_xss / open_redirect classes
    # in findings = stronger verdict; only CSPP / data-manip = SUSPECTED.
    classes = {f["vuln_class"] for f in all_findings}
    critical_classes = classes & {"dom_xss", "csti", "code_eval", "open_redirect"}
    if critical_classes:
        verdict, confidence = "CONFIRMED", 0.8
        ev = f"DOM sink reflection in {len(all_findings)} probe(s) across {', '.join(sorted(critical_classes))}"
    else:
        verdict, confidence = "SUSPECTED", 0.55
        ev = f"DOM marker reflected in {len(all_findings)} probe(s); no critical-class sink hit yet"

    return make_verdict(
        verdict, confidence, ev,
        vuln_type="dom_xss",
        details={
            "url": url,
            "findings_count": len(all_findings),
            "vuln_classes": sorted(classes),
            "findings_preview": all_findings[:10],
        },
        summary=human,
    )
