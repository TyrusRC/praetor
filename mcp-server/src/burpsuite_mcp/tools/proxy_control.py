"""Tools for controlling Burp proxy — intercept, match-replace, annotations, stats, traffic monitoring.

CRUD-collapsed tools:
  - intercept(action="on"|"off"|"status")
  - match_replace(action="set"|"list"|"remove"|"clear", rules=, rule_id=, force=)
  - traffic_monitor(action="register"|"check"|"remove", tag=, patterns=)
"""

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


# Headers whose rewriting frequently breaks traffic or leaks auth. Flag before applying.
_DANGEROUS_HEADER_PATTERNS = (
    "host:",               # breaks TLS SNI / vhost routing
    "authorization:",      # auth-leak risk if replaced globally
    "cookie:",             # session leak across targets
    "content-length:",     # mismatches body length → smuggling/500s
    "transfer-encoding:",  # request smuggling risk
)


def _lookup_finding_id(finding_id: str) -> tuple[bool, str]:
    """Resolve a finding ID across every .burp-intel domain.

    Returns (exists, "<domain> <title>"). Never raises — a missing or corrupt
    store just means "not found", and the caller refuses the annotation.
    """
    try:
        from burpsuite_mcp.tools.notes._helpers import _intel_dir
        root = _intel_dir()
    except Exception:
        return False, ""
    if not root.exists():
        return False, ""
    for d in sorted(root.iterdir()):
        path = d / "findings.json"
        if not path.is_file():
            continue
        try:
            store = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for f in store.get("findings", []) or []:
            if f.get("id") == finding_id:
                return True, f"{d.name} {f.get('title', '')}".strip()
    return False, ""


def _record_annotation_on_finding(finding_id: str, verified: dict) -> None:
    """Append a Burp-confirmed annotation to the finding record. Best-effort.

    Stores the read-back (what Burp actually holds), never the requested text.
    Re-annotating the same index replaces the entry rather than stacking, so
    the list always matches the live history.
    """
    try:
        from burpsuite_mcp.tools.notes._helpers import _intel_dir
        root = _intel_dir()
        if not root.exists():
            return
        for d in sorted(root.iterdir()):
            path = d / "findings.json"
            if not path.is_file():
                continue
            try:
                store = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for f in store.get("findings", []) or []:
                if f.get("id") != finding_id:
                    continue
                tags = [
                    a for a in (f.get("annotations") or [])
                    if isinstance(a, dict) and a.get("index") != verified.get("index")
                ]
                tags.append(verified)
                f["annotations"] = tags
                path.write_text(json.dumps(store, indent=2), encoding="utf-8")
                return
    except Exception:
        pass  # annotation bookkeeping never blocks the annotate call


def register(mcp: FastMCP):

    # ── Intercept Control (collapsed) ──────────────────────────────

    @mcp.tool()
    async def intercept(action: str = "status") -> str:
        """Control Burp proxy interception.

        Args:
            action: 'on' (enable), 'off' (disable), or 'status' (check)
        """
        a = action.lower()
        if a in ("on", "enable", "enabled"):
            data = await client.post("/api/intercept/enable")
            if "error" in data:
                return f"Error: {data['error']}"
            return "Proxy intercept ENABLED — requests will be held"
        if a in ("off", "disable", "disabled"):
            data = await client.post("/api/intercept/disable")
            if "error" in data:
                return f"Error: {data['error']}"
            return "Proxy intercept DISABLED — requests passing through"
        if a in ("status", "state", "check"):
            data = await client.get("/api/intercept/status")
            if "error" in data:
                return f"Error: {data['error']}"
            enabled = data.get("intercept_enabled", False)
            return f"Intercept is {'ENABLED' if enabled else 'DISABLED'}"
        return f"Unknown action '{action}'. Use 'on', 'off', or 'status'."

    # ── Match & Replace (collapsed) ────────────────────────────────

    @mcp.tool()
    async def match_replace(
        action: str = "list",
        rules: list[dict] | None = None,
        rule_id: int = -1,
        force: bool = False,
    ) -> str:
        """Manage Burp's match-and-replace rules.

        Args:
            action: 'set' (add rules), 'list' (show active), 'remove' (delete by rule_id), 'clear' (remove all)
            rules: For action=set — list of {type, match, replace, scope?, enabled?}
            rule_id: For action=remove — rule ID returned by 'set' or 'list'
            force: For action=set — allow dangerous header rewrites (Host, Auth, Cookie, Content-Length, Transfer-Encoding)
        """
        a = action.lower()

        if a == "set":
            if not rules:
                return "Error: action=set requires rules list"
            if not force:
                blocked = []
                for i, r in enumerate(rules):
                    match_str = str(r.get("match", "")).lower()
                    for pat in _DANGEROUS_HEADER_PATTERNS:
                        if pat in match_str:
                            blocked.append(f"rule #{i}: matches '{pat}' — set force=True to override")
                            break
                if blocked:
                    return (
                        "Refused: dangerous header rewrite detected.\n  "
                        + "\n  ".join(blocked)
                        + "\nRe-run with force=True if intentional."
                    )
            data = await client.post("/api/match-replace/add", json={"rules": rules})
            if "error" in data:
                return f"Error: {data['error']}"
            active = data.get("rules", [])
            if not active:
                return "No rules active"
            lines = [f"Active Rules ({len(active)}):"]
            lines.append(f"{'ID':<5} {'TYPE':<10} {'SCOPE':<10} MATCH → REPLACE")
            lines.append("-" * 70)
            for r in active:
                match_short = str(r.get("match", ""))[:25]
                replace_short = str(r.get("replace", ""))[:25]
                lines.append(
                    f"{r.get('id', '?'):<5} {r.get('type', '?'):<10} {r.get('scope', 'all'):<10} "
                    f"{match_short} → {replace_short}"
                )
            global_rules = [r for r in active if r.get("scope") not in ("in_scope",)]
            if global_rules:
                lines.append(f"\nWarning: {len(global_rules)} rule(s) apply to ALL traffic (not in-scope-only).")
            lines.append("Note: rules are in-memory only — Burp restart wipes them.")
            return "\n".join(lines)

        if a == "list":
            data = await client.get("/api/match-replace")
            if "error" in data:
                return f"Error: {data['error']}"
            rules_list = data.get("rules", [])
            if not rules_list:
                return "No match-replace rules active"
            lines = [f"Match-Replace Rules ({len(rules_list)}):"]
            for r in rules_list:
                status = "ON" if r.get("enabled", True) else "OFF"
                lines.append(
                    f"  [{r.get('id')}] [{status}] {r.get('type')}/{r.get('scope','all')}: "
                    f"{r.get('match', '')[:40]} → {r.get('replace', '')[:40]}"
                )
            return "\n".join(lines)

        if a == "remove":
            if rule_id < 0:
                return "Error: action=remove requires rule_id"
            data = await client.delete(f"/api/match-replace/{rule_id}")
            if "error" in data:
                return f"Error: {data['error']}"
            return f"Rule #{rule_id} removed"

        if a == "clear":
            data = await client.post("/api/match-replace/clear")
            if "error" in data:
                return f"Error: {data['error']}"
            return "All match-replace rules cleared"

        return f"Unknown action '{action}'. Use 'set', 'list', 'remove', or 'clear'."

    # ── Annotations ─────────────────────────────────────────────

    @mcp.tool()
    async def annotate_request(
        index: int,
        color: str = "",
        comment: str = "",
        endpoint: str = "",
        finding_id: str = "",
        confirm: bool = False,
    ) -> str:
        """Mark a proxy history item with a color and/or comment in Burp's UI. Read-back verified.

        A RED or ORANGE tag is a claim ("this entry proves finding X"). Those
        colors require either a `finding_id` that resolves in .burp-intel, or
        `confirm=True`. Everything else annotates freely.

        Args:
            index: Proxy history index (Proxy -> HTTP history, NOT a Logger index)
            color: RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY
            comment: Note text. Rule 18 format: '<f-id> | <vuln> | <evidence>'
            endpoint: Endpoint the annotation is about. Server refuses to tag an
                unrelated request when supplied — always pass it for claim colors.
            finding_id: Saved finding this tag refers to (e.g. 'f003'). Verified to exist.
            confirm: Operator override when a claim color has no saved finding yet.
        """
        color_upper = (color or "").upper()
        claim_color = color_upper in ("RED", "ORANGE")

        if finding_id:
            known, where = _lookup_finding_id(finding_id)
            if not known:
                return (
                    f"Refused: finding_id={finding_id!r} does not exist in .burp-intel. "
                    f"Annotating a request with a finding ID that was never saved is how "
                    f"writeups end up citing comments Burp never had.\n"
                    f"  Fix: save_finding(...) first, then annotate with the returned ID — "
                    f"or drop finding_id and annotate with a plain observation."
                )
            claim_color = False  # a resolvable ID is the evidence the gate wanted
            comment = comment or f"{finding_id} | see {where}"

        if claim_color and not confirm:
            return (
                f"QUESTION GATE — {color_upper} marks a confirmed/strong-suspicion claim on "
                f"proxy entry #{index}, but no finding_id was given.\n"
                f"  Comment: {comment or '(none)'}\n"
                f"  Answer one:\n"
                f"    a) pass finding_id='fNNN' if the finding is already saved;\n"
                f"    b) pass confirm=True if you have verified this entry yourself;\n"
                f"    c) use YELLOW (anomaly) or CYAN (chain candidate) — no claim implied."
            )

        payload: dict = {"index": index, "color": color, "comment": comment}
        if endpoint:
            payload["endpoint"] = endpoint
        data = await client.post("/api/annotations/set", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        # Report what Burp actually stored, not what we asked for. A later
        # get_annotations(index) returns exactly this.
        stored_color = data.get("color", "NONE")
        stored_notes = data.get("notes", "")
        url = data.get("url", "")
        method = data.get("method", "")

        # Record the read-back on the finding. A writeup may then cite only tags
        # that Burp confirmed storing — the "the md says I commented X but the
        # history has no such comment" failure comes from citing the requested
        # text instead of the stored text.
        if finding_id:
            _record_annotation_on_finding(
                finding_id,
                {"index": index, "color": stored_color, "comment": stored_notes,
                 "url": url, "method": method},
            )

        lines = [f"Annotated #{index} — verified in Burp:"]
        lines.append(f"  color:   {stored_color}")
        lines.append(f"  comment: {stored_notes or '(none)'}")
        if url:
            lines.append(f"  entry:   {method} {url}")
        if comment and stored_notes != comment:
            lines.append(
                "  WARNING: Burp stored a different comment than requested. "
                "Cite the stored text above, not the requested text."
            )
        return "\n".join(lines)

    @mcp.tool()
    async def annotate_bulk(items: list[dict], confirm: bool = False) -> str:
        """Annotate multiple proxy history items at once. Claim colors are gated.

        RED and ORANGE assert "this entry proves finding X" exactly as they do
        on annotate_request, so they carry the same gate here — a bulk call is
        not a way around it. Batches of unverified claim colors are what leave a
        history full of RED entries no finding stands behind.

        Args:
            items: List of dicts: {index, color?, comment?, endpoint?, finding_id?}.
                `endpoint` makes the server refuse to tag an unrelated request.
            confirm: Operator override for claim colors with no saved finding.
        """
        blocked: list[str] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            color_upper = str(it.get("color") or "").upper()
            if color_upper not in ("RED", "ORANGE"):
                continue
            fid = str(it.get("finding_id") or "").strip()
            if fid:
                known, _where = _lookup_finding_id(fid)
                if not known:
                    blocked.append(
                        f"#{it.get('index', '?')} {color_upper}: finding_id "
                        f"{fid!r} does not exist in .burp-intel"
                    )
                continue
            if not confirm:
                blocked.append(
                    f"#{it.get('index', '?')} {color_upper}: no finding_id"
                )

        if blocked:
            return (
                "QUESTION GATE — nothing annotated. "
                f"{len(blocked)} of {len(items)} entries make a claim "
                "(RED/ORANGE) with nothing backing it:\n"
                + "\n".join(f"    - {b}" for b in blocked[:10])
                + ("\n    ..." if len(blocked) > 10 else "")
                + "\n  Answer one:\n"
                "    a) add finding_id='fNNN' per entry once the finding is saved;\n"
                "    b) pass confirm=True if you verified these entries yourself;\n"
                "    c) downgrade to YELLOW (anomaly) or CYAN (chain candidate)."
            )

        data = await client.post("/api/annotations/bulk", json={"items": items})
        if "error" in data:
            return f"Error: {data['error']}"
        applied = data.get("applied", 0)
        errors = data.get("errors", []) or []
        out = [f"Annotated {applied} of {len(items)} items"]
        if errors:
            out.append(f"  Rejected {len(errors)}:")
            out.extend(f"    - {e}" for e in errors[:10])
            out.append("  Rejected entries carry NO annotation — do not cite them as tagged.")
        return "\n".join(out)

    @mcp.tool()
    async def get_annotations(index: int) -> str:
        """Get the current annotation (color and comment) for a proxy history item.

        Args:
            index: Proxy history index
        """
        data = await client.get(f"/api/annotations/{index}")
        if "error" in data:
            return f"Error: {data['error']}"
        color = data.get("color", "NONE")
        comment = data.get("notes", "")
        if color == "NONE" and not comment:
            return f"#{index}: no annotations"
        return f"#{index}: color={color}, comment={comment}"

    # ── Statistics & Live Traffic ────────────────────────────────

    @mcp.tool()
    async def get_proxy_stats() -> str:
        """Get proxy traffic statistics -- total requests, unique hosts, method and status distributions."""
        data = await client.get("/api/traffic/stats")
        if "error" in data:
            return f"Error: {data['error']}"
        lines = [f"Proxy Stats ({data.get('total_requests', 0)} total requests)"]
        lines.append(f"  Unique hosts: {data.get('unique_hosts', 0)}")
        methods = data.get("method_distribution", {})
        if methods:
            lines.append(f"\n  Methods: {', '.join(f'{k}={v}' for k, v in methods.items())}")
        statuses = data.get("status_code_distribution", {})
        if statuses:
            lines.append(f"  Status codes: {', '.join(f'{k}={v}' for k, v in statuses.items())}")
        return "\n".join(lines)

    @mcp.tool()
    async def get_live_requests(since_index: int) -> str:
        """Get new proxy requests captured since a given index.

        Args:
            since_index: Return items after this proxy history index
        """
        data = await client.get("/api/traffic/live", params={"since_index": since_index})
        if "error" in data:
            return f"Error: {data['error']}"
        items = data.get("items", [])
        if not items:
            return f"No new requests since #{since_index}"
        lines = [f"New Requests ({len(items)} since #{since_index}):"]
        lines.append(f"{'IDX':<7} {'METHOD':<8} {'STATUS':<7} URL")
        lines.append("-" * 80)
        for item in items:
            lines.append(
                f"{item.get('index', '?'):<7} {item.get('method', '?'):<8} "
                f"{item.get('status_code', '?'):<7} {item.get('url', '?')}"
            )
        return "\n".join(lines)

    # ── Traffic Monitoring (collapsed) ──────────────────────────

    @mcp.tool()
    async def traffic_monitor(
        action: str = "check",
        tag: str = "",
        patterns: list[dict] | None = None,
    ) -> str:
        """Register and check regex-based traffic monitors over proxy traffic.

        Args:
            action: 'register' (create monitor), 'check' (get hits), 'remove' (delete)
            tag: Monitor name (required for all actions)
            patterns: For action=register — list of {location, regex} dicts
        """
        a = action.lower()
        if not tag:
            return "Error: tag is required"

        if a == "register":
            if not patterns:
                return "Error: action=register requires patterns list"
            data = await client.post("/api/traffic/monitor/register", json={
                "tag": tag, "patterns": patterns,
            })
            if "error" in data:
                return f"Error: {data['error']}"
            return f"Monitor '{tag}' registered with {len(patterns)} pattern(s). Use traffic_monitor(action='check', tag='{tag}') to check for hits."

        if a == "check":
            data = await client.get("/api/traffic/monitor/check", params={"tag": tag})
            if "error" in data:
                return f"Error: {data['error']}"
            hits = data.get("hits", [])
            if not hits:
                return f"Monitor '{tag}': no new hits"
            lines = [f"Monitor '{tag}' — {len(hits)} hit(s):"]
            for hit in hits:
                lines.append(
                    f"  [#{hit.get('index')}] {str(hit.get('matched_text', ''))[:100]}"
                )
            return "\n".join(lines)

        if a == "remove":
            data = await client.delete(f"/api/traffic/monitor/{tag}")
            if "error" in data:
                return f"Error: {data['error']}"
            return f"Monitor '{tag}' removed"

        return f"Unknown action '{action}'. Use 'register', 'check', or 'remove'."
