"""Tools for saving findings and generating reports."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

def _intel_dir() -> Path:
    """Resolve the .burp-intel directory at call time (cwd may change)."""
    return Path.cwd() / ".burp-intel"


def _sanitized(domain: str) -> str:
    cleaned = re.sub(r'[^a-zA-Z0-9._-]', '_', domain).strip(".")
    if not cleaned or ".." in cleaned:
        raise ValueError(f"Invalid domain: {domain!r}")
    return cleaned


def _safe_findings_path(domain: str) -> Path:
    """Resolve findings.json for a domain with path-traversal guard."""
    base = _intel_dir().resolve()
    sub = _sanitized(domain)
    candidate = (base / sub / "findings.json").resolve()
    if base != candidate and base not in candidate.parents:
        raise ValueError(f"Domain escapes intel root: {domain!r}")
    return _intel_dir() / sub / "findings.json"


def _domain_from_endpoint(endpoint: str) -> str:
    """Best-effort host extraction from an endpoint URL or bare host."""
    if not endpoint:
        return ""
    if "://" in endpoint:
        return urlparse(endpoint).hostname or ""
    # bare /path/... — no host info
    return ""


def _load_findings_file(path: Path) -> dict:
    if not path.exists():
        return {"findings": [], "last_modified": ""}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {"findings": [], "last_modified": ""}


def _write_findings_file(path: Path, data: dict) -> None:
    """Atomic write — concurrent agents saving to the same domain mustn't
    corrupt findings.json by interleaving partial writes. Render to a temp
    file in the same directory, then os.replace() — POSIX-atomic on the
    same filesystem."""
    import os
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".findings-", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _find_by_id(findings: list[dict], finding_id: str) -> tuple[int, dict | None]:
    """Linear scan for a finding by its persistent ID. Returns (index, finding)
    or (-1, None) if not found."""
    for i, f in enumerate(findings):
        if f.get("id") == finding_id:
            return i, f
    return -1, None


def _format_proof_for_review(f: dict) -> str:
    """Render a finding's evidence in a compact human-readable block, used when
    the FP-delete tool needs the operator to confirm a borderline-confidence
    deletion. Pulls the fields a triager would care about."""
    lines = [
        f"  ID:          {f.get('id', '?')}",
        f"  Title:       {f.get('title', '')[:120]}",
        f"  Severity:    {f.get('severity', 'INFO')}",
        f"  Confidence:  {f.get('confidence', 0.0):.2f}",
        f"  Status:      {f.get('status', 'suspected')}",
        f"  Vuln class:  {f.get('vuln_type', '')}",
        f"  Endpoint:    {f.get('endpoint', '')}",
        f"  Parameter:   {f.get('parameter', '')}",
    ]
    et = (f.get("evidence_text") or "").strip()
    if et:
        clip = et if len(et) <= 400 else et[:400] + "..."
        lines.append(f"  Evidence:    {clip}")
    ev = f.get("evidence") or {}
    if isinstance(ev, dict):
        for key in ("logger_index", "proxy_history_index", "collaborator_interaction_id"):
            if ev.get(key) is not None:
                lines.append(f"  evidence.{key}: {ev[key]}")
    if f.get("reproductions"):
        lines.append(f"  Reproductions: {len(f['reproductions'])} entries")
    if f.get("chain_with"):
        lines.append(f"  Chain anchors: {', '.join(f['chain_with'])}")
    if f.get("human_verified"):
        lines.append("  Human-verified: yes")
    return "\n".join(lines)


async def _hard_delete_finding(domain: str, finding: dict) -> tuple[bool, str]:
    """Remove a finding from .burp-intel/<domain>/findings.json AND from Burp's
    in-memory store. Returns (deleted_locally, burp_msg)."""
    findings_path = _safe_findings_path(domain)
    deleted_locally = False
    if findings_path.exists():
        store = _load_findings_file(findings_path)
        all_findings = store.get("findings", [])
        target_id = finding.get("id")
        keep = [f for f in all_findings if f.get("id") != target_id]
        if len(keep) != len(all_findings):
            store["findings"] = keep
            store["last_modified"] = datetime.now(timezone.utc).isoformat()
            _write_findings_file(findings_path, store)
            deleted_locally = True
    burp_msg = ""
    burp_id = (finding.get("burp_id") or "")
    ev = finding.get("evidence") or {}
    if not burp_id and isinstance(ev, dict):
        burp_id = str(ev.get("burp_id") or "")
    if burp_id:
        resp = await client.delete(f"/api/notes/findings/{burp_id}")
        if isinstance(resp, dict) and "error" not in resp:
            burp_msg = f"Burp in-memory: removed (id={burp_id})"
        else:
            burp_msg = f"Burp in-memory: skip ({resp.get('error', 'no response')})"
    else:
        burp_msg = "Burp in-memory: no burp_id recorded — Burp store not touched (will not re-appear after extension reload)"
    return deleted_locally, burp_msg


def _dedupe_finding(existing: list[dict], new: dict) -> tuple[list[dict], str, int]:
    """Merge `new` into `existing` by (endpoint + vuln_type + title + parameter).

    vuln_type is part of the key so two distinct classes (e.g. xss vs csrf)
    that happen to share an endpoint+title don't silently collapse — that
    used to delete the earlier finding's evidence on the second save.

    Returns (updated_list, action, index) where action is 'created' or 'updated'
    and index points at the finding's position in the returned list.
    """
    key_ep = new.get("endpoint", "")
    key_vuln = (new.get("vuln_type", "") or "").lower()
    key_title = new.get("title", "").lower()
    key_param = new.get("parameter", "")

    for i, f in enumerate(existing):
        same_ep = f.get("endpoint", "") == key_ep
        same_vuln = (f.get("vuln_type", "") or "").lower() == key_vuln
        same_title = f.get("title", "").lower() == key_title
        same_param = f.get("parameter", "") == key_param
        if same_ep and same_vuln and same_title and same_param:
            merged = {**f, **new, "id": f.get("id")}
            existing[i] = merged
            return existing, "updated", i
    existing.append(new)
    return existing, "created", len(existing) - 1


def register(mcp: FastMCP):

    @mcp.tool()
    async def save_finding(
        title: str,
        description: str,
        evidence: dict,
        severity: str = "INFO",
        endpoint: str = "",
        evidence_text: str = "",
        reproductions: list[dict] | None = None,
        chain_with: list[str] | None = None,
        status: str = "suspected",
        domain: str = "",
        parameter: str = "",
        vuln_type: str = "",
        confidence: float = 0.5,
        force_recon_gate: bool = False,
        human_verified: bool = False,
        overrides: list[str] | None = None,
    ) -> str:
        """Save a pentest finding. Requires prior assess_finding() call. Burp hard-rejects missing evidence.

        Args:
            title: Short finding title
            description: Detailed vulnerability description
            evidence: Dict with logger_index, proxy_history_index, or collaborator_interaction_id
            severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO. Operator-locked — wins over advisor's inferred severity. See user-override skill for routing guidance.
            endpoint: Affected URL/endpoint
            evidence_text: Freeform proof string for the report
            reproductions: Required for timing/blind vuln_types (>=2 dicts with logger_index/elapsed_ms/status_code)
            chain_with: Required for NEVER SUBMIT vuln_types — list of finding IDs for the chain
            status: suspected, confirmed, stale, or likely_false_positive
            domain: Target domain for persistent .burp-intel storage
            parameter: Parameter name (dedup key)
            vuln_type: Vulnerability class (e.g. sqli, xss, sqli_blind)
            confidence: 0.0-1.0 score
            force_recon_gate: Bypass the session-start recon gate (Rule 20a). Only use if recon is already in flight in this session and not yet persisted.
            human_verified: Operator confirmed visually in Burp UI / browser DevTools. Logged in finding metadata (R19).
            overrides: Audit-trailed gate bypasses (R20). Each entry "<gate>:<reason>". Stored in finding entry as 'overrides' for review.
        """
        # Severity is operator-locked. Validate but don't auto-adjust.
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        severity_upper = (severity or "INFO").upper()
        if severity_upper not in valid_severities:
            return (
                f"Error: invalid severity '{severity}'. Must be one of: "
                f"{', '.join(sorted(valid_severities))}. Operator owns severity choice; "
                f"see user-override skill for guidance."
            )
        severity = severity_upper

        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.5

        # Tool-call format guard: if the caller's evidence_text contains
        # literal Anthropic-style tool-parameter markers, the harness almost
        # certainly truncated the parameter block — every later parameter
        # (status / vuln_type / parameter / confidence / chain_with) silently
        # reverted to defaults, producing a "saved but with empty fields"
        # finding that's hard to spot. Reject up-front with a precise hint.
        leak_markers = (
            "</evidence_text>",
            "</invoke>",
            "<status>",
            "<vuln_type>",
            "<parameter>",
            "<confidence>",
            "<chain_with>",
            "<human_verified>",
        )
        for m in leak_markers:
            if m in (evidence_text or ""):
                return (
                    f"Error: evidence_text contains tool-call leak marker {m!r}. "
                    "This usually means a malformed parameter block (the harness "
                    "swallowed later parameters into evidence_text, leaving "
                    "vuln_type / parameter / status / confidence at defaults). "
                    "Re-issue save_finding with a clean evidence_text and each "
                    "parameter as its own argument."
                )

        resolved_domain = domain or _domain_from_endpoint(endpoint)

        # ── Status='likely_false_positive' shortcut ────────────────────
        # The pipeline does not save FPs. If a matching finding already exists
        # in .burp-intel/<domain>/findings.json, hard-delete it (and its Burp
        # in-memory mirror). For genuinely new FP attempts, no-op.
        if (status or "").lower() == "likely_false_positive":
            if not resolved_domain:
                return (
                    "Refusing to process likely_false_positive without a domain. "
                    "Pass domain= so we can locate any prior persisted record."
                )
            try:
                findings_path = _safe_findings_path(resolved_domain)
            except ValueError as e:
                return f"Error: {e}"
            existing = _load_findings_file(findings_path).get("findings", []) if findings_path.exists() else []
            new_key_ep = endpoint or ""
            new_key_vuln = (vuln_type or "").lower()
            new_key_title = (title or "").lower()
            new_key_param = parameter or ""
            target = None
            for f in existing:
                if (
                    f.get("endpoint", "") == new_key_ep
                    and (f.get("vuln_type", "") or "").lower() == new_key_vuln
                    and f.get("title", "").lower() == new_key_title
                    and f.get("parameter", "") == new_key_param
                ):
                    target = f
                    break
            if target is None:
                return (
                    "No prior finding matched on (endpoint, vuln_type, title, parameter). "
                    "Nothing persisted, nothing to delete. (likely_false_positive is "
                    "never saved — use mark_finding_false_positive(finding_id) for "
                    "explicit deletion of a known ID.)"
                )
            conf = float(target.get("confidence", 0.5) or 0.5)
            if conf >= 0.6:
                return (
                    f"Refusing to silent-delete via save_finding(status='likely_false_positive') — "
                    f"existing record has confidence={conf:.2f} (>=0.6 requires explicit review).\n"
                    f"Use: mark_finding_false_positive(finding_id='{target.get('id', '')}', "
                    f"domain='{resolved_domain}', confirmed_by_user=True, reason='<why>')"
                )
            deleted_locally, burp_msg = await _hard_delete_finding(resolved_domain, target)
            return (
                f"Hard-deleted FP {target.get('id', '?')} (confidence={conf:.2f}) "
                f"from {resolved_domain}.\n"
                f"  Local store: {'removed' if deleted_locally else 'no-op'}\n"
                f"  {burp_msg}"
            )

        # ── Rule 20a: recon gate ──────────────────────────────────
        # Refuse to persist findings for domains where no recon has been
        # recorded. Empty `.burp-intel/<domain>/` = operator skipped session-
        # start intel; saving here would create a phantom history with no
        # context. force_recon_gate=True overrides for in-flight recon.
        # R20 unified override: 'recon_gate' in overrides also bypasses gate.
        override_set = {(o.split(":", 1)[0] if ":" in o else o).strip().lower()
                        for o in (overrides or [])}
        skip_recon_gate = force_recon_gate or "recon_gate" in override_set
        if resolved_domain and not skip_recon_gate:
            from burpsuite_mcp.tools.intel import recon_gate_check
            gate_err = recon_gate_check(resolved_domain)
            if gate_err is not None:
                return f"RECON GATE: {gate_err}"

        # ── R25: chain_with validator ─────────────────────────────
        # Reject chain_with referencing findings that are likely_false_positive
        # or stale. Force re-verification before chain.
        if chain_with and resolved_domain:
            try:
                findings_path = _safe_findings_path(resolved_domain)
                if findings_path.exists():
                    existing = _load_findings_file(findings_path).get("findings", [])
                    by_id = {f.get("id", ""): f for f in existing if f.get("id")}
                    bad_chain: list[str] = []
                    for cid in chain_with:
                        anchor = by_id.get(cid)
                        if anchor is None:
                            bad_chain.append(f"{cid} (not found)")
                            continue
                        anchor_status = anchor.get("status", "")
                        if anchor_status in ("likely_false_positive", "stale"):
                            bad_chain.append(f"{cid} ({anchor_status})")
                    if bad_chain:
                        return (
                            f"CHAIN GATE: chain_with references dead anchors: "
                            f"{', '.join(bad_chain)}. Re-verify each before chaining, "
                            f"or pass overrides=['q4_dedup:reviewed'] only after manual confirmation."
                        )
            except (OSError, ValueError):
                pass  # best-effort

        # ZERO-NOISE GATE — call Burp first. If the server rejects (missing
        # evidence index, NEVER SUBMIT without chain, missing reproductions),
        # we MUST NOT persist anything to .burp-intel/findings.json. Otherwise
        # rejected findings accumulate locally and get re-loaded next session,
        # wasting tokens on phantom "confirmed" findings.
        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "endpoint": endpoint,
            "evidence_text": evidence_text,
            "evidence": evidence,
            "vuln_type": vuln_type,
            "status": status,
        }
        if reproductions:
            payload["reproductions"] = reproductions
        if chain_with:
            payload["chain_with"] = chain_with

        data = await client.post("/api/notes/findings", json=payload)
        if "error" in data:
            err_code = data.get("code", "")
            err_hint = data.get("hint", "")
            err_msg = data.get("error", "(no message)")
            # Map error codes to actionable retry guidance
            retry_advice = {
                "never_submit": "Either pass chain_with=[<id>] OR set_program_policy() to remove the class.",
                "chain_unknown_id": "Run get_findings() to list valid chain anchor IDs.",
                "evidence_missing": "Pass evidence={'logger_index': <N>}.",
                "reproductions_required": "Pass reproductions=[{logger_index,elapsed_ms,status_code}, ...] (>=2).",
                "reproductions_invalid": "Each reproductions[] entry needs an integer logger_index in range.",
            }.get(err_code, "")
            parts = [f"Error (gate rejected — nothing persisted): {err_msg}"]
            if err_code:
                parts.append(f"  Error type: {err_code}")
            if err_hint:
                parts.append(f"  Hint: {err_hint}")
            if retry_advice:
                parts.append(f"  Retry: {retry_advice}")
            return "\n".join(parts)
        burp_id = data.get("id", "?")

        # Gate passed — now safe to persist locally.
        dedup_action = "created"
        saved_id = ""
        if resolved_domain:
            findings_path = _safe_findings_path(resolved_domain)
            store = _load_findings_file(findings_path)
            now = datetime.now(timezone.utc).isoformat()
            new_entry = {
                "title": title,
                "description": description,
                "severity": severity,
                "endpoint": endpoint,
                "evidence_text": evidence_text,
                "evidence": evidence,
                "human_verified": human_verified,
                "overrides": list(overrides or []),
                "reproductions": reproductions or [],
                "chain_with": chain_with or [],
                "status": status,
                "parameter": parameter,
                "vuln_type": vuln_type,
                "confidence": round(confidence, 2),
                "last_updated": now,
                # Persist Burp's in-memory id so a later FP delete can reach
                # it via DELETE /api/notes/findings/{id}. Without this, the
                # local .burp-intel/<domain>/findings.json gets cleaned but
                # Burp's UI Findings tab keeps showing the dead entry until
                # the next extension reload.
                "burp_id": str(burp_id) if burp_id != "?" else "",
            }
            existing_list = store.get("findings", [])
            updated_list, dedup_action, idx = _dedupe_finding(existing_list, new_entry)
            if dedup_action == "created":
                existing_ids = {f.get("id", "") for f in updated_list if f.get("id")}
                next_num = 1
                while f"f{next_num:03d}" in existing_ids:
                    next_num += 1
                updated_list[idx]["id"] = f"f{next_num:03d}"
                updated_list[idx]["created"] = now
            saved_id = updated_list[idx].get("id", "")
            store["findings"] = updated_list
            store["last_modified"] = now
            _write_findings_file(findings_path, store)

        if not resolved_domain:
            return (
                f"Finding saved to Burp in-memory only [{severity}] {title} (Burp ID: {burp_id}).\n"
                "Warning: no domain passed and could not derive from endpoint. "
                "Finding will be lost on Burp reload. Pass `domain=...` to persist."
            )

        action_label = "Updated" if dedup_action == "updated" else "Saved"
        return (
            f"{action_label} [{severity}] c={confidence:.2f} {title}\n"
            f"  Persistent ID: {saved_id} ({resolved_domain})\n"
            f"  Burp ID: {burp_id}\n"
            f"  Location: .burp-intel/{_sanitized(resolved_domain)}/findings.json"
        )

    @mcp.tool()
    async def get_findings(endpoint: str = "") -> str:
        """Get all saved pentest findings, optionally filtered by endpoint URL.

        Args:
            endpoint: Filter by endpoint URL substring (empty = all)
        """
        params = {}
        if endpoint:
            params["endpoint"] = endpoint

        data = await client.get("/api/notes/findings", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        findings = data.get("findings", [])
        if not findings:
            return "No findings saved yet."

        lines = [f"Saved Findings ({data.get('total', 0)}):\n"]
        for f in findings:
            lines.append(f"[{f.get('severity')}] #{f.get('id')} - {f.get('title')}")
            if f.get("endpoint"):
                lines.append(f"  Endpoint: {f['endpoint']}")
            if f.get("description"):
                lines.append(f"  {f['description'][:200]}")
            lines.append("")

        return "\n".join(lines)

    @mcp.tool()
    async def hydrate_burp_findings(domain: str = "all", include_suspected: bool = False) -> str:
        """Re-populate Burp's in-memory Findings tab from persisted .burp-intel findings. Use after extension reload.

        Args:
            domain: Specific domain to hydrate, or 'all' for every .burp-intel domain
            include_suspected: If True, also restore suspected/stale findings (default: confirmed-only)
        """
        targets: list[Path] = []
        intel_root = _intel_dir()
        if domain == "all":
            if intel_root.exists():
                for d in sorted(intel_root.iterdir()):
                    if d.is_dir() and (d / "findings.json").exists():
                        targets.append(d / "findings.json")
        else:
            p = _safe_findings_path(domain)
            if p.exists():
                targets.append(p)

        if not targets:
            return f"No findings.json found for {domain!r} under .burp-intel/. Nothing to hydrate."

        allowed_statuses = {"confirmed"}
        if include_suspected:
            allowed_statuses |= {"suspected", "stale"}

        restored = 0
        skipped_status = 0
        skipped_gate = 0
        skipped_dup = 0
        gate_errors: list[str] = []

        for path in targets:
            try:
                data = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            findings = data.get("findings", [])

            for f in findings:
                status = f.get("status", "suspected")
                if status not in allowed_statuses:
                    skipped_status += 1
                    continue

                payload = {
                    "title": f.get("title", ""),
                    "description": f.get("description", ""),
                    "severity": f.get("severity", "INFO"),
                    "endpoint": f.get("endpoint", ""),
                    "evidence_text": f.get("evidence_text", ""),
                    "evidence": f.get("evidence", {}),
                    "vuln_type": f.get("vuln_type", ""),
                    "status": status,
                }
                if f.get("reproductions"):
                    payload["reproductions"] = f["reproductions"]
                if f.get("chain_with"):
                    payload["chain_with"] = f["chain_with"]

                resp = await client.post("/api/notes/findings", json=payload)
                if "error" in resp:
                    err = resp["error"]
                    if "duplicate" in err.lower() or "already" in err.lower():
                        skipped_dup += 1
                    else:
                        skipped_gate += 1
                        if len(gate_errors) < 5:
                            fid = f.get("id", "?")
                            gate_errors.append(f"  {fid} ({f.get('title','')[:40]}): {err[:120]}")
                    continue
                restored += 1

        lines = [
            f"Hydrated Burp Findings tab from {len(targets)} domain(s).",
            f"  Restored:        {restored}",
            f"  Skipped (status not in {sorted(allowed_statuses)}): {skipped_status}",
            f"  Skipped (already in Burp memory):                   {skipped_dup}",
            f"  Skipped (gate rejection — evidence index stale):    {skipped_gate}",
        ]
        if gate_errors:
            lines.append("")
            lines.append("First gate rejections (evidence indices likely no longer resolve):")
            lines.extend(gate_errors)
            lines.append("")
            lines.append("Persistent .burp-intel store unchanged. Re-capture the underlying")
            lines.append("requests via search_history / browser_crawl to make these visible.")

        return "\n".join(lines)

    @mcp.tool()
    async def mark_finding_false_positive(
        finding_id: str,
        domain: str,
        confirmed_by_user: bool = False,
        force: bool = False,
        reason: str = "",
    ) -> str:
        """Hard-delete a saved finding and its Burp in-memory mirror.

        Confidence-tiered review (operator-set policy):
          - confidence < 0.6           → delete immediately, no prompt.
          - 0.6 <= confidence < 0.8    → returns full evidence dump and asks the
                                         operator to re-call with confirmed_by_user=True.
          - confidence >= 0.8          → refuses unless force=True with reason — looks
                                         like a real finding; operator must override.

        Args:
            finding_id: Persistent ID, e.g. 'f003'
            domain:     Target domain (where the finding lives in .burp-intel)
            confirmed_by_user: Set True to confirm a 0.6–0.8 borderline deletion.
            force:      Set True to override the >=0.8 refusal. Requires reason.
            reason:     Audit trail — why is this an FP? Required for force=True.
        """
        if not domain:
            return "Error: domain is required to locate the finding."
        try:
            findings_path = _safe_findings_path(domain)
        except ValueError as e:
            return f"Error: {e}"
        if not findings_path.exists():
            return f"No findings.json for domain {domain!r}."
        store = _load_findings_file(findings_path)
        all_findings = store.get("findings", [])
        idx, target = _find_by_id(all_findings, finding_id)
        if target is None:
            return (
                f"Finding {finding_id!r} not found in {domain}. "
                f"Existing IDs: {', '.join(f.get('id', '?') for f in all_findings) or '(none)'}"
            )

        conf = float(target.get("confidence", 0.5) or 0.5)
        proof_block = _format_proof_for_review(target)

        # Tier 3: high-confidence — looks like a real finding.
        if conf >= 0.8:
            if not force:
                return (
                    f"REFUSING to delete {finding_id} — confidence={conf:.2f} "
                    f"(>=0.8 = looks like a real finding).\n"
                    f"\nFull record:\n{proof_block}\n"
                    f"\nIf you have manually verified this is an FP (target patched, "
                    f"original reproduction was a misread, etc.), re-call with:\n"
                    f"  mark_finding_false_positive(finding_id='{finding_id}', "
                    f"domain='{domain}', force=True, reason='<one-line why>')"
                )
            if not reason.strip():
                return (
                    f"REFUSING to force-delete {finding_id} without a reason. "
                    f"force=True requires reason='<why this confirmed/high-conf "
                    f"finding is actually FP>' for the audit trail."
                )

        # Tier 2: borderline — operator must say yes.
        elif 0.6 <= conf < 0.8:
            if not confirmed_by_user:
                return (
                    f"BORDERLINE FP — confidence={conf:.2f} on {finding_id}. "
                    f"Showing full evidence; operator decides.\n"
                    f"\n{proof_block}\n"
                    f"\nIf this is genuinely an FP, re-call with:\n"
                    f"  mark_finding_false_positive(finding_id='{finding_id}', "
                    f"domain='{domain}', confirmed_by_user=True, reason='<why>')\n"
                    f"\nIf the suspicion is still real but unverified, leave it alone "
                    f"or update via save_finding(status='suspected', ...)."
                )

        # Tier 1: low-conf or all gates passed → hard delete.
        deleted_locally, burp_msg = await _hard_delete_finding(domain, target)
        audit = []
        audit.append(f"Hard-deleted {finding_id} (confidence={conf:.2f}, "
                     f"severity={target.get('severity', 'INFO')}) from {domain}.")
        audit.append(f"  Local store: {'removed' if deleted_locally else 'no-op'}")
        audit.append(f"  {burp_msg}")
        if force:
            audit.append(f"  Force-delete reason: {reason}")
        elif confirmed_by_user:
            audit.append(f"  Operator-confirmed reason: {reason or '(none given)'}")
        return "\n".join(audit)

    @mcp.tool()
    async def export_report(format: str = "markdown") -> str:
        """Export all findings as a pentest report.

        Args:
            format: 'markdown' or 'json'
        """
        data = await client.get("/api/notes/export", params={"format": format})
        if "error" in data:
            return f"Error: {data['error']}"

        if format == "json":
            return json.dumps(data, indent=2, default=str)
        return data.get("content", "No findings to export.")
