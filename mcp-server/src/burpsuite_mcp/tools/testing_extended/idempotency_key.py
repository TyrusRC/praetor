"""probe_idempotency_key — idempotency-key scope/principal abuse.

Replays a finalize/payment request under variants that should be rejected by a
correctly-scoped idempotency-key implementation:

  - clone        : same key, different principal (token/cookie swap)
  - mutate_amount: same key, mutated body (amount/recipient)
  - missing      : key removed entirely
  - case_mangle  : alternate casing/prefix (Idempotency-Key vs idempotency-key vs X-Idempotency-Key)
  - empty        : key sent but empty
  - long         : 4KB key (length-limit blow-up)
  - replay_after : same key replayed N times in a row (response should match first)

Strix-derived. Pure black-box.
"""

import json
from copy import deepcopy

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_DEFAULT_HEADER = "Idempotency-Key"


def _hdr_variants(header: str, value: str) -> list[tuple[str, dict]]:
    return [
        ("canonical", {header: value}),
        ("lowercase", {header.lower(): value}),
        ("uppercase", {header.upper(): value}),
        ("x-prefix", {f"X-{header}": value}),
        ("legacy-uuid", {"X-Request-ID": value}),
    ]


def _mutate_body(body: dict, fields: list[str]) -> dict:
    out = deepcopy(body)
    for f in fields:
        if f not in out:
            continue
        v = out[f]
        if isinstance(v, (int, float)):
            out[f] = v * 10
        elif isinstance(v, str) and v.isdigit():
            out[f] = str(int(v) * 10)
        elif isinstance(v, str):
            out[f] = "attacker-" + v
    return out


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_idempotency_key(
        session_primary: str,
        endpoint: str,
        body: dict,
        method: str = "POST",
        idempotency_header: str = _DEFAULT_HEADER,
        idempotency_value: str = "00000000-0000-4000-8000-000000000abc",
        session_secondary: str = "",
        mutate_fields: list[str] | None = None,
        replay_count: int = 3,
    ) -> str:
        """Idempotency-key scope/principal abuse battery.

        Args:
            session_primary: Auth session that owns the original transaction.
            endpoint: Path to finalize/payment endpoint (e.g. /api/v1/payments).
            body: JSON body of the canonical valid request.
            method: HTTP method (default POST).
            idempotency_header: Header name (default Idempotency-Key).
            idempotency_value: Key to use in the canonical request.
            session_secondary: Session for the 'clone' test (different principal). If empty, clone is skipped.
            mutate_fields: Fields to tamper for the 'mutate_amount' test. Defaults to ['amount','total','price','recipient','to'].
            replay_count: Times to replay the canonical request (response must equal #1).
        """
        if mutate_fields is None:
            mutate_fields = ["amount", "total", "price", "recipient", "to"]

        lines = [
            f"probe_idempotency_key {method} {endpoint}",
            f"Header={idempotency_header} Value={idempotency_value} mutate_fields={mutate_fields}",
            "",
        ]
        headers = {"Content-Type": "application/json"}
        findings: list[str] = []

        # 1) canonical — establish baseline (status/body) on primary session
        canonical_headers = {**headers, idempotency_header: idempotency_value}
        canon = await client.post("/api/session/request", json={
            "session": session_primary, "method": method, "path": endpoint,
            "headers": canonical_headers, "body": json.dumps(body),
        })
        if "error" in canon:
            return f"Error on canonical send: {canon['error']}"
        canon_status = canon.get("status", 0)
        canon_body = canon.get("response_body", "")
        canon_len = len(canon_body)
        lines.append(f"[canonical] status={canon_status} len={canon_len}")

        # 2) replay_after — replay_count times with same key
        replay_results = []
        for i in range(replay_count - 1):
            r = await client.post("/api/session/request", json={
                "session": session_primary, "method": method, "path": endpoint,
                "headers": canonical_headers, "body": json.dumps(body),
            })
            if "error" in r:
                replay_results.append((-1, "error", r["error"]))
                continue
            replay_results.append((r.get("status", 0), len(r.get("response_body", "")), r.get("response_body", "")[:80]))
        lines.append(f"[replay] {len(replay_results)} extra replays:")
        for idx, (st, ln, prev) in enumerate(replay_results, start=2):
            same = "SAME" if st == canon_status and ln == canon_len else "DIFFERS"
            lines.append(f"  #{idx}: status={st} len={ln} [{same}] {prev}")
            if same == "DIFFERS" and st >= 200 and st < 300:
                findings.append(f"REPLAY_NOT_IDEMPOTENT (replay #{idx} status={st} differs from canonical {canon_status})")

        # 3) clone — same key, different principal
        if session_secondary:
            clone = await client.post("/api/session/request", json={
                "session": session_secondary, "method": method, "path": endpoint,
                "headers": canonical_headers, "body": json.dumps(body),
            })
            if "error" in clone:
                lines.append(f"[clone] error: {clone['error']}")
            else:
                cs = clone.get("status", 0)
                cbody = clone.get("response_body", "")
                lines.append(f"[clone-different-principal] status={cs} len={len(cbody)}")
                if 200 <= cs < 300:
                    findings.append(f"CROSS_PRINCIPAL_KEY_ACCEPTED (status={cs}) — secondary session reused primary's idempotency key successfully")

        # 4) mutate_amount — same key, mutated body
        mutated = _mutate_body(body, mutate_fields)
        if mutated != body:
            m = await client.post("/api/session/request", json={
                "session": session_primary, "method": method, "path": endpoint,
                "headers": canonical_headers, "body": json.dumps(mutated),
            })
            if "error" in m:
                lines.append(f"[mutate] error: {m['error']}")
            else:
                ms = m.get("status", 0)
                mbody = m.get("response_body", "")
                lines.append(f"[mutate-body] status={ms} len={len(mbody)}")
                # Two failure modes:
                #  - 2xx + body matches canonical: server cached by key, ignored mutated body (FUNDS LOSS)
                #  - 2xx + body different: server accepted mutation AND processed (DOUBLE CHARGE)
                if 200 <= ms < 300:
                    if abs(len(mbody) - canon_len) < 20 and ms == canon_status:
                        findings.append("MUTATION_IGNORED (key-only dedup; cached response ignores body changes — funds-loss path)")
                    else:
                        findings.append(f"MUTATION_PROCESSED (mutated body accepted with same key — double-charge / double-process path; status={ms})")

        # 5) missing — no key
        nokey = await client.post("/api/session/request", json={
            "session": session_primary, "method": method, "path": endpoint,
            "headers": headers, "body": json.dumps(body),
        })
        if "error" not in nokey:
            ns = nokey.get("status", 0)
            lines.append(f"[no-key] status={ns}")
            if 200 <= ns < 300:
                findings.append("KEY_NOT_REQUIRED (endpoint accepts requests with no idempotency key — replay/double-submit unchecked)")

        # 6) case_mangle / variant headers
        lines.append("[header-variants]")
        for variant_name, h in _hdr_variants(idempotency_header, idempotency_value):
            if variant_name == "canonical":
                continue  # already tested
            send_headers = {**headers, **h}
            r = await client.post("/api/session/request", json={
                "session": session_primary, "method": method, "path": endpoint,
                "headers": send_headers, "body": json.dumps(body),
            })
            if "error" in r:
                lines.append(f"  {variant_name}: error")
                continue
            rs = r.get("status", 0)
            rbody = r.get("response_body", "")
            same = rs == canon_status and abs(len(rbody) - canon_len) < 20
            tag = "SAME" if same else "DIFFERS"
            lines.append(f"  {variant_name}: status={rs} len={len(rbody)} [{tag}]")
            if 200 <= rs < 300 and not same:
                findings.append(f"HEADER_CASE_MISMATCH ({variant_name} bypassed dedup — request processed as new)")

        # 7) empty / long
        for variant_name, val in [("empty", ""), ("long-4kb", "A" * 4096)]:
            r = await client.post("/api/session/request", json={
                "session": session_primary, "method": method, "path": endpoint,
                "headers": {**headers, idempotency_header: val},
                "body": json.dumps(body),
            })
            if "error" in r:
                lines.append(f"[{variant_name}] error")
                continue
            rs = r.get("status", 0)
            lines.append(f"[{variant_name}] status={rs}")
            if variant_name == "empty" and 200 <= rs < 300:
                findings.append("EMPTY_KEY_ACCEPTED (empty value treated as missing/no-key — replay path)")

        lines.append("\n--- Summary ---")
        if findings:
            lines.append(f"Findings: {len(findings)}")
            for f in findings:
                lines.append(f"  [!] {f}")
            lines.append("\nVerify each finding manually — idempotency violations need transaction confirmation (e.g. duplicate charge in a real ledger).")
        else:
            lines.append("No idempotency-key violations detected.")
        return "\n".join(lines)
