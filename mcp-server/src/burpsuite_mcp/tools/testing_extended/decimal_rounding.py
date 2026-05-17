"""probe_float_decimal_rounding — sub-cent leakage at currency / quantity boundaries.

Payment endpoints that treat amounts as IEEE-754 floats or that round before
validating leak fractional value at scale (Office Space "salami slicing"):

  - 0.005 rounds UP on the customer side (charged $0) but DOWN on the server (kept).
  - 1e-308 silently becomes 0 on truncation but passes "amount > 0" check.
  - 0.1 + 0.2 != 0.3 — total recompute mismatches client.
  - Scientific notation "1e-5" may bypass regex /^\\d+(\\.\\d{1,2})?$/.

Pure black-box. Operator provides the JSON path to the amount field.
"""

import json
from copy import deepcopy

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_VARIANTS = [
    # (label, value, intent)
    (0.001, "sub-cent — should be rejected or rounded to 0"),
    (0.005, "round-half-even quirk — $0 vs $0.01 mismatch"),
    (0.0049999999, "below half-cent — should be 0"),
    (0.0050000001, "just above half-cent"),
    (-0.01, "negative cent — refund-as-charge path"),
    (-1, "negative dollar"),
    (0, "explicit zero"),
    (1e-308, "IEEE-754 subnormal — may underflow to 0 after parse"),
    (1e308, "IEEE-754 max — may overflow / become inf"),
    (float("nan"), "NaN — comparison ops fail-open (NaN > 0 is False)"),
    (float("inf"), "infinity"),
    ("0.005", "string with sub-cent"),
    ("1e-5", "scientific notation string — regex bypass"),
    ("0.1.1", "malformed decimal — parser leniency"),
    ("0,01", "comma-as-decimal-separator — locale parsing"),
    ("0 0.01", "non-break-space prefix"),
    ("+0.01", "leading-plus sign"),
    ("0.010000000000000001", "23-digit precision underflow"),
    ("0x1", "hex literal"),
    ("0o10", "octal literal"),
    ("99999999999999999999.99", "100-digit overflow"),
]


def _set_json_path(obj, path: list[str], value):
    cur = obj
    for p in path[:-1]:
        if isinstance(cur, dict):
            cur = cur.setdefault(p, {})
        elif isinstance(cur, list) and p.isdigit():
            cur = cur[int(p)]
    last = path[-1]
    if isinstance(cur, dict):
        cur[last] = value
    elif isinstance(cur, list) and last.isdigit():
        cur[int(last)] = value


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_float_decimal_rounding(
        session: str,
        endpoint: str,
        body: dict,
        amount_json_path: str,
        method: str = "POST",
    ) -> str:
        """Inject IEEE-754 edge cases into a currency / quantity field and watch behavior.

        Args:
            session: Auth session.
            endpoint: Path of the payment / amount-accepting endpoint.
            body: Canonical body.
            amount_json_path: Dot-path to the amount field (e.g. 'amount' or 'payment.amount').
            method: HTTP method (default POST).
        """
        path_parts = amount_json_path.split(".")
        canonical = await client.post("/api/session/request", json={
            "session": session, "method": method, "path": endpoint,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body),
        })
        if "error" in canonical:
            return f"Error on canonical send: {canonical['error']}"
        c_status = canonical.get("status", 0)
        c_len = len(canonical.get("response_body", ""))
        lines = [
            f"probe_float_decimal_rounding {method} {endpoint} amount@{amount_json_path}",
            f"[canonical] status={c_status} len={c_len}",
            "",
        ]

        findings: list[str] = []
        for value, intent in _VARIANTS:
            mutated = deepcopy(body)
            try:
                _set_json_path(mutated, path_parts, value)
                vbody = json.dumps(mutated, allow_nan=True)
            except Exception as e:
                lines.append(f"  {repr(value)}: encode error — {e}")
                continue
            r = await client.post("/api/session/request", json={
                "session": session, "method": method, "path": endpoint,
                "headers": {"Content-Type": "application/json"},
                "body": vbody,
            })
            if "error" in r:
                lines.append(f"  {repr(value)} ({intent}): error — {r['error']}")
                continue
            s = r.get("status", 0)
            rbody = r.get("response_body", "")
            ln = len(rbody)

            flags = []
            if 200 <= s < 300 and c_status >= 400:
                flags.append("VALIDATION_BYPASSED")
            elif 200 <= s < 300:
                # Look for the value or its rounded form in response
                str_v = str(value)
                for echo in (str_v, str(int(value) if isinstance(value, (int, float)) and value == value and value not in (float("inf"), float("-inf")) else "")):
                    if echo and echo in rbody:
                        flags.append("ECHOED")
                        break
                if c_status >= 200 and c_status < 300 and abs(ln - c_len) > 0.25 * c_len:
                    flags.append("DIVERGES")
            elif s >= 500:
                flags.append(f"SERVER_ERROR:{s}")

            flag_str = " ".join(f"[!{f}]" for f in flags) if flags else "[OK]"
            lines.append(f"  {repr(value)} ({intent}): status={s} len={ln} {flag_str}")
            if flags:
                findings.append((value, intent, flags))

        lines.append("\n--- Summary ---")
        if findings:
            lines.append(f"Anomalies: {len(findings)} / {len(_VARIANTS)}")
            for value, intent, flags in findings:
                lines.append(f"  [!] {repr(value)} ({intent}): {', '.join(flags)}")
            lines.append("\nRisk: amount field accepts edge-case numerics. Verify the stored/charged amount in a real ledger before claiming finding.")
        else:
            lines.append("No numeric-edge anomalies detected.")
        return "\n".join(lines)
