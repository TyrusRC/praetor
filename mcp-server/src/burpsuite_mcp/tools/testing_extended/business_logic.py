"""test_business_logic — negative/zero/large/type-confusion/boundary value tests."""

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing_extended._helpers import fmt_val


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_business_logic(
        session: str,
        endpoint: str,
        parameter: str,
        test_type: str = "all",
    ) -> str:
        """Test business logic flaws with negative values, zero, large numbers, type confusion, and boundary inputs.

        Args:
            session: Session name for auth state
            endpoint: Target endpoint path
            parameter: Parameter name to test
            test_type: 'all', 'negative_values', 'zero_values', 'large_values', 'type_confusion', 'boundary'
        """
        test_cases = {}

        if test_type in ("all", "negative_values"):
            test_cases["negative_values"] = [
                (-1, "Negative one"),
                (-100, "Negative hundred"),
                (-999, "Large negative"),
                (-0.01, "Small negative decimal"),
            ]

        if test_type in ("all", "zero_values"):
            test_cases["zero_values"] = [
                (0, "Zero"),
                (0.0, "Float zero"),
                ("0", "String zero"),
                ("00", "Double zero string"),
            ]

        if test_type in ("all", "large_values"):
            test_cases["large_values"] = [
                (999999999, "Large number"),
                (2147483647, "INT32_MAX"),
                (2147483648, "INT32_MAX + 1"),
                (9999999999999, "Very large"),
                (0.0001, "Very small decimal"),
            ]

        if test_type in ("all", "type_confusion"):
            test_cases["type_confusion"] = [
                ("abc", "String where number expected"),
                (True, "Boolean true"),
                (False, "Boolean false"),
                (None, "Null value"),
                ([], "Empty array"),
                ({}, "Empty object"),
                ("1e308", "Scientific notation overflow"),
                ("NaN", "NaN string"),
                ("Infinity", "Infinity string"),
            ]

        if test_type in ("all", "boundary"):
            test_cases["boundary"] = [
                ("", "Empty string"),
                (" ", "Whitespace only"),
                ("a" * 10000, "Very long string (10K chars)"),
                ("\x00", "Null byte"),
                ("-1", "Negative as string"),
                ("1.1.1", "Invalid number format"),
            ]

        if not test_cases:
            return f"Error: Invalid test_type '{test_type}'. Use: all, negative_values, zero_values, large_values, type_confusion, boundary"

        baseline_resp = await client.post("/api/session/request", json={
            "session": session, "method": "POST", "path": endpoint,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({parameter: 1}),
        })
        if "error" in baseline_resp:
            return f"Error getting baseline: {baseline_resp['error']}"

        baseline_status = baseline_resp.get("status", 0)
        baseline_length = len(baseline_resp.get("response_body", ""))
        baseline_body = baseline_resp.get("response_body", "")

        lines = [
            f"Business Logic Tests: {endpoint} [{parameter}]",
            f"Baseline: status={baseline_status}, length={baseline_length}\n",
        ]

        anomalies = []

        for category, tests in test_cases.items():
            lines.append(f"--- {category} ---")
            for value, desc in tests:
                resp = await client.post("/api/session/request", json={
                    "session": session, "method": "POST", "path": endpoint,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({parameter: value}),
                })

                if "error" in resp:
                    lines.append(f"  {desc} ({fmt_val(value)}): Error — {resp['error']}")
                    continue

                status = resp.get("status", 0)
                body = resp.get("response_body", "")
                length = len(body)
                length_diff_pct = abs(length - baseline_length) / max(baseline_length, 1) * 100

                flags = []
                if status != baseline_status:
                    flags.append(f"STATUS:{status}")
                if length_diff_pct > 20:
                    flags.append(f"LENGTH:{length_diff_pct:.0f}%")
                for kw in ["error", "exception", "stack", "traceback", "invalid", "type"]:
                    if kw in body.lower() and kw not in baseline_body.lower():
                        flags.append(f"KEYWORD:{kw}")
                        break

                flag_str = " ".join(f"[!{f}]" for f in flags) if flags else "[OK]"
                lines.append(f"  {desc} ({fmt_val(value)}): status={status} len={length} {flag_str}")

                if flags:
                    anomalies.append((desc, value, flags, body[:200]))
                    lines.append(f"    > {body[:150]}")

        lines.append(f"\n--- Summary ---")
        lines.append(f"Anomalies: {len(anomalies)}/{sum(len(v) for v in test_cases.values())} tests")
        if anomalies:
            lines.append("Flagged:")
            for desc, val, flags, _ in anomalies:
                lines.append(f"  {desc} ({fmt_val(val)}): {', '.join(flags)}")

        return "\n".join(lines)
