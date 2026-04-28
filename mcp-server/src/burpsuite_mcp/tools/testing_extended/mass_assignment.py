"""test_mass_assignment — inject extra parameters (role/admin/price/...) and detect binding."""

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing_extended._helpers import fmt_val


_MASS_ASSIGN_PARAMS = [
    "role", "is_admin", "admin", "verified", "active", "price", "discount",
    "balance", "permissions", "group", "type", "status", "plan", "credits",
    "is_staff", "approved", "privilege", "level",
]


def _mass_assign_value(param: str):
    """Return a sensible test value for a mass assignment parameter."""
    bool_params = {"is_admin", "admin", "verified", "active", "approved", "is_staff"}
    num_params = {"price", "discount", "balance", "credits", "level"}
    if param in bool_params:
        return True
    if param in num_params:
        return 0
    if param == "role":
        return "admin"
    if param == "permissions":
        return ["admin", "write", "delete"]
    if param == "group":
        return "administrators"
    if param == "type":
        return "admin"
    if param == "status":
        return "approved"
    if param == "plan":
        return "enterprise"
    return "injected_value"


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_mass_assignment(
        session: str,
        method: str,
        path: str,
        known_params: dict,
        extra_params: dict | None = None,
    ) -> str:
        """Test for mass assignment / parameter binding by injecting extra parameters.

        Example:
            test_mass_assignment(session="s1", method="POST", path="/api/profile",
                known_params={"name": "test"}, extra_params={"role": "admin", "is_admin": true})

        Args:
            session: Session name for auth state
            method: HTTP method (POST, PUT, PATCH)
            path: Target endpoint path
            known_params: Known/expected parameters dict (baseline)
            extra_params: Extra parameters to inject (uses common defaults if empty)
        """
        if not extra_params:
            extra_params = {p: _mass_assign_value(p) for p in _MASS_ASSIGN_PARAMS}

        baseline_resp = await client.post("/api/session/request", json={
            "session": session, "method": method, "path": path,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(known_params),
        })
        if "error" in baseline_resp:
            return f"Error getting baseline: {baseline_resp['error']}"

        baseline_status = baseline_resp.get("status", 0)
        baseline_body = baseline_resp.get("response_body", "")
        baseline_length = len(baseline_body)

        lines = [
            f"Mass Assignment Test: {method} {path}",
            f"Known params: {list(known_params.keys())}",
            f"Extra params to test: {list(extra_params.keys())}",
            f"Baseline: status={baseline_status}, length={baseline_length}\n",
        ]

        combined = {**known_params, **extra_params}
        combined_resp = await client.post("/api/session/request", json={
            "session": session, "method": method, "path": path,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(combined),
        })

        accepted = []
        rejected = []

        if "error" in combined_resp:
            lines.append(f"Combined request error: {combined_resp['error']}")
        else:
            combined_status = combined_resp.get("status", 0)
            combined_body = combined_resp.get("response_body", "")

            if combined_status == baseline_status:
                lines.append(f"Combined request: status={combined_status} (same as baseline)")
                for param, value in extra_params.items():
                    str_val = str(value).lower()
                    param_lower = param.lower()
                    if param_lower in combined_body.lower() or str_val in combined_body.lower():
                        if param_lower not in baseline_body.lower() and str_val not in baseline_body.lower():
                            accepted.append(param)
                if combined_body != baseline_body:
                    length_diff = abs(len(combined_body) - baseline_length)
                    lines.append(f"  Response body differs by {length_diff} bytes")
            else:
                lines.append(f"Combined request: status={combined_status} (different from baseline {baseline_status})")

        lines.append("\n--- Individual Parameter Tests ---")
        for param, value in extra_params.items():
            test_params = {**known_params, param: value}
            resp = await client.post("/api/session/request", json={
                "session": session, "method": method, "path": path,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps(test_params),
            })

            if "error" in resp:
                lines.append(f"  {param}={fmt_val(value)}: Error")
                continue

            status = resp.get("status", 0)
            body = resp.get("response_body", "")
            length = len(body)

            flags = []
            str_val = str(value).lower()
            param_lower = param.lower()

            if (param_lower in body.lower() or str_val in body.lower()) and \
               (param_lower not in baseline_body.lower() and str_val not in baseline_body.lower()):
                flags.append("REFLECTED")
                if param not in accepted:
                    accepted.append(param)

            if status != baseline_status:
                flags.append(f"STATUS:{status}")
            if abs(length - baseline_length) > baseline_length * 0.1:
                flags.append(f"LENGTH_DIFF")
            if body != baseline_body and not flags:
                flags.append("BODY_CHANGED")

            if flags:
                flag_str = " ".join(f"[!{f}]" for f in flags)
                lines.append(f"  {param}={fmt_val(value)}: {flag_str}")
            else:
                rejected.append(param)

        lines.append(f"\n--- Summary ---")
        if accepted:
            lines.append(f"ACCEPTED (reflected/changed behavior): {', '.join(accepted)}")
            lines.append("Risk: Server may bind these parameters — test if they persist or change authorization.")
        if rejected:
            lines.append(f"Rejected/ignored: {', '.join(rejected[:10])}" + (f" +{len(rejected)-10} more" if len(rejected) > 10 else ""))
        if not accepted:
            lines.append("No mass assignment indicators detected.")

        return "\n".join(lines)
